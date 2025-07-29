using Authly.Models;
using Authly.Data;
using Authly.Authorization.UserStorage;
using Authly.Configuration;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using System.Threading.Tasks;

namespace Authly.Services
{
    /// <summary>
    /// Database-based security service for IP tracking and user lockouts
    /// </summary>
    public class DatabaseSecurityService : ISecurityService
    {
        private readonly AuthlyDbContext _context;
        private readonly IApplicationLogger _logger;
        private readonly IUserStorage _userStorage;
        private readonly UserLockoutOptions _userLockoutOptions;
        private readonly IpRateLimitingOptions _ipRateLimitingOptions;
        private readonly IMetricsService _metricsService;
        private readonly IMqttService _mqttService;

        public DatabaseSecurityService(
            AuthlyDbContext context,
            IApplicationLogger logger,
            IUserStorage userStorage,
            IOptions<UserLockoutOptions> userLockoutOptions,
            IOptions<IpRateLimitingOptions> ipRateLimitingOptions,             
            IMetricsService metricsService,
            IMqttService mqttService
            )
        {
            _context = context;
            _logger = logger;
            _userStorage = userStorage;
            _userLockoutOptions = userLockoutOptions.Value;
            _ipRateLimitingOptions = ipRateLimitingOptions.Value;
            _metricsService = metricsService;
            _mqttService = mqttService;
        }

        public bool IsUserLockedOut(User user)
        {
            if (!_userLockoutOptions.Enabled || user.LockoutEnd == null)
                return false;

            return user.LockoutEnd > DateTime.UtcNow;
        }

        public bool IsIpBanned(string ipAddress)
        {
            if (!_ipRateLimitingOptions.Enabled || string.IsNullOrEmpty(ipAddress))
                return false;

            try
            {
                var ipAttempt = _context.IpLoginAttempts
                    .FirstOrDefault(x => x.IpAddress == ipAddress);

                if (ipAttempt == null)
                    return false;

                var now = DateTime.UtcNow;

                // Check if IP is currently banned
                if (ipAttempt.IsBanned && ipAttempt.BanEndUtc.HasValue && ipAttempt.BanEndUtc > now)
                {
                    return true;
                }

                // Clean up expired bans
                if (ipAttempt.IsBanned && ipAttempt.BanEndUtc.HasValue && ipAttempt.BanEndUtc <= now)
                {
                    ipAttempt.IsBanned = false;
                    ipAttempt.BanEndUtc = null;
                    ipAttempt.Note = "Ban expired";

                    // If sliding window is disabled, reset failed attempts after ban expires
                    if (!_ipRateLimitingOptions.SlidingWindow)
                    {
                        ipAttempt.FailedAttempts = 0;
                        ipAttempt.FirstAttemptUtc = now;
                        _logger.Log("DatabaseSecurityService", $"IP {ipAddress} ban expired, failed attempts reset to 0");
                    }
                    
                    _context.SaveChanges();
                }

                return false;
            }
            catch (Exception ex)
            {
                _logger.LogError("DatabaseSecurityService", $"Error checking IP ban status for {ipAddress}: {ex.Message}", ex);
                return false;
            }
        }

        public AuthenticationResult RecordFailedAttempt(User? user, string ipAddress)
        {
            _logger.Log("DatabaseSecurityService", $"Recording failed attempt for user {user?.UserName ?? "unknown"} from IP {ipAddress}");

            try
            {
                // Check IP ban first
                if (IsIpBanned(ipAddress))
                {
                    var banEnd = GetIpBanEndTime(ipAddress);
                    _logger.LogWarning("DatabaseSecurityService", $"IP {ipAddress} is banned until {banEnd}");
                    return AuthenticationResult.IpBannedResult(banEnd ?? DateTime.UtcNow.AddMinutes(_ipRateLimitingOptions.BanDurationMinutes));
                }

                // Record IP attempt
                if (_ipRateLimitingOptions.Enabled)
                {
                    var ipResult = RecordIpAttempt(ipAddress);
                    if (ipResult != null)
                    {
                        return ipResult;
                    }
                }

                // Check user lockout
                if (user != null)
                {
                    if (IsUserLockedOut(user))
                    {
                        var lockoutEnd = GetLockoutEndTime(user);
                        _logger.LogWarning("DatabaseSecurityService", $"User {user.UserName} is locked out until {lockoutEnd}");
                        return AuthenticationResult.LockedOutResult(lockoutEnd ?? DateTime.UtcNow.AddMinutes(_userLockoutOptions.LockoutDurationMinutes));
                    }

                    // Record user attempt
                    if (_userLockoutOptions.Enabled)
                    {
                        RecordUserAttempt(user);
                    }

                    // Check if user should be locked out
                    if (_userLockoutOptions.Enabled && user.FailedLoginAttempts >= _userLockoutOptions.MaxFailedAttempts)
                    {
                        user.LockoutStart = DateTime.UtcNow;
                        user.LockoutEnd = DateTime.UtcNow.AddMinutes(_userLockoutOptions.LockoutDurationMinutes);
                        _userStorage.UpdateUser(user);
                        
                        // Record user lockout security event and metric
                        _metricsService.RecordSecurityEventAsync("user_lockout", $"User {user.UserName} locked due to {user.FailedLoginAttempts} failed attempts", SecurityEventSeverity.Medium, ipAddress, user.UserName);

                        _mqttService.PublishAsync("authly/user/lockout", 
                            new { userId = user.Id, userName = user.UserName, name = user.FullName, lockoutEnd = user.LockoutEnd, failedAttempts = user.FailedLoginAttempts, timestamp = DateTime.UtcNow });

                        _logger.LogWarning("DatabaseSecurityService", $"User {user.UserName} locked out until {user.LockoutEnd}");
                        return AuthenticationResult.LockedOutResult(user.LockoutEnd.Value);
                    }

                    var remainingAttempts = GetRemainingAttempts(user);
                    _logger.Log("DatabaseSecurityService", $"User {user.UserName} has {remainingAttempts} remaining attempts");
                    
                    return AuthenticationResult.FailedResult("Invalid credentials", remainingAttempts);
                }

                return AuthenticationResult.FailedResult("Invalid credentials");
            }
            catch (Exception ex)
            {
                _logger.LogError("DatabaseSecurityService", $"Error recording failed attempt: {ex.Message}", ex);
                return AuthenticationResult.FailedResult("Authentication error occurred");
            }
        }

        public async Task<bool> RecordUnauthorizedAccessAsync(string ipAddress, string path, int statusCode, string operationType)
        {
            if (!_ipRateLimitingOptions.Enabled || string.IsNullOrEmpty(ipAddress))
                return false;

            try
            {
                var now = DateTime.UtcNow;
                var threshold = _ipRateLimitingOptions.MaxAttemptsPerIp * 2; // 2x the normal threshold
                
                var unauthorizedAttempt = await _context.IpLoginAttempts
                    .FirstOrDefaultAsync(x => x.IpAddress == ipAddress + "_unauthorized");

                if (unauthorizedAttempt == null)
                {
                    unauthorizedAttempt = new IpLoginAttempt
                    {
                        IpAddress = ipAddress + "_unauthorized",
                        FailedAttempts = 1,
                        FirstAttemptUtc = now,
                        LastAttemptUtc = now,
                        IsBanned = false,
                        BanEndUtc = null,
                        Note = "DoS"
                    };
                    _context.IpLoginAttempts.Add(unauthorizedAttempt);
                }
                else
                {
                    unauthorizedAttempt.FailedAttempts++;
                    unauthorizedAttempt.LastAttemptUtc = now;
                }

                await _context.SaveChangesAsync();

                _logger.LogDebug("DatabaseSecurityService", 
                    $"Recording unauthorized access from IP {ipAddress} ({unauthorizedAttempt.FailedAttempts}/{threshold}). " +
                    $"Path: {path}, StatusCode: {statusCode}, OperationType: {operationType}");

                // Log periodic warnings and record security events
                if (unauthorizedAttempt.FailedAttempts % _ipRateLimitingOptions.MaxAttemptsPerIp == 0 || unauthorizedAttempt.FailedAttempts >= threshold)
                {
                    var severity = unauthorizedAttempt.FailedAttempts >= threshold ? SecurityEventSeverity.High : SecurityEventSeverity.Medium;
                    
                    await _metricsService.RecordSecurityEventAsync(
                        "unauthorized_access_pattern",
                        $"IP {ipAddress} made {unauthorizedAttempt.FailedAttempts} unauthorized access attempts. Last: {operationType} -> {statusCode} at {path}",
                        severity,
                        ipAddress);

                    _logger.LogWarning("DatabaseSecurityService", 
                        $"IP {ipAddress} has made {unauthorizedAttempt.FailedAttempts} unauthorized access attempts. " +
                        $"Last attempt: {operationType} -> {statusCode} at {path}");
                }

                // Check if we should ban the IP
                if (unauthorizedAttempt.FailedAttempts >= threshold)
                {
                    _logger.LogWarning("DatabaseSecurityService", 
                        $"IP {ipAddress} exceeded unauthorized access threshold ({unauthorizedAttempt.FailedAttempts}/{threshold}). " +
                        "Recommending automatic ban.");
                        
                    return true;
                }

                return false;
            }
            catch (Exception ex)
            {
                _logger.LogError("DatabaseSecurityService", $"Error recording unauthorized access: {ex.Message}", ex);
                return false;
            }
        }

        public void ClearUserFailedAttempts(User user)
        {
            _logger.Log("DatabaseSecurityService", $"Clearing failed attempts for user {user.UserName}");

            if (_userLockoutOptions.Enabled)
            {
                user.FailedLoginAttempts = 0;
                user.LastFailedLoginAttempt = null;
                user.LockoutStart = null;
                user.LockoutEnd = null;
                
                try
                {
                    _userStorage.UpdateUser(user);
                }
                catch (Exception ex)
                {
                    _logger.LogError("DatabaseSecurityService", $"Error clearing user failed attempts: {ex.Message}", ex);
                }
            }
        }

        public int GetRemainingAttempts(User user)
        {
            if (!_userLockoutOptions.Enabled)
                return int.MaxValue;

            return Math.Max(0, _userLockoutOptions.MaxFailedAttempts - user.FailedLoginAttempts);
        }

        public DateTime? GetLockoutEndTime(User user)
        {
            if (!_userLockoutOptions.Enabled)
                return null;

            return user.LockoutEnd;
        }

        public DateTime? GetIpBanEndTime(string ipAddress)
        {
            if (!_ipRateLimitingOptions.Enabled || string.IsNullOrEmpty(ipAddress))
                return null;

            try
            {
                var ipAttempt = _context.IpLoginAttempts
                    .FirstOrDefault(x => x.IpAddress == ipAddress);

                return ipAttempt?.BanEndUtc;
            }
            catch (Exception ex)
            {
                _logger.LogError("DatabaseSecurityService", $"Error getting IP ban end time: {ex.Message}", ex);
                return null;
            }
        }

        public bool UnlockUser(User user)
        {
            try
            {
                _logger.Log("DatabaseSecurityService", $"Manually unlocking user {user.UserName}");
                
                user.FailedLoginAttempts = 0;
                user.LastFailedLoginAttempt = null;
                user.LockoutStart = null;
                user.LockoutEnd = null;
                
                _userStorage.UpdateUser(user);

                // Record user unlock security event (not lockout!)
                _metricsService.RecordSecurityEventAsync("user_unlock", $"User {user.UserName} manually unlocked", SecurityEventSeverity.Low, null, user.UserName);

                _logger.Log("DatabaseSecurityService", $"User {user.UserName} unlocked successfully");

                _mqttService.Publish("authly/user/unlock", new { userId = user.Id, userName = user.UserName, name = user.FullName, timestamp = DateTime.UtcNow });

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError("DatabaseSecurityService", $"Failed to unlock user {user.UserName}: {ex.Message}", ex);
                return false;
            }
        }

        public bool UnbanIpAddress(string ipAddress, string type = "Manual")
        {
            try
            {
                bool securityLog = false;
                _logger.Log("DatabaseSecurityService", $"Manually unbanning IP {ipAddress}");

                var ipAttempt = _context.IpLoginAttempts
                    .FirstOrDefault(x => x.IpAddress == ipAddress);

                if (ipAttempt != null)
                {
                    securityLog = ipAttempt.IsBanned;

                    ipAttempt.IsBanned = false;
                    ipAttempt.BanEndUtc = null;
                    ipAttempt.FailedAttempts = 0;
                    ipAttempt.FirstAttemptUtc = DateTime.UtcNow;
                    ipAttempt.LastAttemptUtc = DateTime.UtcNow;
                    ipAttempt.Note = $"{type} unban";
                }

                var unauthorizedAttempt = _context.IpLoginAttempts
                    .FirstOrDefault(x => x.IpAddress == ipAddress + "_unauthorized");

                if (unauthorizedAttempt != null)
                {
                    _context.IpLoginAttempts.Remove(unauthorizedAttempt);
                    _logger.Log("DatabaseSecurityService", $"Cleared unauthorized access tracking for IP {ipAddress}");
                }

                _context.SaveChanges();

                if (securityLog)
                {
                    // Record IP unban security event
                    _metricsService.RecordSecurityEventAsync("ip_unban", $"IP {ipAddress} manually unbanned", SecurityEventSeverity.Low, ipAddress);

                    _mqttService.PublishAsync("authly/ip/unban", new { ipAddress, note = ipAttempt.Note, timestamp = DateTime.UtcNow });
                }
                _logger.Log("DatabaseSecurityService", $"IP {ipAddress} unbanned successfully");
                
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError("DatabaseSecurityService", $"Error unbanning IP {ipAddress}: {ex.Message}", ex);
                return false;
            }
        }

        public List<IpLoginAttempt> GetAllIpBans()
        {
            try
            {
                var now = DateTime.UtcNow;
                return _context.IpLoginAttempts
                    .Where(x => !x.IpAddress.EndsWith("_unauthorized") && // Exclude unauthorized tracking records
                                (x.FailedAttempts > 0 || (x.IsBanned && x.BanEndUtc > now)))
                    .OrderByDescending(x => x.LastAttemptUtc)
                    .ToList();
            }
            catch (Exception ex)
            {
                _logger.LogError("DatabaseSecurityService", $"Error getting IP bans: {ex.Message}", ex);
                return new List<IpLoginAttempt>();
            }
        }

        public bool ManualLockUser(User user)
        {
            try
            {
                _logger.Log("DatabaseSecurityService", $"Manually locking user {user.UserName} permanently");
                
                user.LockoutStart = DateTime.UtcNow;
                user.LockoutEnd = DateTime.MaxValue; // Permanent lockout
                user.FailedLoginAttempts = _userLockoutOptions.MaxFailedAttempts;
                user.LastFailedLoginAttempt = DateTime.UtcNow;
                
                _userStorage.UpdateUser(user);

                // Record manual lockout security event
                _metricsService.RecordSecurityEventAsync("user_lockout", $"User {user.UserName} manually locked (permanent)", SecurityEventSeverity.High, null, user.UserName);

                _mqttService.Publish("authly/user/lock", new { userId = user.Id, userName = user.UserName, name = user.FullName, lockoutEnd = user.LockoutEnd, failedAttempts = user.FailedLoginAttempts, manual = true, timestamp = DateTime.UtcNow });

                _logger.Log("DatabaseSecurityService", $"User {user.UserName} locked permanently");
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError("DatabaseSecurityService", $"Failed to manually lock user {user.UserName}: {ex.Message}", ex);
                return false;
            }
        }

        public bool ManualBanIpAddress(string ipAddress, string note = null)
        {
            try
            {
                if (string.IsNullOrEmpty(ipAddress))
                {
                    _logger.LogWarning("DatabaseSecurityService", "Cannot ban empty IP address");
                    return false;
                }

                _logger.Log("DatabaseSecurityService", $"Manually banning IP {ipAddress} permanently");
                
                var now = DateTime.UtcNow;
                var ipAttempt = _context.IpLoginAttempts
                    .FirstOrDefault(x => x.IpAddress == ipAddress);

                var unauthorizedAttempt = _context.IpLoginAttempts
                    .FirstOrDefault(x => x.IpAddress == ipAddress + "_unauthorized");

                if (unauthorizedAttempt != null)
                {
                    _context.IpLoginAttempts.Remove(unauthorizedAttempt);
                    _logger.Log("DatabaseSecurityService", $"Cleared unauthorized access tracking for IP {ipAddress}");
                }

                if (ipAttempt == null)
                {
                    ipAttempt = new IpLoginAttempt
                    {
                        IpAddress = ipAddress,
                        FailedAttempts = unauthorizedAttempt?.FailedAttempts ?? _ipRateLimitingOptions.MaxAttemptsPerIp,
                        FirstAttemptUtc = unauthorizedAttempt?.FirstAttemptUtc ?? now,
                        LastAttemptUtc = now,
                        IsBanned = true,
                        BanEndUtc = DateTime.MaxValue,
                        Note = note ?? "Manual ban"
                    };
                    _context.IpLoginAttempts.Add(ipAttempt);
                }
                else
                {
                    ipAttempt.IsBanned = true;
                    ipAttempt.BanEndUtc = DateTime.MaxValue;
                    ipAttempt.LastAttemptUtc = now;
                    ipAttempt.FailedAttempts = Math.Max(ipAttempt.FailedAttempts, _ipRateLimitingOptions.MaxAttemptsPerIp);
                    ipAttempt.Note = note ?? "Manual ban";
                }

                _context.SaveChanges();

                // Record manual ban security event
                _metricsService.RecordSecurityEventAsync("ip_ban", $"IP {ipAddress} manually banned (permanent)", SecurityEventSeverity.High, ipAddress);

                _mqttService.Publish("authly/ip/ban", new { ipAddress, permanent = true, note = ipAttempt.Note, timestamp = DateTime.UtcNow });

                _logger.Log("DatabaseSecurityService", $"IP {ipAddress} banned permanently");
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError("DatabaseSecurityService", $"Failed to manually ban IP {ipAddress}: {ex.Message}", ex);
                return false;
            }
        }

        /// <summary>
        /// Cleanup old IP login attempts (used by DatabaseCleanupService)
        /// </summary>
        /// <param name="olderThanDays">Remove attempts older than this many days</param>
        /// <returns>Number of cleaned records</returns>
        public async Task<int> CleanupOldIpAttemptsAsync(int olderThanDays)
        {
            try
            {
                var cutoffDate = DateTime.UtcNow.AddDays(-olderThanDays);
                
                // Remove old IP attempts that are not currently banned (including unauthorized tracking)
                var oldIpAttempts = await _context.IpLoginAttempts
                    .Where(ip => ip.FirstAttemptUtc < cutoffDate && 
                                (!ip.IsBanned || (ip.BanEndUtc.HasValue && ip.BanEndUtc < DateTime.UtcNow)))
                    .ToListAsync();

                if (oldIpAttempts.Any())
                {
                    _context.IpLoginAttempts.RemoveRange(oldIpAttempts);
                    await _context.SaveChangesAsync();

                    var regularAttempts = oldIpAttempts.Count(x => !x.IpAddress.EndsWith("_unauthorized"));
                    var unauthorizedAttempts = oldIpAttempts.Count(x => x.IpAddress.EndsWith("_unauthorized"));

                    _logger.Log("DatabaseSecurityService", 
                        $"Cleaned up {regularAttempts} old IP attempts and {unauthorizedAttempts} unauthorized access attempts older than {olderThanDays} days");
                    
                    return oldIpAttempts.Count;
                }

                return 0;
            }
            catch (Exception ex)
            {
                _logger.LogError("DatabaseSecurityService", $"Error cleaning up old IP attempts: {ex.Message}", ex);
                return 0;
            }
        }

        /// <summary>
        /// Records an IP attempt and returns ban result if IP should be banned
        /// </summary>
        private AuthenticationResult? RecordIpAttempt(string ipAddress)
        {
            if (string.IsNullOrEmpty(ipAddress))
                return null;

            try
            {
                var now = DateTime.UtcNow;
                var ipAttempt = _context.IpLoginAttempts
                    .FirstOrDefault(x => x.IpAddress == ipAddress);

                if (ipAttempt == null)
                {
                    ipAttempt = new IpLoginAttempt
                    {
                        IpAddress = ipAddress,
                        FailedAttempts = 1,
                        FirstAttemptUtc = now,
                        LastAttemptUtc = now
                    };
                    _context.IpLoginAttempts.Add(ipAttempt);
                }
                else
                {
                    // If IP is already banned, don't increment further
                    if (ipAttempt.IsBanned && ipAttempt.BanEndUtc > now)
                    {
                        return null;
                    }

                    // Check if we should reset the sliding window
                    if (_ipRateLimitingOptions.SlidingWindow && 
                        ipAttempt.FirstAttemptUtc.AddMinutes(_ipRateLimitingOptions.WindowMinutes) < now)
                    {
                        ipAttempt.FailedAttempts = 1;
                        ipAttempt.FirstAttemptUtc = now;
                        ipAttempt.IsBanned = false;
                        ipAttempt.BanEndUtc = null;
                        ipAttempt.Note = "Sliding window reset";
                    }
                    else
                    {
                        ipAttempt.FailedAttempts++;
                    }
                    
                    ipAttempt.LastAttemptUtc = now;
                }

                // Check if IP should be banned
                if (ipAttempt.FailedAttempts >= _ipRateLimitingOptions.MaxAttemptsPerIp && !ipAttempt.IsBanned)
                {
                    ipAttempt.IsBanned = true;
                    ipAttempt.Note = "Exceeded max attempts";
                    ipAttempt.BanEndUtc = DateTime.UtcNow.AddMinutes(_ipRateLimitingOptions.BanDurationMinutes);
                    _logger.LogWarning("DatabaseSecurityService", $"IP {ipAddress} banned until {ipAttempt.BanEndUtc}");
                    
                    _context.SaveChanges();

                    // Record IP ban security event
                    _metricsService.RecordSecurityEventAsync("ip_ban", $"IP {ipAddress} banned due to {ipAttempt.FailedAttempts} failed attempts", SecurityEventSeverity.Medium, ipAddress);

                    _mqttService.PublishAsync("authly/ip/ban", 
                        new { ipAddress, banEnd = ipAttempt.BanEndUtc, failedAttempts = ipAttempt.FailedAttempts, note = ipAttempt.Note, manual = false, timestamp = DateTime.UtcNow });

                    return AuthenticationResult.IpBannedResult(ipAttempt.BanEndUtc.Value);
                }

                _context.SaveChanges();
                return null;
            }
            catch (Exception ex)
            {
                _logger.LogError("DatabaseSecurityService", $"Error recording IP attempt: {ex.Message}", ex);
                return null;
            }
        }

        /// <summary>
        /// Records a user attempt
        /// </summary>
        private void RecordUserAttempt(User user)
        {
            var now = DateTime.UtcNow;
            
            // Check if we should reset the sliding window
            if (_userLockoutOptions.SlidingWindow && 
                user.LastFailedLoginAttempt.HasValue &&
                user.LastFailedLoginAttempt.Value.AddMinutes(_userLockoutOptions.WindowMinutes) < now)
            {
                user.FailedLoginAttempts = 1;
            }
            else
            {
                user.FailedLoginAttempts++;
            }
            
            user.LastFailedLoginAttempt = now;
        }
    }
}
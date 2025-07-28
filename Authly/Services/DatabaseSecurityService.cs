using Authly.Models;
using Authly.Data;
using Authly.Authorization.UserStorage;
using Authly.Configuration;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

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

        public DatabaseSecurityService(
            AuthlyDbContext context,
            IApplicationLogger logger,
            IUserStorage userStorage,
            IOptions<UserLockoutOptions> userLockoutOptions,
            IOptions<IpRateLimitingOptions> ipRateLimitingOptions,             
            IMetricsService metricsService)
        {
            _context = context;
            _logger = logger;
            _userStorage = userStorage;
            _userLockoutOptions = userLockoutOptions.Value;
            _ipRateLimitingOptions = ipRateLimitingOptions.Value;
            _metricsService = metricsService;
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
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError("DatabaseSecurityService", $"Failed to unlock user {user.UserName}: {ex.Message}", ex);
                return false;
            }
        }

        public bool UnbanIpAddress(string ipAddress)
        {
            try
            {
                _logger.Log("DatabaseSecurityService", $"Manually unbanning IP {ipAddress}");
                
                var ipAttempt = _context.IpLoginAttempts
                    .FirstOrDefault(x => x.IpAddress == ipAddress);

                if (ipAttempt != null)
                {
                    ipAttempt.IsBanned = false;
                    ipAttempt.BanEndUtc = null;
                    ipAttempt.FailedAttempts = 0;
                    ipAttempt.FirstAttemptUtc = DateTime.UtcNow;
                    ipAttempt.LastAttemptUtc = DateTime.UtcNow;
                    
                    _context.SaveChanges();

                    // Record IP unban security event
                    _metricsService.RecordSecurityEventAsync("ip_unban", $"IP {ipAddress} manually unbanned", SecurityEventSeverity.Low, ipAddress);

                    _logger.Log("DatabaseSecurityService", $"IP {ipAddress} unbanned successfully");
                }
                
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
                    .Where(x => x.FailedAttempts > 0 || (x.IsBanned && x.BanEndUtc > now))
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

                _logger.Log("DatabaseSecurityService", $"User {user.UserName} locked permanently");
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError("DatabaseSecurityService", $"Failed to manually lock user {user.UserName}: {ex.Message}", ex);
                return false;
            }
        }

        public bool ManualBanIpAddress(string ipAddress)
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

                if (ipAttempt == null)
                {
                    ipAttempt = new IpLoginAttempt
                    {
                        IpAddress = ipAddress,
                        FailedAttempts = _ipRateLimitingOptions.MaxAttemptsPerIp,
                        FirstAttemptUtc = now,
                        LastAttemptUtc = now,
                        IsBanned = true,
                        BanEndUtc = DateTime.MaxValue
                    };
                    _context.IpLoginAttempts.Add(ipAttempt);
                }
                else
                {
                    ipAttempt.IsBanned = true;
                    ipAttempt.BanEndUtc = DateTime.MaxValue;
                    ipAttempt.LastAttemptUtc = now;
                    ipAttempt.FailedAttempts = Math.Max(ipAttempt.FailedAttempts, _ipRateLimitingOptions.MaxAttemptsPerIp);
                }

                _context.SaveChanges();

                // Record manual ban security event
                _metricsService.RecordSecurityEventAsync("ip_ban", $"IP {ipAddress} manually banned (permanent)", SecurityEventSeverity.High, ipAddress);

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
                
                // Remove old IP attempts that are not currently banned
                var oldIpAttempts = await _context.IpLoginAttempts
                    .Where(ip => ip.FirstAttemptUtc < cutoffDate && 
                                (!ip.IsBanned || (ip.BanEndUtc.HasValue && ip.BanEndUtc < DateTime.UtcNow)))
                    .ToListAsync();

                if (oldIpAttempts.Any())
                {
                    _context.IpLoginAttempts.RemoveRange(oldIpAttempts);
                    await _context.SaveChangesAsync();

                    _logger.Log("DatabaseSecurityService", $"Cleaned up {oldIpAttempts.Count} old IP attempts older than {olderThanDays} days");
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
                    ipAttempt.BanEndUtc = DateTime.UtcNow.AddMinutes(_ipRateLimitingOptions.BanDurationMinutes);
                    _logger.LogWarning("DatabaseSecurityService", $"IP {ipAddress} banned until {ipAttempt.BanEndUtc}");
                    
                    _context.SaveChanges();

                    // Record IP ban security event
                    _metricsService.RecordSecurityEventAsync("ip_ban", $"IP {ipAddress} banned due to {ipAttempt.FailedAttempts} failed attempts", SecurityEventSeverity.Medium, ipAddress);

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
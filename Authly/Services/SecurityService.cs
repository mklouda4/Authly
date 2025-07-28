using Authly.Configuration;
using Authly.Models;
using Microsoft.Extensions.Options;
using System.Collections.Concurrent;
using System.Text.Json;

namespace Authly.Services
{
    /// <summary>
    /// Interface for security service managing failed login attempts and lockouts
    /// </summary>
    public interface ISecurityService
    {
        /// <summary>
        /// Checks if a user is currently locked out
        /// </summary>
        /// <param name="user">User to check</param>
        /// <returns>True if user is locked out</returns>
        bool IsUserLockedOut(User user);

        /// <summary>
        /// Checks if an IP address is currently banned
        /// </summary>
        /// <param name="ipAddress">IP address to check</param>
        /// <returns>True if IP is banned</returns>
        bool IsIpBanned(string ipAddress);

        /// <summary>
        /// Records a failed login attempt for a user and IP
        /// </summary>
        /// <param name="user">User who failed to login (can be null if user not found)</param>
        /// <param name="ipAddress">IP address of the attempt</param>
        /// <returns>Authentication result with lockout information</returns>
        AuthenticationResult RecordFailedAttempt(User? user, string ipAddress);

        /// <summary>
        /// Records an unauthorized access attempt (redirect to login, 401, 403, etc.)
        /// </summary>
        /// <param name="ipAddress">IP address of the attempt</param>
        /// <param name="path">Path that was accessed</param>
        /// <param name="statusCode">HTTP status code returned</param>
        /// <param name="operationType">Type of operation attempted</param>
        /// <returns>True if IP should be banned</returns>
        Task<bool> RecordUnauthorizedAccessAsync(string ipAddress, string path, int statusCode, string operationType);

        /// <summary>
        /// Clears failed login attempts for a user after successful login
        /// NOTE: This does NOT clear IP attempts to prevent security bypass
        /// </summary>
        /// <param name="user">User who successfully logged in</param>
        void ClearUserFailedAttempts(User user);

        /// <summary>
        /// Gets the remaining attempts before lockout for a user
        /// </summary>
        /// <param name="user">User to check</param>
        /// <returns>Number of remaining attempts</returns>
        int GetRemainingAttempts(User user);

        /// <summary>
        /// Gets the lockout end time for a user
        /// </summary>
        /// <param name="user">User to check</param>
        /// <returns>Lockout end time or null if not locked out</returns>
        DateTime? GetLockoutEndTime(User user);

        /// <summary>
        /// Gets the ban end time for an IP address
        /// </summary>
        /// <param name="ipAddress">IP address to check</param>
        /// <returns>Ban end time or null if not banned</returns>
        DateTime? GetIpBanEndTime(string ipAddress);

        /// <summary>
        /// Manually unlocks a user
        /// </summary>
        /// <param name="user">User to unlock</param>
        /// <returns>True if unlock successful</returns>
        bool UnlockUser(User user);

        /// <summary>
        /// Manually unbans an IP address
        /// </summary>
        /// <param name="ipAddress">IP address to unban</param>
        /// <returns>True if unban successful</returns>
        bool UnbanIpAddress(string ipAddress);

        /// <summary>
        /// Gets all current IP bans
        /// </summary>
        /// <returns>List of current IP ban information</returns>
        List<IpLoginAttempt> GetAllIpBans();

        /// <summary>
        /// Manually locks a user permanently (until manual unlock)
        /// </summary>
        /// <param name="user">User to lock permanently</param>
        /// <returns>True if lock successful</returns>
        bool ManualLockUser(User user);

        /// <summary>
        /// Manually bans an IP address permanently (until manual unban)
        /// </summary>
        /// <param name="ipAddress">IP address to ban permanently</param>
        /// <returns>True if ban successful</returns>
        bool ManualBanIpAddress(string ipAddress);
    }

    /// <summary>
    /// Security service implementation for managing failed login attempts and lockouts
    /// </summary>
    public class SecurityService : ISecurityService
    {
        private readonly UserLockoutOptions _userLockoutOptions;
        private readonly IpRateLimitingOptions _ipRateLimitingOptions;
        private readonly IApplicationLogger _logger;
        private readonly IWebHostEnvironment _environment;
        private readonly IMetricsService _metricsService;

        // In-memory storage for IP attempts with file persistence
        private readonly ConcurrentDictionary<string, IpLoginAttempt> _ipAttempts = new();
        
        // In-memory storage for unauthorized access tracking
        private readonly ConcurrentDictionary<string, UnauthorizedAccessTracker> _unauthorizedAccess = new();
        
        private readonly string _ipBansFilePath;
        private readonly JsonSerializerOptions _jsonSerializerOptions;

        public SecurityService(
            IOptions<UserLockoutOptions> userLockoutOptions,
            IOptions<IpRateLimitingOptions> ipRateLimitingOptions,
            IApplicationLogger logger,
            IWebHostEnvironment environment,
            IMetricsService metricsService)
        {
            _userLockoutOptions = userLockoutOptions.Value;
            _ipRateLimitingOptions = ipRateLimitingOptions.Value;
            _logger = logger;
            _environment = environment;
            _metricsService = metricsService;
            
            _ipBansFilePath = Path.Combine(_environment.WebRootPath ?? _environment.ContentRootPath, "data", "ip-bans.json");
            _jsonSerializerOptions = new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true,
                WriteIndented = true
            };

            // Load existing IP bans from file
            LoadIpBansFromFile();
        }

        /// <summary>
        /// Checks if a user is currently locked out
        /// </summary>
        public bool IsUserLockedOut(User user)
        {
            if (!_userLockoutOptions.Enabled || user.LockoutEnd == null)
                return false;

            return user.LockoutEnd > DateTime.UtcNow;
        }

        /// <summary>
        /// Checks if an IP address is currently banned
        /// </summary>
        public bool IsIpBanned(string ipAddress)
        {
            if (!_ipRateLimitingOptions.Enabled || string.IsNullOrEmpty(ipAddress))
                return false;

            if (_ipAttempts.TryGetValue(ipAddress, out var attempt))
            {
                if (attempt.BanEndUtc.HasValue && attempt.BanEndUtc > DateTime.UtcNow)
                {
                    return true;
                }
                // Clean up expired bans
                else if (attempt.BanEndUtc.HasValue && attempt.BanEndUtc <= DateTime.UtcNow)
                {
                    attempt.IsBanned = false;
                    attempt.BanEndUtc = null;
                    
                    // If sliding window is disabled, reset failed attempts after ban expires
                    // This gives the IP a "clean slate" after serving their ban time
                    if (!_ipRateLimitingOptions.SlidingWindow)
                    {
                        attempt.FailedAttempts = 0;
                        attempt.FirstAttemptUtc = DateTime.UtcNow;
                        _logger.Log("SecurityService", $"IP {ipAddress} ban expired, failed attempts reset to 0 (sliding window disabled)");
                    }
                    else
                    {
                        _logger.Log("SecurityService", $"IP {ipAddress} ban expired, failed attempts preserved (sliding window enabled)");
                    }
                    
                    SaveIpBansToFile();
                }
            }

            return false;
        }

        /// <summary>
        /// Records a failed login attempt for a user and IP
        /// </summary>
        public AuthenticationResult RecordFailedAttempt(User? user, string ipAddress)
        {
            _logger.Log("SecurityService", $"Recording failed attempt for user {user?.UserName ?? "unknown"} from IP {ipAddress}");

            // Check IP ban first (regardless of user)
            if (IsIpBanned(ipAddress))
            {
                var banEnd = GetIpBanEndTime(ipAddress);
                _logger.LogWarning("SecurityService", $"IP {ipAddress} is banned until {banEnd}");
                return AuthenticationResult.IpBannedResult(banEnd ?? DateTime.UtcNow.AddMinutes(_ipRateLimitingOptions.BanDurationMinutes));
            }

            // Record IP attempt (even if user not found - this is important for security)
            if (_ipRateLimitingOptions.Enabled)
            {
                var ipResult = RecordIpAttempt(ipAddress);
                if (ipResult != null)
                {
                    // IP was banned as a result of this attempt
                    return ipResult;
                }
            }

            // Check user lockout only if user exists
            if (user != null)
            {
                if (IsUserLockedOut(user))
                {
                    var lockoutEnd = GetLockoutEndTime(user);
                    _logger.LogWarning("SecurityService", $"User {user.UserName} is locked out until {lockoutEnd}");
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
                    _logger.LogWarning("SecurityService", $"User {user.UserName} locked out until {user.LockoutEnd}");
                    
                    // Record user lockout security event
                    _metricsService.RecordSecurityEventAsync("user_lockout", $"User {user.UserName} locked due to {user.FailedLoginAttempts} failed attempts", SecurityEventSeverity.Medium, ipAddress, user.UserName);
                    
                    return AuthenticationResult.LockedOutResult(user.LockoutEnd.Value);
                }

                var remainingAttempts = GetRemainingAttempts(user);
                _logger.Log("SecurityService", $"User {user.UserName} has {remainingAttempts} remaining attempts");
                
                return AuthenticationResult.FailedResult("Invalid credentials", remainingAttempts);
            }

            // User not found - don't give away information
            return AuthenticationResult.FailedResult("Invalid credentials");
        }

        /// <summary>
        /// Records an unauthorized access attempt and returns true if IP should be banned
        /// </summary>
        public async Task<bool> RecordUnauthorizedAccessAsync(string ipAddress, string path, int statusCode, string operationType)
        {
            if (!_ipRateLimitingOptions.Enabled || string.IsNullOrEmpty(ipAddress))
                return false;

            var now = DateTime.UtcNow;
            var threshold = _ipRateLimitingOptions.MaxAttemptsPerIp * 2; // 2x the normal threshold
            
            var tracker = _unauthorizedAccess.AddOrUpdate(ipAddress,
                new UnauthorizedAccessTracker
                {
                    IpAddress = ipAddress,
                    AttemptCount = 1,
                    FirstAttemptUtc = now,
                    LastAttemptUtc = now,
                    LastPath = path,
                    LastStatusCode = statusCode,
                    LastOperationType = operationType
                },
                (key, existing) =>
                {
                    // Check if we should reset the sliding window
                    if (_ipRateLimitingOptions.SlidingWindow && 
                        existing.FirstAttemptUtc.AddMinutes(_ipRateLimitingOptions.WindowMinutes) < now)
                    {
                        existing.AttemptCount = 1;
                        existing.FirstAttemptUtc = now;
                    }
                    else
                    {
                        existing.AttemptCount++;
                    }
                    
                    existing.LastAttemptUtc = now;
                    existing.LastPath = path;
                    existing.LastStatusCode = statusCode;
                    existing.LastOperationType = operationType;
                    return existing;
                });

            // Log periodic warnings and record security events
            if (tracker.AttemptCount % 5 == 0 || tracker.AttemptCount >= threshold)
            {
                var severity = tracker.AttemptCount >= threshold ? SecurityEventSeverity.High : SecurityEventSeverity.Medium;
                
                await _metricsService.RecordSecurityEventAsync(
                    "unauthorized_access_pattern",
                    $"IP {ipAddress} made {tracker.AttemptCount} unauthorized access attempts. Last: {operationType} -> {statusCode}",
                    severity,
                    ipAddress);

                _logger.LogWarning("SecurityService", 
                    $"IP {ipAddress} has made {tracker.AttemptCount} unauthorized access attempts. " +
                    $"Last attempt: {operationType} -> {statusCode} at {path}");
            }

            // Check if we should ban the IP
            if (tracker.AttemptCount >= threshold)
            {
                _logger.LogWarning("SecurityService", 
                    $"IP {ipAddress} exceeded unauthorized access threshold ({tracker.AttemptCount}/{threshold}). " +
                    "Recommending automatic ban.");
                    
                return true;
            }

            return false;
        }

        /// <summary>
        /// Clears failed login attempts for a user after successful login
        /// IMPORTANT: This does NOT clear IP attempts to prevent security bypass
        /// </summary>
        public void ClearUserFailedAttempts(User user)
        {
            _logger.Log("SecurityService", $"Clearing failed attempts for user {user.UserName}");

            // Clear user attempts only
            if (_userLockoutOptions.Enabled)
            {
                user.FailedLoginAttempts = 0;
                user.LastFailedLoginAttempt = null;
                user.LockoutStart = null;
                user.LockoutEnd = null;
            }

            // IMPORTANT: We do NOT clear IP attempts here!
            // This prevents an attacker from using a compromised account to reset IP bans
            _logger.Log("SecurityService", $"IP attempts NOT cleared for security reasons");
        }

        /// <summary>
        /// Gets the remaining attempts before lockout for a user
        /// </summary>
        public int GetRemainingAttempts(User user)
        {
            if (!_userLockoutOptions.Enabled)
                return int.MaxValue;

            return Math.Max(0, _userLockoutOptions.MaxFailedAttempts - user.FailedLoginAttempts);
        }

        /// <summary>
        /// Gets the lockout end time for a user
        /// </summary>
        public DateTime? GetLockoutEndTime(User user)
        {
            if (!_userLockoutOptions.Enabled)
                return null;

            return user.LockoutEnd;
        }

        /// <summary>
        /// Gets the ban end time for an IP address
        /// </summary>
        public DateTime? GetIpBanEndTime(string ipAddress)
        {
            if (!_ipRateLimitingOptions.Enabled || string.IsNullOrEmpty(ipAddress))
                return null;

            if (_ipAttempts.TryGetValue(ipAddress, out var attempt))
            {
                return attempt.BanEndUtc;
            }

            return null;
        }

        /// <summary>
        /// Manually unlocks a user
        /// </summary>
        public bool UnlockUser(User user)
        {
            try
            {
                _logger.Log("SecurityService", $"Manually unlocking user {user.UserName}");
                
                user.FailedLoginAttempts = 0;
                user.LastFailedLoginAttempt = null;
                user.LockoutStart = null;
                user.LockoutEnd = null;
                
                _logger.Log("SecurityService", $"User {user.UserName} unlocked successfully");
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError("SecurityService", $"Failed to unlock user {user.UserName}: {ex.Message}", ex);
                return false;
            }
        }

        /// <summary>
        /// Manually unbans an IP address
        /// </summary>
        public bool UnbanIpAddress(string ipAddress)
        {
            try
            {
                _logger.Log("SecurityService", $"Manually unbanning IP {ipAddress}");
                
                if (_ipAttempts.TryGetValue(ipAddress, out var attempt))
                {
                    attempt.IsBanned = false;
                    attempt.BanEndUtc = null;
                    attempt.FailedAttempts = 0;
                    attempt.FirstAttemptUtc = DateTime.UtcNow;
                    attempt.LastAttemptUtc = DateTime.UtcNow;
                    
                    SaveIpBansToFile();
                    _logger.Log("SecurityService", $"IP {ipAddress} unbanned successfully");
                }

                // Also clear unauthorized access tracking
                _unauthorizedAccess.TryRemove(ipAddress, out _);
                
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError("SecurityService", $"Failed to unban IP {ipAddress}: {ex.Message}", ex);
                return false;
            }
        }

        /// <summary>
        /// Records an IP attempt and returns ban result if IP should be banned
        /// </summary>
        private AuthenticationResult? RecordIpAttempt(string ipAddress)
        {
            if (string.IsNullOrEmpty(ipAddress))
                return null;

            var now = DateTime.UtcNow;
            var result = _ipAttempts.AddOrUpdate(ipAddress, 
                new IpLoginAttempt 
                { 
                    IpAddress = ipAddress, 
                    FailedAttempts = 1, 
                    FirstAttemptUtc = now, 
                    LastAttemptUtc = now 
                },
                (key, existing) =>
                {
                    // If IP is already banned, don't increment further
                    if (existing.IsBanned && existing.BanEndUtc > now)
                    {
                        return existing;
                    }

                    // Check if we should reset the sliding window
                    if (_ipRateLimitingOptions.SlidingWindow && 
                        existing.FirstAttemptUtc.AddMinutes(_ipRateLimitingOptions.WindowMinutes) < now)
                    {
                        existing.FailedAttempts = 1;
                        existing.FirstAttemptUtc = now;
                        existing.IsBanned = false;
                        existing.BanEndUtc = null;
                    }
                    else
                    {
                        existing.FailedAttempts++;
                    }
                    
                    existing.LastAttemptUtc = now;
                    return existing;
                });

            // Check if IP should be banned
            if (result.FailedAttempts >= _ipRateLimitingOptions.MaxAttemptsPerIp && !result.IsBanned)
            {
                result.IsBanned = true;
                result.BanEndUtc = DateTime.UtcNow.AddMinutes(_ipRateLimitingOptions.BanDurationMinutes);
                _logger.LogWarning("SecurityService", $"IP {ipAddress} banned until {result.BanEndUtc}");
                
                // Record IP ban metric
                _metricsService.RecordIpBan();
                
                // Save IP bans immediately when an IP gets banned
                SaveIpBansToFile();
                
                return AuthenticationResult.IpBannedResult(result.BanEndUtc.Value);
            }

            // Save IP attempts to file periodically (every 5 attempts) or immediately if this is the first attempt
            if (result.FailedAttempts == 1 || result.FailedAttempts % 5 == 0)
            {
                SaveIpBansToFile();
            }

            return null;
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

        /// <summary>
        /// Loads IP bans from file
        /// </summary>
        private void LoadIpBansFromFile()
        {
            try
            {
                var directory = Path.GetDirectoryName(_ipBansFilePath);
                if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
                {
                    Directory.CreateDirectory(directory);
                }

                if (File.Exists(_ipBansFilePath))
                {
                    var json = File.ReadAllText(_ipBansFilePath);
                    var ipBans = JsonSerializer.Deserialize<List<IpLoginAttempt>>(json, _jsonSerializerOptions);

                    if (ipBans != null)
                    {
                        foreach (var ipBan in ipBans)
                        {
                            // Only load non-expired bans
                            if (ipBan.BanEndUtc == null || ipBan.BanEndUtc > DateTime.UtcNow)
                            {
                                _ipAttempts.TryAdd(ipBan.IpAddress, ipBan);
                            }
                        }
                        
                        _logger.Log("SecurityService", $"Loaded {ipBans.Count} IP ban records from file");
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError("SecurityService", $"Failed to load IP bans from file: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Saves IP bans to file
        /// </summary>
        private void SaveIpBansToFile()
        {
            try
            {
                var ipBansToSave = _ipAttempts.Values
                    .Where(x => x.FailedAttempts > 0 || x.IsBanned)
                    .ToList();

                var json = JsonSerializer.Serialize(ipBansToSave, _jsonSerializerOptions);
                File.WriteAllText(_ipBansFilePath, json);
                
                _logger.Log("SecurityService", $"Saved {ipBansToSave.Count} IP ban records to file");
            }
            catch (Exception ex)
            {
                _logger.LogError("SecurityService", $"Failed to save IP bans to file: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Gets all current IP bans
        /// </summary>
        public List<IpLoginAttempt> GetAllIpBans()
        {
            try
            {
                var now = DateTime.UtcNow;
                return [.. _ipAttempts.Values
                    .Where(x => x.FailedAttempts > 0 || (x.IsBanned && x.BanEndUtc > now))
                    .OrderByDescending(x => x.LastAttemptUtc)];
            }
            catch (Exception ex)
            {
                _logger.LogError("SecurityService", $"Failed to get IP bans: {ex.Message}", ex);
                return [];
            }
        }

        /// <summary>
        /// Manually locks a user permanently (until manual unlock)
        /// </summary>
        public bool ManualLockUser(User user)
        {
            try
            {
                _logger.Log("SecurityService", $"Manually locking user {user.UserName} permanently");
                
                user.LockoutStart = DateTime.UtcNow;
                user.LockoutEnd = DateTime.MaxValue; // Permanent lockout
                user.FailedLoginAttempts = _userLockoutOptions.MaxFailedAttempts; // Set to max to indicate locked state
                user.LastFailedLoginAttempt = DateTime.UtcNow;
                
                // Record manual lockout metric
                _metricsService.RecordSecurityEvent("ManualUserLock");
                
                _logger.Log("SecurityService", $"User {user.UserName} locked permanently until manual unlock");
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError("SecurityService", $"Failed to manually lock user {user.UserName}: {ex.Message}", ex);
                return false;
            }
        }

        /// <summary>
        /// Manually bans an IP address permanently (until manual unban)
        /// </summary>
        public bool ManualBanIpAddress(string ipAddress)
        {
            try
            {
                if (string.IsNullOrEmpty(ipAddress))
                {
                    _logger.LogWarning("SecurityService", "Cannot ban empty IP address");
                    return false;
                }

                _logger.Log("SecurityService", $"Manually banning IP {ipAddress} permanently");
                
                var now = DateTime.UtcNow;
                var banRecord = _ipAttempts.AddOrUpdate(ipAddress,
                    new IpLoginAttempt
                    {
                        IpAddress = ipAddress,
                        FailedAttempts = _ipRateLimitingOptions.MaxAttemptsPerIp, // Set to max to indicate banned state
                        FirstAttemptUtc = now,
                        LastAttemptUtc = now,
                        IsBanned = true,
                        BanEndUtc = DateTime.MaxValue // Permanent ban
                    },
                    (key, existing) =>
                    {
                        existing.IsBanned = true;
                        existing.BanEndUtc = DateTime.MaxValue; // Permanent ban
                        existing.LastAttemptUtc = now;
                        // Keep existing failed attempts or set to max if lower
                        existing.FailedAttempts = Math.Max(existing.FailedAttempts, _ipRateLimitingOptions.MaxAttemptsPerIp);
                        return existing;
                    });

                // Save changes immediately
                SaveIpBansToFile();
                
                // Record manual ban metric
                _metricsService.RecordSecurityEvent("ManualIpBan");
                
                _logger.Log("SecurityService", $"IP {ipAddress} banned permanently until manual unban");
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError("SecurityService", $"Failed to manually ban IP {ipAddress}: {ex.Message}", ex);
                return false;
            }
        }
    }

    /// <summary>
    /// Tracks unauthorized access attempts from an IP address
    /// </summary>
    internal class UnauthorizedAccessTracker
    {
        public string IpAddress { get; set; } = string.Empty;
        public int AttemptCount { get; set; }
        public DateTime FirstAttemptUtc { get; set; }
        public DateTime LastAttemptUtc { get; set; }
        public string LastPath { get; set; } = string.Empty;
        public int LastStatusCode { get; set; }
        public string LastOperationType { get; set; } = string.Empty;
    }
}
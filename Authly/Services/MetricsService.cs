using Prometheus;
using Authly.Configuration;
using Microsoft.Extensions.Options;
using Authly.Data;
using Authly.Models;
using Microsoft.EntityFrameworkCore;

namespace Authly.Services
{
    /// <summary>
    /// Interface for application metrics service
    /// </summary>
    public interface IMetricsService
    {
        /// <summary>
        /// Record login attempt with detailed information
        /// </summary>
        /// <param name="success">Whether the login was successful</param>
        /// <param name="reason">Reason for failure (if any)</param>
        /// <param name="ipAddress">IP address of the attempt</param>
        /// <param name="userAgent">User agent string</param>
        /// <param name="username">Username attempted</param>
        Task RecordLoginAttemptAsync(bool success, string? reason = null, string? ipAddress = null, string? userAgent = null, string? username = null);

        /// <summary>
        /// Record security event
        /// </summary>
        /// <param name="eventType">Type of security event</param>
        /// <param name="details">Additional details</param>
        /// <param name="severity">Event severity</param>
        /// <param name="ipAddress">IP address associated with event</param>
        /// <param name="username">Username associated with event</param>
        Task RecordSecurityEventAsync(string eventType, string? details = null, SecurityEventSeverity severity = SecurityEventSeverity.Medium, string? ipAddress = null, string? username = null);

        /// <summary>
        /// Record active user sessions count
        /// </summary>
        /// <param name="count">Number of active sessions</param>
        Task RecordActiveUserSessionsAsync(int count);

        /// <summary>
        /// Gets login attempts statistics
        /// </summary>
        Task<(int successful, int failed, double successRate)> GetLoginAttemptsStatsAsync(DateTime? since = null);

        /// <summary>
        /// Gets security events by type
        /// </summary>
        Task<Dictionary<string, int>> GetSecurityEventsByTypeAsync(DateTime? since = null);

        /// <summary>
        /// Gets the latest active sessions count
        /// </summary>
        Task<int> GetActiveUserSessionsAsync();

        /// <summary>
        /// Gets user lockout count
        /// </summary>
        Task<int> GetUserLockoutsAsync(DateTime? since = null);

        /// <summary>
        /// Gets IP ban count
        /// </summary>
        Task<int> GetIpBansAsync(DateTime? since = null);

        /// <summary>
        /// Generates sample data for testing (only in development)
        /// </summary>
        Task GenerateSampleDataAsync();

        /// <summary>
        /// Indicates if metrics collection is enabled
        /// </summary>
        bool IsEnabled { get; }

        /// <summary>
        /// Cleans up old metrics data based on retention policy
        /// </summary>
        /// <param name="retentionDays">Number of days to retain data</param>
        Task CleanupOldMetricsAsync(int retentionDays = 90);

        /// <summary>
        /// Gets metrics statistics for a specific time period
        /// </summary>
        Task<object> GetMetricsStatsAsync(DateTime since, DateTime until);

        // Backward compatibility methods (for Prometheus)
        void RecordLoginAttempt(bool success, string? reason = null);
        void RecordUserLockout();
        void RecordIpBan();
        void RecordActiveUserSessions(int count);
        void RecordSecurityEvent(string eventType);
        double GetSuccessfulLoginAttempts();
        double GetFailedLoginAttempts();
        double GetUserLockouts();
        double GetIpBans();
        double GetActiveUserSessions();
        Dictionary<string, double> GetSecurityEventsByType();
        void GenerateSampleData();
    }

    /// <summary>
    /// Database-backed metrics service that also supports Prometheus
    /// </summary>
    public class MetricsService : IMetricsService
    {
        private readonly ApplicationOptions _options;
        private readonly IApplicationLogger _logger;
        private readonly IDbContextFactory<AuthlyDbContext> _dbContextFactory;
        private readonly IHttpContextAccessor _httpContextAccessor;

        // Prometheus metrics (pro backward compatibility a monitoring)
        private readonly Counter _loginAttemptsCounter = Metrics.CreateCounter(
                "authly_login_attempts_total",
                "Total number of login attempts",
                ["result", "reason"]);
        private readonly Counter _userLockoutsCounter = Metrics.CreateCounter(
                "authly_user_lockouts_total",
                "Total number of user lockouts");
        private readonly Counter _ipBansCounter = Metrics.CreateCounter(
                "authly_ip_bans_total",
                "Total number of IP bans");
        private readonly Gauge _activeUserSessionsGauge = Metrics.CreateGauge(
                "authly_active_user_sessions",
                "Number of active user sessions");
        private readonly Counter _securityEventsCounter = Metrics.CreateCounter(
                "authly_security_events_total",
                "Total number of security events",
                ["event_type"]);

        public MetricsService(
            IOptions<ApplicationOptions> options, 
            IApplicationLogger logger,
            IDbContextFactory<AuthlyDbContext> dbContextFactory,
            IHttpContextAccessor httpContextAccessor)
        {
            _options = options.Value;
            _logger = logger;
            _dbContextFactory = dbContextFactory;
            _httpContextAccessor = httpContextAccessor;
        }

        /// <summary>
        /// Indicates if metrics collection is enabled
        /// </summary>
        public bool IsEnabled => true; // Vždy aktivní pro databázi, Prometheus závisí na konfiguraci

        /// <summary>
        /// Record login attempt with detailed information
        /// </summary>
        public async Task RecordLoginAttemptAsync(bool success, string? reason = null, string? ipAddress = null, string? userAgent = null, string? username = null)
        {
            try
            {
                // Uložit do databáze (vždy)
                var loginAttempt = new LoginAttemptMetric
                {
                    Success = success,
                    FailureReason = reason,
                    IpAddress = ipAddress,
                    UserAgent = userAgent,
                    Username = username,
                    CreatedAt = DateTime.UtcNow
                };

                using var dbContext = await _dbContextFactory.CreateDbContextAsync();
                dbContext.LoginAttemptMetrics.Add(loginAttempt);
                await dbContext.SaveChangesAsync();

                // Také aktualizovat Prometheus (pokud je povoleno)
                if (_options.EnableMetrics)
                {
                    var result = success ? "success" : "failure";
                    var reasonLabel = reason ?? "unknown";
                    _loginAttemptsCounter.WithLabels(result, reasonLabel).Inc();
                }

                _logger.LogDebug("MetricsService", $"Recorded login attempt: Success={success}, Reason={reason}, IP={ipAddress}, User={username}");
            }
            catch (Exception ex)
            {
                _logger.LogError("MetricsService", "Error recording login attempt metric", ex);
            }
        }

        /// <summary>
        /// Record security event
        /// </summary>
        public async Task RecordSecurityEventAsync(string eventType, string? details = null, SecurityEventSeverity severity = SecurityEventSeverity.Medium, string? ipAddress = null, string? username = null)
        {
            try
            {
                // Uložit do databáze (vždy)
                var securityEvent = new SecurityEventMetric
                {
                    EventType = eventType,
                    Details = details,
                    Severity = severity,
                    IpAddress = ipAddress,
                    Username = username,
                    CreatedAt = DateTime.UtcNow
                };

                using var dbContext = await _dbContextFactory.CreateDbContextAsync();
                dbContext.SecurityEventMetrics.Add(securityEvent);
                await dbContext.SaveChangesAsync();

                // Také aktualizovat Prometheus (pokud je povoleno)
                if (_options.EnableMetrics)
                {
                    _securityEventsCounter.WithLabels(eventType).Inc();
                }

                // Automaticky zaznamenat specifické události
                if (eventType == "user_lockout")
                {
                    if (_options.EnableMetrics)
                        _userLockoutsCounter.Inc();
                }
                else if (eventType == "ip_ban")
                {
                    if (_options.EnableMetrics)
                        _ipBansCounter.Inc();
                }

                _logger.LogDebug("MetricsService", $"Recorded security event: Type={eventType}, Severity={severity}, IP={ipAddress}, User={username}");
            }
            catch (Exception ex)
            {
                _logger.LogError("MetricsService", "Error recording security event metric", ex);
            }
        }

        /// <summary>
        /// Record active user sessions count
        /// </summary>
        public async Task RecordActiveUserSessionsAsync(int count)
        {
            try
            {
                using var dbContext = await _dbContextFactory.CreateDbContextAsync();
                // Uložit do databáze (vždy) - jen novou hodnotu každých 5 minut
                var lastRecord = await dbContext.ActiveSessionMetrics
                    .OrderByDescending(x => x.CreatedAt)
                    .FirstOrDefaultAsync();

                // Přidat nový záznam pouze pokud se počet změnil nebo uplynulo více než 5 minut
                if (lastRecord == null || 
                    lastRecord.SessionCount != count || 
                    DateTime.UtcNow - lastRecord.CreatedAt > TimeSpan.FromMinutes(5))
                {
                    var sessionMetric = new ActiveSessionMetric
                    {
                        SessionCount = count,
                        CreatedAt = DateTime.UtcNow
                    };

                    dbContext.ActiveSessionMetrics.Add(sessionMetric);
                    await dbContext.SaveChangesAsync();
                }

                // Také aktualizovat Prometheus (pokud je povoleno)
                if (_options.EnableMetrics)
                {
                    _activeUserSessionsGauge.Set(count);
                }

                _logger.LogDebug("MetricsService", $"Recorded active user sessions: {count}");
            }
            catch (Exception ex)
            {
                _logger.LogError("MetricsService", "Error recording active user sessions metric", ex);
            }
        }

        /// <summary>
        /// Gets login attempts statistics
        /// </summary>
        public async Task<(int successful, int failed, double successRate)> GetLoginAttemptsStatsAsync(DateTime? since = null)
        {
            try
            {
                using var dbContext = await _dbContextFactory.CreateDbContextAsync();
                var query = dbContext.LoginAttemptMetrics.AsQueryable();
                
                if (since.HasValue)
                {
                    query = query.Where(x => x.CreatedAt >= since.Value);
                }

                var successful = await query.CountAsync(x => x.Success);
                var failed = await query.CountAsync(x => !x.Success);
                var total = successful + failed;
                var successRate = total > 0 ? (double)successful / total * 100 : 0;

                return (successful, failed, Math.Round(successRate, 2));
            }
            catch (Exception ex)
            {
                _logger.LogError("MetricsService", "Error getting login attempts stats", ex);
                return (0, 0, 0);
            }
        }

        /// <summary>
        /// Gets security events by type
        /// </summary>
        public async Task<Dictionary<string, int>> GetSecurityEventsByTypeAsync(DateTime? since = null)
        {
            try
            {
                using var dbContext = await _dbContextFactory.CreateDbContextAsync();
                var query = dbContext.SecurityEventMetrics.AsQueryable();
                
                if (since.HasValue)
                {
                    query = query.Where(x => x.CreatedAt >= since.Value);
                }

                var events = await query
                    .GroupBy(x => x.EventType)
                    .Select(g => new { EventType = g.Key, Count = g.Count() })
                    .ToDictionaryAsync(x => x.EventType, x => x.Count);

                return events;
            }
            catch (Exception ex)
            {
                _logger.LogError("MetricsService", "Error getting security events by type", ex);
                return new Dictionary<string, int>();
            }
        }

        /// <summary>
        /// Gets the latest active sessions count
        /// </summary>
        public async Task<int> GetActiveUserSessionsAsync()
        {
            try
            {
                using var dbContext = await _dbContextFactory.CreateDbContextAsync();
                var latest = await dbContext.ActiveSessionMetrics
                    .OrderByDescending(x => x.CreatedAt)
                    .FirstOrDefaultAsync();

                return latest?.SessionCount ?? 0;
            }
            catch (Exception ex)
            {
                _logger.LogError("MetricsService", "Error getting active user sessions", ex);
                return 0;
            }
        }

        /// <summary>
        /// Gets user lockout count
        /// </summary>
        public async Task<int> GetUserLockoutsAsync(DateTime? since = null)
        {
            try
            {
                using var dbContext = await _dbContextFactory.CreateDbContextAsync();
                var query = dbContext.SecurityEventMetrics.Where(x => x.EventType == "user_lockout");
                
                if (since.HasValue)
                {
                    query = query.Where(x => x.CreatedAt >= since.Value);
                }

                return await query.CountAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError("MetricsService", "Error getting user lockouts", ex);
                return 0;
            }
        }

        /// <summary>
        /// Gets IP ban count
        /// </summary>
        public async Task<int> GetIpBansAsync(DateTime? since = null)
        {
            try
            {
                using var dbContext = await _dbContextFactory.CreateDbContextAsync();
                var query = dbContext.SecurityEventMetrics.Where(x => x.EventType == "ip_ban");
                
                if (since.HasValue)
                {
                    query = query.Where(x => x.CreatedAt >= since.Value);
                }

                return await query.CountAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError("MetricsService", "Error getting IP bans", ex);
                return 0;
            }
        }

        /// <summary>
        /// Generates sample data for testing (only in development)
        /// </summary>
        public async Task GenerateSampleDataAsync()
        {
            try
            {
                _logger.Log("MetricsService", "Generating sample metrics data for testing");
                
                var httpContext = _httpContextAccessor.HttpContext;
                var ipAddress = httpContext?.Connection?.RemoteIpAddress?.ToString() ?? "127.0.0.1";
                var userAgent = httpContext?.Request?.Headers["User-Agent"].ToString() ?? "Test-Agent";

                // Generuj vzorové login pokusy
                for (int i = 0; i < 15; i++)
                {
                    await RecordLoginAttemptAsync(true, null, ipAddress, userAgent, $"user{i % 3 + 1}");
                }
                
                for (int i = 0; i < 5; i++)
                {
                    await RecordLoginAttemptAsync(false, "invalid_credentials", ipAddress, userAgent, $"user{i % 2 + 1}");
                }
                
                for (int i = 0; i < 2; i++)
                {
                    await RecordLoginAttemptAsync(false, "invalid_totp", ipAddress, userAgent, "admin");
                }
                
                // Generuj bezpečnostní události
                await RecordSecurityEventAsync("user_lockout", "User locked due to multiple failed attempts", SecurityEventSeverity.Medium, ipAddress, "user1");
                await RecordSecurityEventAsync("ip_ban", "IP banned due to suspicious activity", SecurityEventSeverity.High, ipAddress);
                await RecordSecurityEventAsync("suspicious_activity", "Multiple failed login attempts from same IP", SecurityEventSeverity.Medium, ipAddress);
                await RecordSecurityEventAsync("multiple_failures", "Rapid succession of failed attempts", SecurityEventSeverity.Medium, ipAddress, "user2");
                await RecordSecurityEventAsync("rate_limit_exceeded", "Rate limit exceeded for IP address", SecurityEventSeverity.Low, ipAddress);
                
                // Nastav aktivní sessions
                await RecordActiveUserSessionsAsync(8);
                
                _logger.Log("MetricsService", "Sample metrics data generated successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError("MetricsService", "Error generating sample data", ex);
            }
        }

        /// <summary>
        /// Cleans up old metrics data based on retention policy
        /// </summary>
        /// <param name="retentionDays">Number of days to retain data</param>
        public async Task CleanupOldMetricsAsync(int retentionDays = 90)
        {
            try
            {
                var cutoffDate = DateTime.UtcNow.AddDays(-retentionDays);

                using var dbContext = await _dbContextFactory.CreateDbContextAsync();
                // Smaž staré login attempts
                var oldLoginAttempts = await dbContext.LoginAttemptMetrics
                    .Where(x => x.CreatedAt < cutoffDate)
                    .CountAsync();
                
                if (oldLoginAttempts > 0)
                {
                    await dbContext.LoginAttemptMetrics
                        .Where(x => x.CreatedAt < cutoffDate)
                        .ExecuteDeleteAsync();
                }

                // Smaž staré security events (krome critical)
                var oldSecurityEvents = await dbContext.SecurityEventMetrics
                    .Where(x => x.CreatedAt < cutoffDate && x.Severity != SecurityEventSeverity.Critical)
                    .CountAsync();
                
                if (oldSecurityEvents > 0)
                {
                    await dbContext.SecurityEventMetrics
                        .Where(x => x.CreatedAt < cutoffDate && x.Severity != SecurityEventSeverity.Critical)
                        .ExecuteDeleteAsync();
                }

                // Smaž staré session metrics (nech jen jeden záznam za den pro historii)
                var oldSessions = await dbContext.ActiveSessionMetrics
                    .Where(x => x.CreatedAt < cutoffDate)
                    .GroupBy(x => x.CreatedAt.Date)
                    .Where(g => g.Count() > 1)
                    .SelectMany(g => g.OrderByDescending(x => x.CreatedAt).Skip(1))
                    .CountAsync();

                if (oldSessions > 0)
                {
                    var sessionsToDelete = await dbContext.ActiveSessionMetrics
                        .Where(x => x.CreatedAt < cutoffDate)
                        .GroupBy(x => x.CreatedAt.Date)
                        .Where(g => g.Count() > 1)
                        .SelectMany(g => g.OrderByDescending(x => x.CreatedAt).Skip(1))
                        .ToListAsync();

                    dbContext.ActiveSessionMetrics.RemoveRange(sessionsToDelete);
                    await dbContext.SaveChangesAsync();
                }

                _logger.Log("MetricsService", $"Cleaned up old metrics: {oldLoginAttempts} login attempts, {oldSecurityEvents} security events, {oldSessions} session records");
            }
            catch (Exception ex)
            {
                _logger.LogError("MetricsService", "Error cleaning up old metrics", ex);
            }
        }

        /// <summary>
        /// Gets metrics statistics for a specific time period
        /// </summary>
        public async Task<object> GetMetricsStatsAsync(DateTime since, DateTime until)
        {
            try
            {
                using var dbContext = await _dbContextFactory.CreateDbContextAsync();
                var loginStats = await dbContext.LoginAttemptMetrics
                    .Where(x => x.CreatedAt >= since && x.CreatedAt <= until)
                    .GroupBy(x => x.Success)
                    .Select(g => new { Success = g.Key, Count = g.Count() })
                    .ToListAsync();

                var securityEvents = await dbContext.SecurityEventMetrics
                    .Where(x => x.CreatedAt >= since && x.CreatedAt <= until)
                    .GroupBy(x => x.EventType)
                    .Select(g => new { EventType = g.Key, Count = g.Count() })
                    .ToListAsync();

                var dailyLogins = await dbContext.LoginAttemptMetrics
                    .Where(x => x.CreatedAt >= since && x.CreatedAt <= until)
                    .GroupBy(x => x.CreatedAt.Date)
                    .Select(g => new { 
                        Date = g.Key, 
                        Successful = g.Count(x => x.Success), 
                        Failed = g.Count(x => !x.Success) 
                    })
                    .OrderBy(x => x.Date)
                    .ToListAsync();

                return new
                {
                    period = new { since, until },
                    loginStats = loginStats.ToDictionary(x => x.Success, x => x.Count),
                    securityEvents = securityEvents.ToDictionary(x => x.EventType, x => x.Count),
                    dailyLogins = dailyLogins,
                    totalDays = (until - since).Days
                };
            }
            catch (Exception ex)
            {
                _logger.LogError("MetricsService", "Error getting metrics stats", ex);
                throw;
            }
        }

        #region Backward Compatibility Methods (for Prometheus and existing code)

        public void RecordLoginAttempt(bool success, string? reason = null)
        {
            // Pro backward compatibility - spustí async metodu synchronně
            Task.Run(async () => await RecordLoginAttemptAsync(success, reason));
        }

        public void RecordUserLockout()
        {
            Task.Run(async () => await RecordSecurityEventAsync("user_lockout", "User account locked", SecurityEventSeverity.Medium));
        }

        public void RecordIpBan()
        {
            Task.Run(async () => await RecordSecurityEventAsync("ip_ban", "IP address banned", SecurityEventSeverity.High));
        }

        public void RecordActiveUserSessions(int count)
        {
            Task.Run(async () => await RecordActiveUserSessionsAsync(count));
        }

        public void RecordSecurityEvent(string eventType)
        {
            Task.Run(async () => await RecordSecurityEventAsync(eventType));
        }

        public double GetSuccessfulLoginAttempts()
        {
            try
            {
                var result = GetLoginAttemptsStatsAsync().GetAwaiter().GetResult();
                return result.successful;
            }
            catch
            {
                return 0;
            }
        }

        public double GetFailedLoginAttempts()
        {
            try
            {
                var result = GetLoginAttemptsStatsAsync().GetAwaiter().GetResult();
                return result.failed;
            }
            catch
            {
                return 0;
            }
        }

        public double GetUserLockouts()
        {
            try
            {
                return GetUserLockoutsAsync().GetAwaiter().GetResult();
            }
            catch
            {
                return 0;
            }
        }

        public double GetIpBans()
        {
            try
            {
                return GetIpBansAsync().GetAwaiter().GetResult();
            }
            catch
            {
                return 0;
            }
        }

        public double GetActiveUserSessions()
        {
            try
            {
                return GetActiveUserSessionsAsync().GetAwaiter().GetResult();
            }
            catch
            {
                return 0;
            }
        }

        public Dictionary<string, double> GetSecurityEventsByType()
        {
            try
            {
                var result = GetSecurityEventsByTypeAsync().GetAwaiter().GetResult();
                return result.ToDictionary(kvp => kvp.Key, kvp => (double)kvp.Value);
            }
            catch
            {
                return new Dictionary<string, double>();
            }
        }

        public void GenerateSampleData()
        {
            Task.Run(async () => await GenerateSampleDataAsync());
        }

        #endregion
    }
}
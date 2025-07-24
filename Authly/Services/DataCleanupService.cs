using Microsoft.Extensions.Options;

namespace Authly.Services
{
    /// <summary>
    /// Configuration options for database cleanup
    /// </summary>
    public class DataCleanupOptions
    {
        public const string SectionName = "DatabaseCleanup";

        /// <summary>
        /// Enable automatic database cleanup
        /// </summary>
        public bool Enabled { get; set; } = true;

        /// <summary>
        /// Cleanup interval in hours (default: 4 hours)
        /// </summary>
        public int CleanupIntervalHours { get; set; } = 4;

        /// <summary>
        /// Keep IP login attempts for X days (default: 30 days)
        /// </summary>
        public int KeepIpAttemptsForDays { get; set; } = 30;

        /// <summary>
        /// Keep OAuth authorization codes for X hours after expiration (default: 24 hours)
        /// </summary>
        public int KeepExpiredAuthCodesForHours { get; set; } = 24;

        /// <summary>
        /// Keep revoked OAuth tokens for X days (default: 7 days)
        /// </summary>
        public int KeepRevokedTokensForDays { get; set; } = 7;

        /// <summary>
        /// Log cleanup statistics
        /// </summary>
        public bool LogCleanupStats { get; set; } = true;
    }

    /// <summary>
    /// Background service for comprehensive database cleanup
    /// Removes expired and old records to prevent database growth
    /// </summary>
    public class DataCleanupService : BackgroundService
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly IApplicationLogger _logger;
        private readonly DataCleanupOptions _options;
        private readonly TimeSpan _cleanupInterval;

        public DataCleanupService(
            IServiceProvider serviceProvider,
            IApplicationLogger logger,
            IOptions<DataCleanupOptions> options)
        {
            _serviceProvider = serviceProvider;
            _logger = logger;
            _options = options.Value;
            _cleanupInterval = TimeSpan.FromHours(_options.CleanupIntervalHours);
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            if (!_options.Enabled)
            {
                _logger.Log("DatabaseCleanupService", "Database cleanup is disabled");
                return;
            }

            _logger.LogInfo("DatabaseCleanupService", $"Database Cleanup Service started (interval: {_options.CleanupIntervalHours}h)");

            // Wait 5 minutes after startup before first cleanup
            await Task.Delay(TimeSpan.FromMinutes(5), stoppingToken);

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await PerformCleanupAsync(stoppingToken);
                }
                catch (Exception ex)
                {
                    _logger.LogError("DatabaseCleanupService", "Error occurred during database cleanup", ex);
                }

                // Wait for the next cleanup interval
                try
                {
                    await Task.Delay(_cleanupInterval, stoppingToken);
                }
                catch (OperationCanceledException)
                {
                    // Expected when service is stopping
                    break;
                }
            }

            _logger.LogInfo("DatabaseCleanupService", "Database Cleanup Service stopped");
        }

        private async Task PerformCleanupAsync(CancellationToken stoppingToken)
        {
            var startTime = DateTime.UtcNow;
            var totalCleaned = 0;

            _logger.Log("DatabaseCleanupService", "Starting database cleanup");

            using var scope = _serviceProvider.CreateScope();
            var services = scope.ServiceProvider;

            try
            {
                // Cleanup OAuth tokens
                totalCleaned += await CleanupOAuthTokensAsync(services, stoppingToken);

                // Cleanup regular tokens
                totalCleaned += await CleanupTokensAsync(services, stoppingToken);

                // Cleanup IP attempts
                totalCleaned += await CleanupIpAttemptsAsync(services, stoppingToken);

                // Cleanup session tracking (if applicable)
                await CleanupSessionsAsync(services, stoppingToken);

                var duration = DateTime.UtcNow - startTime;

                if (_options.LogCleanupStats)
                {
                    _logger.Log("DatabaseCleanupService",
                        $"Cleanup completed: {totalCleaned} records removed in {duration.TotalSeconds:F1}s");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError("DatabaseCleanupService", "Error during cleanup operations", ex);
            }
        }

        private async Task<int> CleanupOAuthTokensAsync(IServiceProvider services, CancellationToken stoppingToken)
        {
            try
            {
                var oauthService = services.GetService<IOAuthAuthorizationService>();
                if (oauthService == null) return 0;

                await oauthService.CleanupExpiredTokensAsync();

                // For database implementation, get more detailed cleanup
                if (oauthService is DatabaseOAuthAuthorizationService dbOAuthService)
                {
                    return await PerformAdvancedOAuthCleanupAsync(services, stoppingToken);
                }

                return 0; // JSON implementation doesn't return count
            }
            catch (Exception ex)
            {
                _logger.LogError("DatabaseCleanupService", "Error cleaning up OAuth tokens", ex);
                return 0;
            }
        }

        private async Task<int> PerformAdvancedOAuthCleanupAsync(IServiceProvider services, CancellationToken stoppingToken)
        {
            try
            {
                var context = services.GetService<Data.AuthlyDbContext>();
                if (context == null) return 0;

                var totalCleaned = 0;
                var now = DateTime.UtcNow;

                // Remove very old expired authorization codes
                var oldAuthCodesCutoff = now.AddHours(-_options.KeepExpiredAuthCodesForHours);
                var oldAuthCodes = context.OAuthAuthorizationCodes
                    .Where(c => c.ExpiresUtc < oldAuthCodesCutoff || c.IsUsed)
                    .Take(1000); // Process in batches

                var authCodesCount = oldAuthCodes.Count();
                if (authCodesCount > 0)
                {
                    context.OAuthAuthorizationCodes.RemoveRange(oldAuthCodes);
                    totalCleaned += authCodesCount;
                }

                // Remove old revoked tokens
                var revokedTokensCutoff = now.AddDays(-_options.KeepRevokedTokensForDays);

                var oldRevokedAccessTokens = context.OAuthAccessTokens
                    .Where(t => t.IsRevoked && t.CreatedUtc < revokedTokensCutoff)
                    .Take(1000);

                var accessTokensCount = oldRevokedAccessTokens.Count();
                if (accessTokensCount > 0)
                {
                    context.OAuthAccessTokens.RemoveRange(oldRevokedAccessTokens);
                    totalCleaned += accessTokensCount;
                }

                var oldRevokedRefreshTokens = context.OAuthRefreshTokens
                    .Where(t => t.IsRevoked && t.CreatedUtc < revokedTokensCutoff)
                    .Take(1000);

                var refreshTokensCount = oldRevokedRefreshTokens.Count();
                if (refreshTokensCount > 0)
                {
                    context.OAuthRefreshTokens.RemoveRange(oldRevokedRefreshTokens);
                    totalCleaned += refreshTokensCount;
                }

                if (totalCleaned > 0)
                {
                    _ = await context.SaveChangesAsync(stoppingToken);

                    if (_options.LogCleanupStats)
                    {
                        _logger.Log("DatabaseCleanupService",
                            $"OAuth cleanup: {authCodesCount} auth codes, {accessTokensCount} access tokens, {refreshTokensCount} refresh tokens");
                    }
                }

                return totalCleaned;
            }
            catch (Exception ex)
            {
                _logger.LogError("DatabaseCleanupService", "Error in advanced OAuth cleanup", ex);
                return 0;
            }
        }

        private async Task<int> CleanupTokensAsync(IServiceProvider services, CancellationToken stoppingToken)
        {
            try
            {
                var tokenService = services.GetService<ITokenService>();
                if (tokenService is DatabaseTokenService dbTokenService)
                {
                    return await dbTokenService.CleanupExpiredTokensAsync();
                }

                return 0;
            }
            catch (Exception ex)
            {
                _logger.LogError("DatabaseCleanupService", "Error cleaning up tokens", ex);
                return 0;
            }
        }

        private async Task<int> CleanupIpAttemptsAsync(IServiceProvider services, CancellationToken stoppingToken)
        {
            try
            {
                var securityService = services.GetService<ISecurityService>();
                if (securityService is DatabaseSecurityService dbSecurityService)
                {
                    return await PerformIpAttemptsCleanupAsync(services, stoppingToken);
                }

                return 0;
            }
            catch (Exception ex)
            {
                _logger.LogError("DatabaseCleanupService", "Error cleaning up IP attempts", ex);
                return 0;
            }
        }

        private async Task<int> PerformIpAttemptsCleanupAsync(IServiceProvider services, CancellationToken stoppingToken)
        {
            try
            {
                var context = services.GetService<Data.AuthlyDbContext>();
                if (context == null) return 0;

                var cutoffDate = DateTime.UtcNow.AddDays(-_options.KeepIpAttemptsForDays);

                // Remove old IP attempts that are not currently banned
                var oldIpAttempts = context.IpLoginAttempts
                    .Where(ip => ip.FirstAttemptUtc < cutoffDate &&
                                (!ip.IsBanned || (ip.BanEndUtc.HasValue && ip.BanEndUtc < DateTime.UtcNow)))
                    .Take(1000); // Process in batches

                var count = oldIpAttempts.Count();
                if (count > 0)
                {
                    context.IpLoginAttempts.RemoveRange(oldIpAttempts);
                    _ = await context.SaveChangesAsync(stoppingToken);

                    if (_options.LogCleanupStats)
                    {
                        _logger.Log("DatabaseCleanupService", $"IP attempts cleanup: {count} old records removed");
                    }
                }

                return count;
            }
            catch (Exception ex)
            {
                _logger.LogError("DatabaseCleanupService", "Error in IP attempts cleanup", ex);
                return 0;
            }
        }

        private async Task CleanupSessionsAsync(IServiceProvider services, CancellationToken stoppingToken)
        {
            try
            {
                var sessionService = services.GetService<ISessionTrackingService>();
                sessionService?.CleanupExpiredSessions();

                await Task.CompletedTask;
            }
            catch (Exception ex)
            {
                _logger.LogError("DatabaseCleanupService", "Error cleaning up sessions", ex);
            }
        }
    }
}
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Authly.Services
{
    /// <summary>
    /// Background service for OAuth token cleanup
    /// </summary>
    public class OAuthCleanupService : BackgroundService
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly IApplicationLogger _logger;
        private readonly TimeSpan _cleanupInterval = TimeSpan.FromHours(1); // Cleanup every hour

        public OAuthCleanupService(IServiceProvider serviceProvider, IApplicationLogger logger)
        {
            _serviceProvider = serviceProvider;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInfo("OAuthCleanupService", "OAuth Cleanup Service started");

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    using var scope = _serviceProvider.CreateScope();
                    var oauthService = scope.ServiceProvider.GetRequiredService<IOAuthAuthorizationService>();
                    
                    await oauthService.CleanupExpiredTokensAsync();
                }
                catch (Exception ex)
                {
                    _logger.LogError("OAuthCleanupService", "Error occurred during OAuth token cleanup", ex);
                }

                // Wait for the next cleanup interval
                await Task.Delay(_cleanupInterval, stoppingToken);
            }

            _logger.LogInfo("OAuthCleanupService", "OAuth Cleanup Service stopped");
        }
    }
}
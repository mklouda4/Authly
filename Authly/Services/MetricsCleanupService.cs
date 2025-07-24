using Microsoft.Extensions.Options;
using Authly.Configuration;

namespace Authly.Services
{
    /// <summary>
    /// Background service for cleaning up old metrics data
    /// </summary>
    public class MetricsCleanupService : BackgroundService
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly IApplicationLogger _logger;
        private readonly ApplicationOptions _options;

        public MetricsCleanupService(
            IServiceProvider serviceProvider,
            IApplicationLogger logger,
            IOptions<ApplicationOptions> options)
        {
            _serviceProvider = serviceProvider;
            _logger = logger;
            _options = options.Value;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.Log("MetricsCleanupService", "Metrics cleanup service started");

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    // ?isti jednou za den
                    await Task.Delay(TimeSpan.FromHours(24), stoppingToken);

                    // Použij scope pro získání scoped services
                    using var scope = _serviceProvider.CreateScope();
                    var metricsService = scope.ServiceProvider.GetRequiredService<IMetricsService>();

                    _logger.Log("MetricsCleanupService", "Starting metrics cleanup");

                    // Zachovej data za posledních 90 dní (m?žeme ud?lat konfigurovatelné)
                    await metricsService.CleanupOldMetricsAsync(90);

                    _logger.Log("MetricsCleanupService", "Metrics cleanup completed");
                }
                catch (OperationCanceledException)
                {
                    // Expected when cancellation is requested
                    break;
                }
                catch (Exception ex)
                {
                    _logger.LogError("MetricsCleanupService", $"Error during metrics cleanup: {ex.Message}", ex);
                    
                    // Po?kej kratší dobu p?ed dalším pokusem p?i chyb?
                    try
                    {
                        await Task.Delay(TimeSpan.FromHours(1), stoppingToken);
                    }
                    catch (OperationCanceledException)
                    {
                        break;
                    }
                }
            }

            _logger.Log("MetricsCleanupService", "Metrics cleanup service stopped");
        }
    }
}
using Authly.Services;
using Authly.Models;

namespace Authly.Services
{
    /// <summary>
    /// Interface for metrics service that provides dashboard data
    /// </summary>
    public interface IMetricsDashboardService
    {
        /// <summary>
        /// Gets parsed metrics data for dashboard visualization
        /// </summary>
        /// <returns>Metrics data formatted for charts</returns>
        Task<object?> GetMetricsDashboardDataAsync();

        /// <summary>
        /// Indicates if metrics collection is enabled
        /// </summary>
        bool IsMetricsEnabled { get; }
    }

    /// <summary>
    /// Service for providing metrics dashboard data using database-backed IMetricsService
    /// </summary>
    public class MetricsDashboardService : IMetricsDashboardService
    {
        private readonly IMetricsService _metricsService;
        private readonly IApplicationLogger _logger;

        public MetricsDashboardService(
            IMetricsService metricsService,
            IApplicationLogger logger)
        {
            _metricsService = metricsService;
            _logger = logger;
        }

        /// <summary>
        /// Indicates if metrics collection is enabled
        /// </summary>
        public bool IsMetricsEnabled => _metricsService.IsEnabled;

        /// <summary>
        /// Gets parsed metrics data for dashboard visualization
        /// </summary>
        /// <returns>Metrics data formatted for charts</returns>
        public async Task<object?> GetMetricsDashboardDataAsync()
        {
            if (!IsMetricsEnabled)
            {
                _logger.LogWarning("MetricsDashboardService", "Metrics are not enabled");
                return null;
            }

            try
            {
                _logger.Log("MetricsDashboardService", "Fetching metrics from database");

                // Získáme data z databáze za posledních 30 dní pro p?ehled
                var since = DateTime.UtcNow.AddDays(-30);
                
                var (successful, failed, successRate) = await _metricsService.GetLoginAttemptsStatsAsync(since);
                var userLockouts = await _metricsService.GetUserLockoutsAsync(since);
                var ipBans = await _metricsService.GetIpBansAsync(since);
                var activeSessions = await _metricsService.GetActiveUserSessionsAsync();
                var securityEvents = await _metricsService.GetSecurityEventsByTypeAsync(since);

                var totalLogins = successful + failed;

                var parsedMetrics = new Dictionary<string, object>
                {
                    ["loginAttempts"] = new
                    {
                        successful = successful,
                        failed = failed,
                        total = totalLogins,
                        successRate = successRate
                    },
                    ["security"] = new
                    {
                        userLockouts = userLockouts,
                        ipBans = ipBans,
                        activeSessions = activeSessions
                    },
                    ["securityEvents"] = securityEvents,
                    ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                    ["period"] = new
                    {
                        since = since,
                        days = 30
                    }
                };

                _logger.Log("MetricsDashboardService", "Metrics fetched successfully from database");

                return parsedMetrics;
            }
            catch (Exception ex)
            {
                _logger.LogError("MetricsDashboardService", $"Error fetching metrics: {ex.Message}", ex);
                throw;
            }
        }
    }
}
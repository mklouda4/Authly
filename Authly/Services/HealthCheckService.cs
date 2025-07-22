using Authly.Authorization.UserStorage;
using Authly.Configuration;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;

namespace Authly.Services
{
    /// <summary>
    /// Custom health check for Authly application
    /// </summary>
    public class AuthlyHealthCheck(
        IUserStorage userStorage,
        IApplicationLogger logger,
        IMetricsService metricsService,
        IOptions<ApplicationOptions> appOptions) : IHealthCheck
    {
        private readonly ApplicationOptions _appOptions = appOptions.Value;

        public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
        {
            var healthData = new Dictionary<string, object>();

            try
            {
                // Check application basics
                healthData.Add("application_name", _appOptions.Name);
                healthData.Add("application_version", _appOptions.Version);
                healthData.Add("debug_logging", _appOptions.DebugLogging);
                healthData.Add("metrics_enabled", _appOptions.EnableMetrics);
                healthData.Add("timestamp", DateTime.UtcNow.ToString("O"));

                // Check user storage by trying to find a test user (this will test if storage is accessible)
                try
                {
                    _ = await userStorage.FindFirst();
                    healthData.Add("user_storage_accessible", true);
                }
                catch
                {
                    healthData.Add("user_storage_accessible", false);
                }

                // Check services
                healthData.Add("logger_enabled", logger.IsEnabled);
                healthData.Add("metrics_service_enabled", metricsService.IsEnabled);

                // Check file system access
                var dataDirectory = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", "data");
                healthData.Add("data_directory_exists", Directory.Exists(dataDirectory));
                healthData.Add("data_directory_writable", CheckDirectoryWritable(dataDirectory));

                // Memory usage
                var workingSet = GC.GetTotalMemory(false);
                healthData.Add("memory_usage_bytes", workingSet);
                healthData.Add("memory_usage_mb", Math.Round(workingSet / 1024.0 / 1024.0, 2));

                // Thread pool info
                ThreadPool.GetAvailableThreads(out int workerThreads, out int completionPortThreads);
                healthData.Add("available_worker_threads", workerThreads);
                healthData.Add("available_completion_port_threads", completionPortThreads);

                return HealthCheckResult.Healthy("Authly application is healthy", healthData);
            }
            catch (Exception ex)
            {
                healthData.Add("error_message", ex.Message);
                healthData.Add("error_type", ex.GetType().Name);

                logger.LogError("HealthCheck", $"Health check failed: {ex.Message}", ex);

                return HealthCheckResult.Unhealthy("Authly application health check failed", ex, healthData);
            }
        }

        private static bool CheckDirectoryWritable(string directoryPath)
        {
            try
            {
                if (!Directory.Exists(directoryPath))
                {
                    _ = Directory.CreateDirectory(directoryPath);
                }

                var testFile = Path.Combine(directoryPath, ".health-check-test");
                File.WriteAllText(testFile, "test");
                File.Delete(testFile);
                return true;
            }
            catch
            {
                return false;
            }
        }
    }

    /// <summary>
    /// Readiness health check - checks if application is ready to serve requests
    /// </summary>
    public class ReadinessHealthCheck(IUserStorage userStorage, IApplicationLogger logger) : IHealthCheck
    {
        public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
        {
            var healthData = new Dictionary<string, object>();

            try
            {
                // Check if we can access user storage by trying to find admin user
                var testUser = await userStorage.FindFirst();
                healthData.Add("user_storage_ready", true);
                healthData.Add("user_exists", testUser != null);

                // Check if essential services are ready
                healthData.Add("logger_ready", logger != null);
                healthData.Add("timestamp", DateTime.UtcNow.ToString("O"));

                return HealthCheckResult.Healthy("Application is ready to serve requests", healthData);
            }
            catch (Exception ex)
            {
                healthData.Add("error_message", ex.Message);
                healthData.Add("user_storage_ready", false);

                return HealthCheckResult.Unhealthy("Application is not ready to serve requests", ex, healthData);
            }
        }
    }

    /// <summary>
    /// Liveness health check - checks if application is alive
    /// </summary>
    public class LivenessHealthCheck : IHealthCheck
    {
        public Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
        {
            var healthData = new Dictionary<string, object>
            {
                { "timestamp", DateTime.UtcNow.ToString("O") },
                { "uptime_seconds", Environment.TickCount64 / 1000 },
                { "process_id", Environment.ProcessId },
                { "machine_name", Environment.MachineName }
            };

            return Task.FromResult(HealthCheckResult.Healthy("Application is alive", healthData));
        }
    }
}
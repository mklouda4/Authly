using Prometheus;
using Authly.Configuration;
using Microsoft.Extensions.Options;

namespace Authly.Services
{
    /// <summary>
    /// Interface for application metrics service
    /// </summary>
    public interface IMetricsService
    {
        /// <summary>
        /// Increment login attempts counter
        /// </summary>
        /// <param name="success">Whether the login was successful</param>
        /// <param name="reason">Reason for failure (if any)</param>
        void RecordLoginAttempt(bool success, string? reason = null);

        /// <summary>
        /// Increment user lockout counter
        /// </summary>
        void RecordUserLockout();

        /// <summary>
        /// Increment IP ban counter
        /// </summary>
        void RecordIpBan();

        /// <summary>
        /// Record active user sessions
        /// </summary>
        /// <param name="count">Number of active sessions</param>
        void RecordActiveUserSessions(int count);

        /// <summary>
        /// Record security event
        /// </summary>
        /// <param name="eventType">Type of security event</param>
        void RecordSecurityEvent(string eventType);

        /// <summary>
        /// Indicates if metrics are enabled
        /// </summary>
        bool IsEnabled { get; }
    }

    /// <summary>
    /// Prometheus metrics service for application monitoring
    /// </summary>
    public class MetricsService(IOptions<ApplicationOptions> options, IApplicationLogger logger) : IMetricsService
    {
        private readonly ApplicationOptions _options = options.Value;

        // Prometheus metrics
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

        /// <summary>
        /// Indicates if metrics collection is enabled
        /// </summary>
        public bool IsEnabled => _options.EnableMetrics;

        /// <summary>
        /// Records a login attempt with result and reason
        /// </summary>
        public void RecordLoginAttempt(bool success, string? reason = null)
        {
            if (!IsEnabled) return;

            try
            {
                var result = success ? "success" : "failure";
                var reasonLabel = reason ?? "unknown";
                
                _loginAttemptsCounter.WithLabels(result, reasonLabel).Inc();
                logger.LogDebug("MetricsService", $"Recorded login attempt: {result}, Reason: {reasonLabel}");
            }
            catch (Exception ex)
            {
                logger.LogError("MetricsService", "Error recording login attempt metric", ex);
            }
        }

        /// <summary>
        /// Records a user lockout event
        /// </summary>
        public void RecordUserLockout()
        {
            if (!IsEnabled) return;

            try
            {
                _userLockoutsCounter.Inc();
                logger.LogDebug("MetricsService", "Recorded user lockout");
            }
            catch (Exception ex)
            {
                logger.LogError("MetricsService", "Error recording user lockout metric", ex);
            }
        }

        /// <summary>
        /// Records an IP ban event
        /// </summary>
        public void RecordIpBan()
        {
            if (!IsEnabled) return;

            try
            {
                _ipBansCounter.Inc();
                logger.LogDebug("MetricsService", "Recorded IP ban");
            }
            catch (Exception ex)
            {
                logger.LogError("MetricsService", "Error recording IP ban metric", ex);
            }
        }

        /// <summary>
        /// Records the current number of active user sessions
        /// </summary>
        public void RecordActiveUserSessions(int count)
        {
            if (!IsEnabled) return;

            try
            {
                _activeUserSessionsGauge.Set(count);
                logger.LogDebug("MetricsService", $"Recorded active user sessions: {count}");
            }
            catch (Exception ex)
            {
                logger.LogError("MetricsService", "Error recording active user sessions metric", ex);
            }
        }

        /// <summary>
        /// Records a security-related event
        /// </summary>
        public void RecordSecurityEvent(string eventType)
        {
            if (!IsEnabled) return;

            try
            {
                _securityEventsCounter.WithLabels(eventType).Inc();
                logger.LogDebug("MetricsService", $"Recorded security event: {eventType}");
            }
            catch (Exception ex)
            {
                logger.LogError("MetricsService", "Error recording security event metric", ex);
            }
        }
    }
}
using System.ComponentModel.DataAnnotations;

namespace Authly.Models
{
    /// <summary>
    /// Database entity for storing login attempt metrics
    /// </summary>
    public class LoginAttemptMetric
    {
        /// <summary>
        /// Unique identifier for the login attempt
        /// </summary>
        [Key]
        public int Id { get; set; }

        /// <summary>
        /// Whether the login attempt was successful
        /// </summary>
        public bool Success { get; set; }

        /// <summary>
        /// Reason for failure (if any)
        /// </summary>
        public string? FailureReason { get; set; }

        /// <summary>
        /// IP address of the login attempt
        /// </summary>
        public string? IpAddress { get; set; }

        /// <summary>
        /// User agent string
        /// </summary>
        public string? UserAgent { get; set; }

        /// <summary>
        /// Username attempted (if available)
        /// </summary>
        public string? Username { get; set; }

        /// <summary>
        /// Timestamp when the login attempt occurred
        /// </summary>
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    }

    /// <summary>
    /// Database entity for storing security events
    /// </summary>
    public class SecurityEventMetric
    {
        /// <summary>
        /// Unique identifier for the security event
        /// </summary>
        [Key]
        public int Id { get; set; }

        /// <summary>
        /// Type of security event (e.g., "user_lockout", "ip_ban", "suspicious_activity")
        /// </summary>
        public string EventType { get; set; } = string.Empty;

        /// <summary>
        /// Additional details about the event
        /// </summary>
        public string? Details { get; set; }

        /// <summary>
        /// IP address associated with the event
        /// </summary>
        public string? IpAddress { get; set; }

        /// <summary>
        /// Username associated with the event (if any)
        /// </summary>
        public string? Username { get; set; }

        /// <summary>
        /// Severity level of the event
        /// </summary>
        public SecurityEventSeverity Severity { get; set; } = SecurityEventSeverity.Medium;

        /// <summary>
        /// Timestamp when the event occurred
        /// </summary>
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    }

    /// <summary>
    /// Database entity for storing active session metrics (snapshots)
    /// </summary>
    public class ActiveSessionMetric
    {
        /// <summary>
        /// Unique identifier for the session count snapshot
        /// </summary>
        [Key]
        public int Id { get; set; }

        /// <summary>
        /// Number of active sessions at the time of recording
        /// </summary>
        public int SessionCount { get; set; }

        /// <summary>
        /// Timestamp when the session count was recorded
        /// </summary>
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    }

    /// <summary>
    /// Severity levels for security events
    /// </summary>
    public enum SecurityEventSeverity
    {
        Low = 1,
        Medium = 2,
        High = 3,
        Critical = 4
    }
}
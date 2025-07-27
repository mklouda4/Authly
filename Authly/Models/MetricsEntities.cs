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
        /// Response time in milliseconds for the login operation
        /// </summary>
        public double? ResponseTimeMs { get; set; }

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
    /// Database entity for storing API performance metrics
    /// </summary>
    public class PerformanceMetric
    {
        /// <summary>
        /// Unique identifier for the performance metric
        /// </summary>
        [Key]
        public int Id { get; set; }

        /// <summary>
        /// Type of operation (e.g., "login", "logout", "oauth_authorize", "oauth_token", "api_call")
        /// </summary>
        public string OperationType { get; set; } = string.Empty;

        /// <summary>
        /// Specific endpoint or operation name
        /// </summary>
        public string? Endpoint { get; set; }

        /// <summary>
        /// HTTP method (GET, POST, etc.) for API calls
        /// </summary>
        public string? HttpMethod { get; set; }

        /// <summary>
        /// Response time in milliseconds
        /// </summary>
        public double ResponseTimeMs { get; set; }

        /// <summary>
        /// Whether the operation was successful
        /// </summary>
        public bool Success { get; set; }

        /// <summary>
        /// HTTP status code (for API calls)
        /// </summary>
        public int? StatusCode { get; set; }

        /// <summary>
        /// Request size in bytes (if applicable)
        /// </summary>
        public long? RequestSizeBytes { get; set; }

        /// <summary>
        /// Response size in bytes (if applicable)
        /// </summary>
        public long? ResponseSizeBytes { get; set; }

        /// <summary>
        /// User ID associated with the operation (if available)
        /// </summary>
        public string? UserId { get; set; }

        /// <summary>
        /// IP address of the client
        /// </summary>
        public string? IpAddress { get; set; }

        /// <summary>
        /// User agent string
        /// </summary>
        public string? UserAgent { get; set; }

        /// <summary>
        /// Timestamp when the operation occurred
        /// </summary>
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    }

    /// <summary>
    /// Database entity for storing system resource usage metrics
    /// </summary>
    public class ResourceUsageMetric
    {
        /// <summary>
        /// Unique identifier for the resource usage metric
        /// </summary>
        [Key]
        public int Id { get; set; }

        /// <summary>
        /// CPU usage percentage (0-100)
        /// </summary>
        public double CpuUsagePercent { get; set; }

        /// <summary>
        /// Memory usage in MB
        /// </summary>
        public double MemoryUsageMB { get; set; }

        /// <summary>
        /// Total available memory in MB
        /// </summary>
        public double TotalMemoryMB { get; set; }

        /// <summary>
        /// Memory usage percentage (0-100)
        /// </summary>
        public double MemoryUsagePercent => TotalMemoryMB > 0 ? (MemoryUsageMB / TotalMemoryMB) * 100 : 0;

        /// <summary>
        /// Number of active threads
        /// </summary>
        public int ActiveThreads { get; set; }

        /// <summary>
        /// Number of active database connections
        /// </summary>
        public int? ActiveDbConnections { get; set; }

        /// <summary>
        /// Timestamp when the resource usage was recorded
        /// </summary>
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    }

    /// <summary>
    /// Database entity for storing application uptime metrics
    /// </summary>
    public class UptimeMetric
    {
        /// <summary>
        /// Unique identifier for the uptime metric
        /// </summary>
        [Key]
        public int Id { get; set; }

        /// <summary>
        /// Whether the service was available during this period
        /// </summary>
        public bool IsAvailable { get; set; }

        /// <summary>
        /// Response time for health check in milliseconds (if applicable)
        /// </summary>
        public double? HealthCheckResponseTimeMs { get; set; }

        /// <summary>
        /// Details about availability status or downtime reason
        /// </summary>
        public string? Details { get; set; }

        /// <summary>
        /// Timestamp when the uptime was recorded
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
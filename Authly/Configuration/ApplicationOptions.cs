namespace Authly.Configuration
{
    /// <summary>
    /// Application configuration options for branding and behavior
    /// </summary>
    public class ApplicationOptions
    {
        /// <summary>
        /// Configuration section name
        /// </summary>
        public const string SectionName = "Application";
        
        /// <summary>
        /// Application display name
        /// </summary>
        public string Name { get; set; } = "Authly";

        /// <summary>
        /// Gets the configured domain
        /// </summary>
        public string Domain { get; set; }

        /// <summary>
        /// Gets the configured base URI
        /// </summary>
        public string BaseUrl { get; set; }

        /// <summary>
        /// Application version
        /// </summary>
        public string Version { get; set; } = "1.0.0";
        
        /// <summary>
        /// Enable debug logging for development/troubleshooting
        /// </summary>
        public bool DebugLogging { get; set; } = false;
        
        /// <summary>
        /// Enable Prometheus metrics endpoint
        /// </summary>
        public bool EnableMetrics { get; set; } = false;

        /// <summary>
        /// Enable user registration functionality
        /// </summary>
        public bool AllowRegistration { get; set; } = false;

        /// <summary>
        /// External authentication configuration
        /// </summary>
        public ExternalAuthOptions ExternalAuth { get; set; } = new();
    }

    /// <summary>
    /// External authentication configuration options
    /// </summary>
    public class ExternalAuthOptions
    {
        /// <summary>
        /// Enable Google authentication
        /// </summary>
        public bool EnableGoogle { get; set; } = false;
        
        /// <summary>
        /// Enable Facebook authentication
        /// </summary>
        public bool EnableFacebook { get; set; } = false;

        /// <summary>
        /// Enable Microsoft authentication
        /// </summary>
        public bool EnableMicrosoft { get; set; } = false;

        /// <summary>
        /// Enable GitHub authentication
        /// </summary>
        public bool EnableGitHub { get; set; } = false;
    }

    /// <summary>
    /// User lockout configuration options
    /// </summary>
    public class UserLockoutOptions
    {
        /// <summary>
        /// Enable user lockout functionality
        /// </summary>
        public bool Enabled { get; set; } = false;

        /// <summary>
        /// Maximum number of failed attempts before lockout
        /// </summary>
        public int MaxFailedAttempts { get; set; } = 5;

        /// <summary>
        /// Duration of user lockout in minutes
        /// </summary>
        public int LockoutDurationMinutes { get; set; } = 30;

        /// <summary>
        /// Use sliding window for failed attempts tracking
        /// </summary>
        public bool SlidingWindow { get; set; } = true;

        /// <summary>
        /// Time window in minutes for sliding window
        /// </summary>
        public int WindowMinutes { get; set; } = 15;
    }

    /// <summary>
    /// IP-based rate limiting configuration options
    /// </summary>
    public class IpRateLimitingOptions
    {
        /// <summary>
        /// Enable IP-based rate limiting functionality
        /// </summary>
        public bool Enabled { get; set; } = false;

        /// <summary>
        /// Maximum number of attempts per IP address
        /// </summary>
        public int MaxAttemptsPerIp { get; set; } = 10;

        /// <summary>
        /// Duration of IP ban in minutes
        /// </summary>
        public int BanDurationMinutes { get; set; } = 60;

        /// <summary>
        /// Use sliding window for IP attempts tracking
        /// </summary>
        public bool SlidingWindow { get; set; } = true;

        /// <summary>
        /// Time window in minutes for sliding window
        /// </summary>
        public int WindowMinutes { get; set; } = 15;
    }
}
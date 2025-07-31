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
}
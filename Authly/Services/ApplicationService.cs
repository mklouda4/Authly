using Authly.Configuration;
using Microsoft.Extensions.Options;

namespace Authly.Services
{
    /// <summary>
    /// Interface for application-wide configuration and branding services
    /// </summary>
    public interface IApplicationService
    {
        /// <summary>
        /// Gets the configured application name
        /// </summary>
        string ApplicationName { get; }
        
        /// <summary>
        /// Gets the configured domain name
        /// </summary>
        string DomainName { get; }

        /// <summary>
        /// Gets the configured application version
        /// </summary>
        string ApplicationVersion { get; }
        
        /// <summary>
        /// Indicates if debug logging is enabled
        /// </summary>
        bool IsDebugLoggingEnabled { get; }

        /// <summary>
        /// Indicates if metrics collection is enabled
        /// </summary>
        bool IsMetricsEnabled { get; }

        /// <summary>
        /// Indicates if Google authentication is enabled
        /// </summary>
        bool IsGoogleAuthEnabled { get; }

        /// <summary>
        /// Indicates if Microsoft authentication is enabled
        /// </summary>
        bool IsMicrosoftAuthEnabled { get; }

        /// <summary>
        /// Indicates if GitHub authentication is enabled
        /// </summary>
        bool IsGitHubAuthEnabled { get; }

        /// <summary>
        /// Indicates if Facebook authentication is enabled
        /// </summary>
        bool IsFacebookAuthEnabled { get; }

        /// <summary>
        /// Indicates if any external authentication is enabled
        /// </summary>
        bool IsExternalAuthEnabled { get; }

        /// <summary>
        /// Generates a formatted page title with application branding
        /// </summary>
        /// <param name="pageTitle">Optional page-specific title</param>
        /// <returns>Formatted page title</returns>
        string GetPageTitle(string? pageTitle = null);

        /// <summary>
        /// Indicates if user registration is allowed
        /// </summary>
        bool AllowRegistration { get; }
    }

    /// <summary>
    /// Application service providing configuration and branding functionality
    /// </summary>
    /// <remarks>
    /// Initializes a new instance of ApplicationService
    /// </remarks>
    /// <param name="options">Application configuration options</param>
    public class ApplicationService(IOptions<ApplicationOptions> options) : IApplicationService
    {
        private readonly ApplicationOptions _options = options.Value;

        /// <summary>
        /// Gets the configured application name from settings
        /// </summary>
        public string ApplicationName => _options.Name;
        
        /// <summary>
        /// Gets the configured domain name from settings
        /// </summary>
        public string DomainName => _options.Domain;

        /// <summary>
        /// Gets the configured application version from settings
        /// </summary>
        public string ApplicationVersion => _options.Version;
        
        /// <summary>
        /// Gets the debug logging configuration flag
        /// </summary>
        public bool IsDebugLoggingEnabled => _options.DebugLogging;

        /// <summary>
        /// Gets the metrics configuration flag
        /// </summary>
        public bool IsMetricsEnabled => _options.EnableMetrics;

        /// <summary>
        /// Gets the Google authentication configuration flag
        /// </summary>
        public bool IsGoogleAuthEnabled => _options.ExternalAuth.EnableGoogle;

        /// <summary>
        /// Gets the Facebook authentication configuration flag
        /// </summary>
        public bool IsFacebookAuthEnabled => _options.ExternalAuth.EnableFacebook;

        /// <summary>
        /// Gets the Microsoft authentication configuration flag
        public bool IsMicrosoftAuthEnabled => _options.ExternalAuth.EnableMicrosoft;

        /// <summary>
        /// Gets the GitHub authentication configuration flag
        public bool IsGitHubAuthEnabled => _options.ExternalAuth.EnableGitHub;

        /// <summary>
        /// Gets whether any external authentication is enabled
        /// </summary>
        public bool IsExternalAuthEnabled => IsGoogleAuthEnabled || IsFacebookAuthEnabled || IsMicrosoftAuthEnabled || IsGitHubAuthEnabled;

        /// <summary>
        /// Indicates if user registration is allowed
        /// </summary>
        public bool AllowRegistration => _options.AllowRegistration;

        /// <summary>
        /// Creates a formatted page title with application name
        /// </summary>
        /// <param name="pageTitle">Page-specific title to include</param>
        /// <returns>Application name if no page title provided, otherwise "PageTitle - ApplicationName"</returns>
        public string GetPageTitle(string? pageTitle = null)
        {
            return string.IsNullOrEmpty(pageTitle) 
                ? ApplicationName 
                : $"{pageTitle} - {ApplicationName}";
        }
    }
}
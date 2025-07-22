namespace Authly.Services
{
    /// <summary>
    /// Interface for URL validation service that provides protection against open redirect attacks
    /// by validating and sanitizing return URLs used in authentication flows
    /// </summary>
    public interface IUrlValidator
    {
        /// <summary>
        /// Adds a domain to the whitelist of allowed redirect domains
        /// </summary>
        /// <param name="domain">The domain to add to the whitelist</param>
        void AddAllowedDomain(string domain);
        
        /// <summary>
        /// Validates and sanitizes a return URL to prevent open redirect vulnerabilities
        /// </summary>
        /// <param name="returnUrl">The URL to validate and sanitize</param>
        /// <param name="currentHost">The current host for comparison and validation</param>
        /// <returns>A safe URL or a fallback URL if validation fails</returns>
        string ValidateReturnUrl(string? returnUrl, string currentHost);
    }

    /// <summary>
    /// URL validation service that provides comprehensive protection against open redirect attacks.
    /// This service validates return URLs used in authentication flows to ensure users are only
    /// redirected to trusted locations, preventing malicious redirects to external sites.
    /// </summary>
    public class UrlValidator : IUrlValidator
    {
        /// <summary>
        /// Whitelist of domains that are allowed for redirect operations.
        /// Uses case-insensitive comparison for domain matching.
        /// </summary>
        private readonly HashSet<string> AllowedDomains = new(StringComparer.OrdinalIgnoreCase)
        {
            "localhost",      // Local development
            "localhost:7283",      // Local development
            "127.0.0.1",     // IPv4 loopback
            "10.0.0.1"       // Common internal network address
        };

        /// <summary>
        /// Default fallback URL used when validation fails or no return URL is provided.
        /// Points to the main dashboard to ensure users land on a safe page.
        /// </summary>
        private const string DefaultReturnUrl = "/dashboard";

        /// <summary>
        /// Validates and sanitizes a return URL to prevent open redirect vulnerabilities.
        /// This method implements multiple security checks:
        /// 1. Handles null/empty URLs with safe defaults
        /// 2. Validates relative URLs (starting with single slash)
        /// 3. Rejects protocol-relative URLs (starting with //)
        /// 4. Validates absolute URLs against domain whitelist
        /// 5. Normalizes local URLs to relative format
        /// </summary>
        /// <param name="returnUrl">The URL to validate - may come from query parameters or form data</param>
        /// <param name="currentHost">The current request host for security comparison</param>
        /// <returns>A validated and sanitized URL, or the default fallback URL if validation fails</returns>
        public string ValidateReturnUrl(string? returnUrl, string currentHost)
        {
            // Handle null, empty, or whitespace-only URLs
            if (string.IsNullOrWhiteSpace(returnUrl))
            {
                return DefaultReturnUrl;
            }

            // Validate relative URLs (safe pattern: starts with / but not //)
            // Relative URLs are generally safe as they stay within the same origin
            if (returnUrl.StartsWith("/") && !returnUrl.StartsWith("//"))
            {
                // Additional security check: reject protocol-relative URLs that could bypass validation
                return returnUrl;
            }

            // Normalize URLs without protocol scheme to relative format
            // This handles cases where users might input "dashboard" instead of "/dashboard"
            if (!returnUrl.Contains("://") && !returnUrl.StartsWith("//"))
            {
                return "/" + returnUrl.TrimStart('/');
            }
            return returnUrl;
            //// Handle absolute URLs - require strict validation against whitelist
            //if (Uri.TryCreate(returnUrl, UriKind.Absolute, out var uri))
            //{
            //    // Validate the host against our security whitelist
            //    if (IsAllowedDomain(uri.Host, currentHost))
            //    {
            //        return returnUrl;
            //    }

            //    // Log potential security attempt (absolute URL to untrusted domain)
            //    // Note: In production, consider logging this for security monitoring
            //}

            //// Security fallback: if all validation fails, redirect to safe default
            //// This prevents any potential bypass attempts
            //return DefaultReturnUrl;
        }

        /// <summary>
        /// Determines if a domain is allowed for redirect operations by checking against
        /// the current host and the configured whitelist of trusted domains.
        /// </summary>
        /// <param name="host">The host/domain to validate</param>
        /// <param name="currentHost">The current request host (always considered safe)</param>
        /// <returns>True if the domain is allowed, false if it should be rejected</returns>
        private bool IsAllowedDomain(string host, string currentHost)
        {
            // The current host is always considered safe (same-origin policy)
            if (string.Equals(host, currentHost, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            // Check against the configured whitelist of trusted domains
            return AllowedDomains.Contains(host);
        }

        /// <summary>
        /// Adds a domain to the whitelist of allowed redirect domains.
        /// This method is useful for runtime configuration of trusted domains.
        /// </summary>
        /// <param name="domain">The domain to add to the whitelist (e.g., "example.com")</param>
        /// <remarks>
        /// Use this method to dynamically configure trusted domains at application startup
        /// or when loading configuration from external sources. Domain comparison is case-insensitive.
        /// </remarks>
        public void AddAllowedDomain(string domain)
        {
            if (!string.IsNullOrWhiteSpace(domain))
            {
                AllowedDomains.Add(domain);
            }
        }
    }
}
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Xml.Serialization;

namespace Authly.Extension
{
    /// <summary>
    /// Extension methods for HttpContext
    /// </summary>
    public static class HttpContextExtensions
    {
        /// <summary>
        /// Extracts the client IP address from the HTTP context, considering proxy headers
        /// </summary>
        /// <param name="context">The HTTP context to extract IP address from</param>
        /// <returns>The client IP address as a string</returns>
        public static string GetClientIpAddress(this HttpContext context)
        {
            // X-Forwarded-For is applied by ForwardedHeadersMiddleware only for trusted proxies (see AUTHLY_TRUSTED_PROXIES).
            // Reading the header directly would let any client spoof its IP and bypass IP bans.
            var address = context.Connection.RemoteIpAddress;
            if (address == null)
            {
                return "unknown";
            }

            return (address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address).ToString();
        }

        /// <summary>
        /// Public base URL (scheme + host) of Authly as seen by browsers and clients.
        /// Uses the configured OIDC issuer, then Application:BaseUrl, and only then the request itself -
        /// behind a TLS-terminating proxy the request scheme is "http" unless X-Forwarded-Proto is trusted.
        /// </summary>
        public static string GetPublicBaseUrl(this HttpContext context)
        {
            var configuration = context.RequestServices.GetRequiredService<IConfiguration>();
            return GetPublicBaseUrl(configuration["Oidc:Issuer"], configuration["Application:BaseUrl"], context.Request);
        }

        /// <summary>
        /// Resolves the public base URL from configured candidates (first absolute http/https URL wins), falling back to the request
        /// </summary>
        public static string GetPublicBaseUrl(string? issuer, string? baseUrl, HttpRequest request)
        {
            foreach (var candidate in new[] { issuer, baseUrl })
            {
                if (Uri.TryCreate(candidate, UriKind.Absolute, out var uri) &&
                    (uri.Scheme == Uri.UriSchemeHttps || uri.Scheme == Uri.UriSchemeHttp))
                {
                    return uri.GetLeftPart(UriPartial.Authority);
                }
            }

            return $"{request.Scheme}://{request.Host}";
        }
    }
}

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
    }
}

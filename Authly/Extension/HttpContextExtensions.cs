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
            // Check for forwarded IP first (in case of proxy/load balancer)
            var forwardedFor = context.Request.Headers["X-Forwarded-For"].FirstOrDefault();
            if (!string.IsNullOrEmpty(forwardedFor))
            {
                return forwardedFor.Split(',')[0].Trim();
            }

            // Check for real IP header
            var realIp = context.Request.Headers["X-Real-IP"].FirstOrDefault();
            if (!string.IsNullOrEmpty(realIp))
            {
                return realIp;
            }

            // Fall back to connection remote IP
            return context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        }
    }
}

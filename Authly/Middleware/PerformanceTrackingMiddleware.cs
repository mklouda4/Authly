using Authly.Services;
using Authly.Models;
using Authly.Configuration;
using Microsoft.Extensions.Options;
using System.Diagnostics;

namespace Authly.Middleware
{
    /// <summary>
    /// Middleware for tracking performance metrics of authentication operations and monitoring unauthorized access
    /// </summary>
    public class PerformanceTrackingMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly IApplicationLogger _logger;
        private readonly IpRateLimitingOptions _ipRateLimitingOptions;

        public PerformanceTrackingMiddleware(
            RequestDelegate next, 
            IApplicationLogger logger,
            IOptions<IpRateLimitingOptions> ipRateLimitingOptions)
        {
            _next = next;
            _logger = logger;
            _ipRateLimitingOptions = ipRateLimitingOptions.Value;
        }

        public async Task InvokeAsync(HttpContext context, IMetricsService metricsService, ISecurityService securityService)
        {
            var stopwatch = Stopwatch.StartNew();
            var path = context.Request.Path.Value?.ToLowerInvariant() ?? "";
            var method = context.Request.Method;
            var operationType = DetermineOperationType(path, method);
            var ipAddress = GetIpAddress(context);
            var isAuthenticated = context.User?.Identity?.IsAuthenticated == true;
            
            // Only track specific authentication-related operations
            if (operationType == null)
            {
                await _next(context);
                return;
            }

            var originalBodyStream = context.Response.Body;
            var requestSize = context.Request.ContentLength ?? 0;
            long responseSize = 0;
            int statusCode = 200;
            bool success = true;

            try
            {
                // Wrap response stream to capture response size
                using var responseBody = new MemoryStream();
                context.Response.Body = responseBody;

                await _next(context);

                stopwatch.Stop();
                statusCode = context.Response.StatusCode;
                success = statusCode >= 200 && statusCode < 400;
                responseSize = responseBody.Length;

                // Copy the contents of the new memory stream to the original stream
                responseBody.Seek(0, SeekOrigin.Begin);
                await responseBody.CopyToAsync(originalBodyStream);
            }
            catch (Exception)
            {
                stopwatch.Stop();
                success = false;
                statusCode = context.Response.StatusCode != 200 ? context.Response.StatusCode : 500;
                throw;
            }
            finally
            {
                context.Response.Body = originalBodyStream;

                // Check for unauthorized access and potential IP ban
                await CheckUnauthorizedAccessAsync(
                    context, 
                    operationType, 
                    statusCode, 
                    isAuthenticated, 
                    ipAddress, 
                    metricsService, 
                    securityService);

                // Record performance metric asynchronously
                _ = Task.Run(async () =>
                {
                    try
                    {
                        await metricsService.RecordPerformanceMetricAsync(
                            operationType,
                            path,
                            method,
                            stopwatch.Elapsed.TotalMilliseconds,
                            success,
                            statusCode,
                            requestSize,
                            responseSize,
                            GetUserId(context),
                            ipAddress,
                            GetUserAgent(context)
                        );
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError("PerformanceTrackingMiddleware", $"Failed to record performance metric for {operationType} {path}", ex);
                    }
                });
            }
        }

        /// <summary>
        /// Checks for unauthorized access patterns and handles potential IP banning
        /// </summary>
        private async Task CheckUnauthorizedAccessAsync(
            HttpContext context,
            string operationType,
            int statusCode,
            bool isAuthenticated,
            string? ipAddress,
            IMetricsService metricsService,
            ISecurityService securityService)
        {
            if (!_ipRateLimitingOptions.Enabled || string.IsNullOrEmpty(ipAddress))
                return;

            try
            {
                var path = context.Request.Path.Value?.ToLowerInvariant() ?? "";
                var isRedirectToLogin = IsRedirectToLogin(statusCode, context);
                
                if (operationType == "login" && isRedirectToLogin)
                {
                    return;
                }
                if (operationType == "logout")
                {
                    return;
                }
                if ((operationType == "dashboard" || operationType == "dashboard_access") && statusCode == 200)
                {
                    return;
                }

                var isUnauthorizedAccess = !isAuthenticated && (
                    isRedirectToLogin || 
                    statusCode == 401 || 
                    statusCode == 403 ||
                    (operationType != "login" && RequiresAuthentication(path))
                );
                var isAuthorizedAccess = !isAuthenticated && statusCode == 200;

                if (isUnauthorizedAccess)
                {
                    var shouldBan = await securityService.RecordUnauthorizedAccessAsync(ipAddress, path, statusCode, operationType);
                    
                    if (shouldBan)
                    {
                        // Use SecurityService to ban the IP
                        var banResult = securityService.ManualBanIpAddress(ipAddress);
                        
                        if (banResult)
                        {
                            _logger.LogWarning("PerformanceTrackingMiddleware", $"IP {ipAddress} has been automatically banned for excessive unauthorized access attempts. " +
                                $"Path: {path}, StatusCode: {statusCode}, OperationType: {operationType}");
                            // Record security event
                            await metricsService.RecordSecurityEventAsync(
                                "automatic_ip_ban",
                                $"IP automatically banned for excessive unauthorized access attempts. Last attempt: {operationType} -> {statusCode}",
                                SecurityEventSeverity.High,
                                ipAddress);
                        }
                    }
                }
                else if (isAuthenticated && operationType == "login")
                {
                    // Note: Unauthorized access tracking is cleared in SecurityService.UnbanIpAddress()
                    // when IP is manually unbanned, not on successful authentication to prevent bypass
                    _logger.LogDebug("PerformanceTrackingMiddleware", $"User successfully authenticated from IP {ipAddress}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError("PerformanceTrackingMiddleware", $"Error checking unauthorized access for IP {ipAddress}", ex);
            }
        }

        /// <summary>
        /// Determines if the response is a redirect to login
        /// </summary>
        private static bool IsRedirectToLogin(int statusCode, HttpContext context)
        {
            if (statusCode == 302 || statusCode == 301)
            {
                var location = context.Response.Headers["Location"].FirstOrDefault();
                return !string.IsNullOrEmpty(location) && 
                       (location.Contains("/login", StringComparison.OrdinalIgnoreCase) ||
                        location.Contains("/account/login", StringComparison.OrdinalIgnoreCase));
            }
            return false;
        }

        /// <summary>
        /// Determines if the path requires authentication
        /// </summary>
        private static bool RequiresAuthentication(string path)
        {
            // Protected paths that typically require authentication
            var protectedPaths = new[]
            {
                "/dashboard",
                "/admin",
                "/profile",
                "/settings",
                "/oauth/authorize",
                "/oauth/userinfo",
                "/api/"
            };

            return protectedPaths.Any(protectedPath => 
                path.StartsWith(protectedPath, StringComparison.OrdinalIgnoreCase));
        }

        private static string? DetermineOperationType(string path, string method)
        {
            return path switch
            {
                var p when p.Contains("/login") => "login",
                var p when p.Contains("/logout") => "logout",
                var p when p.Contains("/oauth/authorize") => "oauth_authorize",
                var p when p.Contains("/oauth/token") => "oauth_token",
                var p when p.Contains("/oauth/userinfo") => "oauth_userinfo",
                var p when p.Contains("/oauth/revoke") => "oauth_revoke",
                var p when p.StartsWith("/api/") => "api_call",
                var p when p.Contains("/dashboard") => "dashboard_access",
                var p when p.Contains("/admin") => "admin_access",
                var p when p.Contains("/profile") => "profile_access",
                _ => null // Don't track other operations
            };
        }

        private static string? GetUserId(HttpContext context)
        {
            return context.User?.Identity?.IsAuthenticated == true 
                ? context.User.FindFirst("sub")?.Value ?? context.User.FindFirst("id")?.Value
                : null;
        }

        private static string? GetIpAddress(HttpContext context)
            => context.Connection.RemoteIpAddress?.ToString();

        private static string? GetUserAgent(HttpContext context) 
            => context.Request.Headers["User-Agent"].FirstOrDefault();
    }

    /// <summary>
    /// Extension methods for registering the performance tracking middleware
    /// </summary>
    public static class PerformanceTrackingMiddlewareExtensions
    {
        public static IApplicationBuilder UsePerformanceTracking(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<PerformanceTrackingMiddleware>();
        }
    }
}
using Authly.Services;
using Authly.Models;
using System.Diagnostics;

namespace Authly.Middleware
{
    /// <summary>
    /// Middleware for tracking performance metrics of authentication operations
    /// </summary>
    public class PerformanceTrackingMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<PerformanceTrackingMiddleware> _logger;

        public PerformanceTrackingMiddleware(RequestDelegate next, ILogger<PerformanceTrackingMiddleware> logger)
        {
            _next = next;
            _logger = logger;
        }

        public async Task InvokeAsync(HttpContext context, IMetricsService metricsService)
        {
            var stopwatch = Stopwatch.StartNew();
            var path = context.Request.Path.Value?.ToLowerInvariant() ?? "";
            var method = context.Request.Method;
            var operationType = DetermineOperationType(path, method);
            
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
                            GetIpAddress(context),
                            GetUserAgent(context)
                        );
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Failed to record performance metric for {OperationType} {Path}", operationType, path);
                    }
                });
            }
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
        {
            return context.Connection.RemoteIpAddress?.ToString();
        }

        private static string? GetUserAgent(HttpContext context)
        {
            return context.Request.Headers["User-Agent"].FirstOrDefault();
        }
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
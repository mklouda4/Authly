using Authly.Authorization;
using Authly.Authorization.UserStorage;
using Authly.Extension;
using Authly.Services;
using System.Security.Claims;
using System.Text.Json;

namespace Authly.Middleware
{
    /// <summary>
    /// Middleware for handling external authentication requests from reverse proxies (nginx/Caddy)
    /// Implements auth_request pattern for SSO functionality
    /// </summary>
    public class ExternalAuthMiddleware(RequestDelegate next)
    {
        /// <summary>
        /// Processes HTTP requests and handles external authentication endpoints
        /// </summary>
        /// <param name="context">HTTP context</param>
        /// <param name="userStorage">User storage service</param>
        /// <param name="appLogger">Application logger</param>
        /// <param name="securityService">Security service for failed attempts tracking</param>
        /// <param name="metricsService">Metrics service for monitoring</param>
        /// <param name="signInManager">Custom sign-in manager for authentication operations</param>
        public async Task InvokeAsync(
            HttpContext context,
            IConfiguration configuration,
            IUserStorage userStorage,
            IApplicationLogger appLogger,
            ISecurityService securityService,
            IMetricsService metricsService,
            CustomSignInManager signInManager)
        {
            // Handle external auth verification endpoint
            if (context.Request.Path == "/api/authz/forward-auth")
            {
                await HandleAuthVerificationAsync(context, configuration, userStorage, appLogger, securityService, signInManager);
                return;
            }

            // Handle external auth user info endpoint
            if (context.Request.Path == "/api/authz/user")
            {
                await HandleUserInfoAsync(context, appLogger, securityService, signInManager);
                return;
            }

            // Handle external auth login redirect endpoint
            if (context.Request.Path == "/api/authz/login")
            {
                await HandleLoginRedirectAsync(context, appLogger, securityService);
                return;
            }

            // Continue to next middleware for all other requests
            await next(context);
        }

        /// <summary>
        /// Handles authentication verification requests from reverse proxy
        /// Returns 200 if user is authenticated, 401/403 if not
        /// </summary>
        private async Task HandleAuthVerificationAsync(HttpContext context,
            IConfiguration configuration,
            IUserStorage userStorage,
            IApplicationLogger appLogger,
            ISecurityService securityService,
            CustomSignInManager signInManager)
        {
            try
            {
                var ipAddress = context.GetClientIpAddress();
                appLogger.Log("ExternalAuthMiddleware", $"Auth verification request from IP: {ipAddress}");

                // Check if IP is banned before proceeding
                if (securityService.IsIpBanned(ipAddress))
                {
                    var banEnd = securityService.GetIpBanEndTime(ipAddress);
                    appLogger.LogWarning("ExternalAuthMiddleware", $"IP {ipAddress} is banned until {banEnd} - denying auth verification");
                    context.Response.StatusCode = 403;
                    await context.Response.WriteAsync("IP address banned");
                    return;
                }

                var cookies = context.Request.Headers["Cookie"].ToString();
                appLogger.Log("ExternalAuthMiddleware", $"Received cookies: {cookies}");

                var authHeader = context.Request.Headers["Authorization"].ToString();
                appLogger.Log("ExternalAuthMiddleware", $"Authorization header: {authHeader}");
                
                // Check if user is authenticated
                var authResult = await signInManager.AuthenticateAsync();

                if (!authResult.Succeeded || authResult.Principal?.Identity?.IsAuthenticated != true)
                {
                    var baseUrl = configuration["Application:BaseUrl"];
                    appLogger.Log("ExternalAuthMiddleware", "User not authenticated - redirecting to login");

                    var originalHost = context.Request.Headers["X-Forwarded-Host"].FirstOrDefault();
                    var originalPath = context.Request.Headers["X-Original-URI"].FirstOrDefault() ??
                                   context.Request.Query["returnUrl"].FirstOrDefault() ?? "/";
                    var originalScheme = context.Request.Headers["X-Forwarded-Proto"].FirstOrDefault() ?? "https";

                    var fullReturnUrl = $"{originalScheme}://{originalHost}{originalPath}";
                    var loginUrl = $"{baseUrl}/login?returnUrl={Uri.EscapeDataString(fullReturnUrl)}";

                    context.Response.StatusCode = 302;
                    context.Response.Headers.TryAdd("Location", loginUrl);
                    return;

                    //appLogger.Log("ExternalAuthMiddleware", "User not authenticated - returning 401");
                    //context.Response.StatusCode = 401;
                    //await context.Response.WriteAsync("Unauthorized");
                    //return;
                }

                appLogger.Log("ExternalAuthMiddleware", $"AuthResult succeeded: {authResult.Succeeded}");
                if (authResult.Principal != null)
                {
                    appLogger.Log("ExternalAuthMiddleware", $"Principal identity authenticated: {authResult.Principal.Identity?.IsAuthenticated}");
                    appLogger.Log("ExternalAuthMiddleware", $"Principal identity name: {authResult.Principal.Identity?.Name}");
                }

                // Get user information from claims
                var userId = authResult.Principal.FindFirst(ClaimTypes.UserData)?.Value;
                var userName = authResult.Principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                var userEmail = authResult.Principal.FindFirst(ClaimTypes.Email)?.Value;
                var userDisplayName = authResult.Principal.FindFirst(ClaimTypes.Name)?.Value;

                if (string.IsNullOrEmpty(userId) && string.IsNullOrEmpty(userName))
                {
                    appLogger.LogWarning("ExternalAuthMiddleware", "Authenticated user has no valid identity claims");
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsync("Invalid user claims");
                    return;
                }

                // Optional: Verify user still exists and is not locked out
                if (!string.IsNullOrEmpty(userId))
                {
                    var user = await userStorage.FindUserById(userId);
                    if (user == null)
                    {
                        appLogger.LogWarning("ExternalAuthMiddleware", $"User with ID {userId} not found in storage");
                        context.Response.StatusCode = 401;
                        await context.Response.WriteAsync("User not found");
                        return;
                    }

                    // Check if user is locked out
                    if (user.IsLockedOut)
                    {
                        appLogger.LogWarning("ExternalAuthMiddleware", $"User {userName} is locked out");
                        context.Response.StatusCode = 403;
                        await context.Response.WriteAsync("User locked out");
                        return;
                    }
                }

                // Add user information to response headers for reverse proxy
                _ = context.Response.Headers.TryAdd("X-Auth-User", userName ?? "");
                _ = context.Response.Headers.TryAdd("X-Auth-Email", userEmail ?? "");
                _ = context.Response.Headers.TryAdd("X-Auth-Name", userDisplayName ?? "");
                _ = context.Response.Headers.TryAdd("X-Auth-UserId", userId ?? "");
                _ = context.Response.Headers.TryAdd("Remote-User", userName ?? "");
                _ = context.Response.Headers.TryAdd("Remote-Email", userEmail ?? "");
                _ = context.Response.Headers.TryAdd("Remote-Name", userDisplayName ?? "");
                _ = context.Response.Headers.TryAdd("Remote-UserId", userId ?? "");

                // Add role information
                var roles = authResult.Principal.FindAll(ClaimTypes.Role).Select(c => c.Value).ToArray();
                if (roles.Length > 0)
                {
                    _ = context.Response.Headers.TryAdd("X-Auth-Roles", string.Join(",", roles));
                    _ = context.Response.Headers.TryAdd("Remote-Groups", string.Join(",", roles));
                }

                appLogger.Log("ExternalAuthMiddleware", $"Auth verification successful for user: {userName}");

                context.Response.StatusCode = 200;
                await context.Response.WriteAsync("OK");
            }
            catch (Exception ex)
            {
                appLogger.LogError("ExternalAuthMiddleware", "Error during auth verification", ex);
                context.Response.StatusCode = 500;
                await context.Response.WriteAsync("Internal server error");
            }
        }

        /// <summary>
        /// Handles user information requests from reverse proxy
        /// Returns JSON with user details if authenticated
        /// </summary>
        private async Task HandleUserInfoAsync(
            HttpContext context,
            IApplicationLogger appLogger,
            ISecurityService securityService,
            CustomSignInManager signInManager)
        {
            try
            {
                var ipAddress = context.GetClientIpAddress();
                appLogger.Log("ExternalAuthMiddleware", $"User info request from IP: {ipAddress}");

                // Check if IP is banned before proceeding
                if (securityService.IsIpBanned(ipAddress))
                {
                    var banEnd = securityService.GetIpBanEndTime(ipAddress);
                    appLogger.LogWarning("ExternalAuthMiddleware", $"IP {ipAddress} is banned until {banEnd} - denying user info request");
                    context.Response.StatusCode = 403;
                    await context.Response.WriteAsync("IP address banned");
                    return;
                }

                // Check if user is authenticated
                var authResult = await signInManager.AuthenticateAsync();

                if (!authResult.Succeeded || authResult.Principal?.Identity?.IsAuthenticated != true)
                {
                    appLogger.Log("ExternalAuthMiddleware", "User not authenticated for user info request");
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsync("Unauthorized");
                    return;
                }

                // Get user information from claims
                var userId = authResult.Principal.FindFirst(ClaimTypes.UserData)?.Value;
                var userName = authResult.Principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                var userEmail = authResult.Principal.FindFirst(ClaimTypes.Email)?.Value;
                var userDisplayName = authResult.Principal.FindFirst(ClaimTypes.Name)?.Value;
                var roles = authResult.Principal.FindAll(ClaimTypes.Role).Select(c => c.Value).ToArray();

                // Create user info response
                var userInfo = new
                {
                    id = userId,
                    username = userName,
                    email = userEmail,
                    displayName = userDisplayName,
                    roles,
                    authenticated = true,
                    authenticationTime = authResult.Properties?.IssuedUtc?.ToString("yyyy-MM-ddTHH:mm:ssZ")
                };

                context.Response.ContentType = "application/json";
                context.Response.StatusCode = 200;

                var json = JsonSerializer.Serialize(userInfo, new JsonSerializerOptions
                {
                    PropertyNamingPolicy = JsonNamingPolicy.CamelCase
                });

                await context.Response.WriteAsync(json);

                appLogger.Log("ExternalAuthMiddleware", $"User info returned for user: {userName}");
            }
            catch (Exception ex)
            {
                appLogger.LogError("ExternalAuthMiddleware", "Error during user info request", ex);
                context.Response.StatusCode = 500;
                await context.Response.WriteAsync("Internal server error");
            }
        }

        /// <summary>
        /// Handles login redirect requests from reverse proxy
        /// Redirects to login page with return URL
        /// </summary>
        private async Task HandleLoginRedirectAsync(HttpContext context, IApplicationLogger appLogger, ISecurityService securityService)
        {
            try
            {
                var ipAddress = context.GetClientIpAddress();
                var returnUrl = context.Request.Query["returnUrl"].FirstOrDefault() ?? context.Request.Headers["X-Original-URI"].FirstOrDefault() ?? "/";

                appLogger.Log("ExternalAuthMiddleware", $"Login redirect request from IP: {ipAddress}, returnUrl: {returnUrl}");

                // Check if IP is banned before proceeding
                if (securityService.IsIpBanned(ipAddress))
                {
                    var banEnd = securityService.GetIpBanEndTime(ipAddress);
                    var banEndFormatted = banEnd?.ToString("yyyy-MM-dd HH:mm:ss") ?? "unknown";
                    appLogger.LogWarning("ExternalAuthMiddleware", $"IP {ipAddress} is banned until {banEnd} - redirecting to login with ban message");

                    // Redirect to login page with IP ban error
                    var loginUrlWithBan = $"/login?error=ip_banned&banEnd={Uri.EscapeDataString(banEndFormatted)}&returnUrl={Uri.EscapeDataString(returnUrl)}";
                    context.Response.Redirect(loginUrlWithBan);
                    return;
                }

                // Build login URL with return URL
                var loginUrl = $"/login?returnUrl={Uri.EscapeDataString(returnUrl)}";

                context.Response.Redirect(loginUrl);
                appLogger.Log("ExternalAuthMiddleware", $"Redirecting to login: {loginUrl}");
            }
            catch (Exception ex)
            {
                appLogger.LogError("ExternalAuthMiddleware", "Error during login redirect", ex);
                context.Response.StatusCode = 500;
                await context.Response.WriteAsync("Internal server error");
            }
        }
    }
}
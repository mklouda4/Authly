using Authly.Authorization;
using Authly.Authorization.UserStorage;
using Authly.Extension;
using Authly.Models;
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
        /// Returns 200 if user is authenticated via session or token, 401/403 if not
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

                // Try token-based authentication first
                var user = await TryTokenAuthenticationAsync(context, appLogger);
                if (user != null)
                {
                    await SetAuthHeadersFromUser(context, appLogger, user);
                    appLogger.Log("ExternalAuthMiddleware", $"Auth verification successful for user: {user.UserName} (token auth)");
                    context.Response.StatusCode = 200;
                    await context.Response.WriteAsync("OK");
                    return;
                }

                // Fallback to session-based authentication
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
                }

                appLogger.Log("ExternalAuthMiddleware", $"AuthResult succeeded: {authResult.Succeeded}");
                if (authResult.Principal != null)
                {
                    appLogger.Log("ExternalAuthMiddleware", $"Principal identity authenticated: {authResult.Principal.Identity?.IsAuthenticated}");
                    appLogger.Log("ExternalAuthMiddleware", $"Principal identity name: {authResult.Principal.Identity?.Name}");
                }

                // Get user information from claims for session auth
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
                    var sessionUser = await userStorage.FindUserById(userId);
                    if (sessionUser == null)
                    {
                        appLogger.LogWarning("ExternalAuthMiddleware", $"User with ID {userId} not found in storage");
                        context.Response.StatusCode = 401;
                        await context.Response.WriteAsync("User not found");
                        return;
                    }

                    // Check if user is locked out
                    if (sessionUser.IsLockedOut)
                    {
                        appLogger.LogWarning("ExternalAuthMiddleware", $"User {userName} is locked out");
                        context.Response.StatusCode = 403;
                        await context.Response.WriteAsync("User locked out");
                        return;
                    }
                }

                // Add user information to response headers for reverse proxy (session auth)
                await SetAuthHeadersFromSession(context, authResult, userName, userEmail, userDisplayName, userId);

                appLogger.Log("ExternalAuthMiddleware", $"Auth verification successful for user: {userName} (session auth)");

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
        /// Sets authentication headers from User object (token-based auth)
        /// </summary>
        private async Task SetAuthHeadersFromUser(HttpContext context, IApplicationLogger appLogger, User user)
        {
            await Task.CompletedTask;
            try
            {
                // Add user information to response headers for reverse proxy
                _ = context.Response.Headers.TryAdd("X-Auth-User", user.UserName ?? "");
                _ = context.Response.Headers.TryAdd("X-Auth-Email", user.Email ?? "");
                _ = context.Response.Headers.TryAdd("X-Auth-Name", user.FullName ?? "");
                _ = context.Response.Headers.TryAdd("X-Auth-UserId", user.Id ?? "");
                _ = context.Response.Headers.TryAdd("Remote-User", user.UserName ?? "");
                _ = context.Response.Headers.TryAdd("Remote-Email", user.Email ?? "");
                _ = context.Response.Headers.TryAdd("Remote-Name", user.FullName ?? "");
                _ = context.Response.Headers.TryAdd("Remote-UserId", user.Id ?? "");

                // Add role information based on user properties
                var roles = new List<string> { "user" };
                if (user.Administrator)
                {
                    roles.Add("admin");
                    roles.Add("Administrator");
                }

                if (roles.Count > 0)
                {
                    var rolesString = string.Join(",", roles);
                    _ = context.Response.Headers.TryAdd("X-Auth-Roles", rolesString);
                    _ = context.Response.Headers.TryAdd("Remote-Groups", rolesString);
                }

                // Add additional headers for token-based auth
                _ = context.Response.Headers.TryAdd("X-Auth-Method", "token");
                _ = context.Response.Headers.TryAdd("X-Auth-IsAdmin", user.Administrator.ToString().ToLower());
                _ = context.Response.Headers.TryAdd("X-Auth-HasTotp", user.HasTotp.ToString().ToLower());

                appLogger.Log("ExternalAuthMiddleware", $"Set auth headers for token user: {user.UserName}");
            }
            catch (Exception ex)
            {
                appLogger.LogError("ExternalAuthMiddleware", "Error setting auth headers from user", ex);
            }
        }

        /// <summary>
        /// Sets authentication headers from session claims
        /// </summary>
        private async Task SetAuthHeadersFromSession(HttpContext context, Microsoft.AspNetCore.Authentication.AuthenticateResult authResult, 
            string? userName, string? userEmail, string? userDisplayName, string? userId)
        {
            await Task.CompletedTask;
            try
            {
                // Add user information to response headers for reverse proxy
                _ = context.Response.Headers.TryAdd("X-Auth-User", userName ?? "");
                _ = context.Response.Headers.TryAdd("X-Auth-Email", userEmail ?? "");
                _ = context.Response.Headers.TryAdd("X-Auth-Name", userDisplayName ?? "");
                _ = context.Response.Headers.TryAdd("X-Auth-UserId", userId ?? "");
                _ = context.Response.Headers.TryAdd("Remote-User", userName ?? "");
                _ = context.Response.Headers.TryAdd("Remote-Email", userEmail ?? "");
                _ = context.Response.Headers.TryAdd("Remote-Name", userDisplayName ?? "");
                _ = context.Response.Headers.TryAdd("Remote-UserId", userId ?? "");

                // Add role information from claims
                var roles = authResult.Principal.FindAll(ClaimTypes.Role).Select(c => c.Value).ToArray();
                if (roles.Length > 0)
                {
                    var rolesString = string.Join(",", roles);
                    _ = context.Response.Headers.TryAdd("X-Auth-Roles", rolesString);
                    _ = context.Response.Headers.TryAdd("Remote-Groups", rolesString);
                }

                // Add additional headers for session-based auth
                _ = context.Response.Headers.TryAdd("X-Auth-Method", "session");
                
                // Check if user is admin from roles
                var isAdmin = roles.Contains("Administrator") || roles.Contains("admin");
                _ = context.Response.Headers.TryAdd("X-Auth-IsAdmin", isAdmin.ToString().ToLower());
            }
            catch (Exception ex)
            {
                // Log error but don't fail the request
                // appLogger.LogError would need to be accessible here
            }
        }

        /// <summary>
        /// Handles user information requests from reverse proxy
        /// Returns JSON with user details if authenticated via session or token
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

                // Try token-based authentication first
                var user = await TryTokenAuthenticationAsync(context, appLogger);
                if (user != null)
                {
                    await ReturnUserInfoAsync(context, appLogger, user, "token");
                    return;
                }

                // Fallback to session-based authentication
                var authResult = await signInManager.AuthenticateAsync();

                if (!authResult.Succeeded || authResult.Principal?.Identity?.IsAuthenticated != true)
                {
                    appLogger.Log("ExternalAuthMiddleware", "User not authenticated for user info request");
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsync("Unauthorized");
                    return;
                }

                // Get user information from claims for session auth
                var userId = authResult.Principal.FindFirst(ClaimTypes.UserData)?.Value;
                var userName = authResult.Principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                var userEmail = authResult.Principal.FindFirst(ClaimTypes.Email)?.Value;
                var userDisplayName = authResult.Principal.FindFirst(ClaimTypes.Name)?.Value;
                var roles = authResult.Principal.FindAll(ClaimTypes.Role).Select(c => c.Value).ToArray();

                var sessionUserInfo = new
                {
                    id = userId,
                    username = userName,
                    email = userEmail,
                    displayName = userDisplayName,
                    roles,
                    authenticated = true,
                    authenticationMethod = "session",
                    authenticationTime = authResult.Properties?.IssuedUtc?.ToString("yyyy-MM-ddTHH:mm:ssZ")
                };

                await WriteJsonResponseAsync(context, sessionUserInfo);
                appLogger.Log("ExternalAuthMiddleware", $"User info returned for user: {userName} (session auth)");
            }
            catch (Exception ex)
            {
                appLogger.LogError("ExternalAuthMiddleware", "Error during user info request", ex);
                context.Response.StatusCode = 500;
                await context.Response.WriteAsync("Internal server error");
            }
        }

        /// <summary>
        /// Attempts to authenticate user using token from Authorization header or URL parameter
        /// </summary>
        private async Task<User?> TryTokenAuthenticationAsync(HttpContext context, IApplicationLogger appLogger)
        {
            try
            {
                string? token = null;

                // Try to get token from Authorization header (Bearer token)
                var authHeader = context.Request.Headers["Authorization"].ToString();
                if (!string.IsNullOrEmpty(authHeader))
                {
                    if (authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                    {
                        token = authHeader["Bearer ".Length..].Trim();
                        appLogger.Log("ExternalAuthMiddleware", "Token found in Authorization header");
                      }
                    else if (authHeader.StartsWith("Token ", StringComparison.OrdinalIgnoreCase))
                    {
                        token = authHeader["Token ".Length..].Trim();
                        appLogger.Log("ExternalAuthMiddleware", "Token found in Authorization header (Token scheme)");
                    }
                }

                // Try to get token from URL parameter as fallback
                if (string.IsNullOrEmpty(token))
                {
                    token = context.Request.Query["token"].FirstOrDefault() ?? 
                            context.Request.Query["access_token"].FirstOrDefault();
                    
                    if (!string.IsNullOrEmpty(token))
                    {
                        appLogger.Log("ExternalAuthMiddleware", "Token found in URL parameter");
                    }
                }

                // Try to get token from X-API-Key header as additional option
                if (string.IsNullOrEmpty(token))
                {
                    token = context.Request.Headers["X-API-Key"].FirstOrDefault();
                    if (!string.IsNullOrEmpty(token))
                    {
                        appLogger.Log("ExternalAuthMiddleware", "Token found in X-API-Key header");
                      }
                }

                if (string.IsNullOrEmpty(token))
                {
                    return null;
                }

                // Get required services from DI container
                var tokenService = context.RequestServices.GetRequiredService<ITokenService>();
                var securityService = context.RequestServices.GetRequiredService<ISecurityService>();
                var ipAddress = context.GetClientIpAddress();
                
                // Validate token and get user
                var user = await tokenService.ValidateTokenAsync(token);
                
                if (user != null)
                {
                    appLogger.Log("ExternalAuthMiddleware", $"Token validation successful for user: {user.UserName}");

                    // Check if user is locked out
                    if (securityService.IsUserLockedOut(user))
                    {
                        appLogger.LogWarning("ExternalAuthMiddleware", $"Token user {user.UserName} is locked out until {user.LockoutEnd}");
                        
                        // Record the failed attempt for trying to access with locked account
                        var securityResult = securityService.RecordFailedAttempt(user, ipAddress);
                        appLogger.LogWarning("ExternalAuthMiddleware", $"Recorded failed attempt for locked user {user.UserName} from IP {ipAddress}");

                        // Update user with any changes from security service (e.g., extended lockout)
                        var userStore = context.RequestServices.GetRequiredService<IUserStorage>();
                        await userStore.UpdateUser(user);
                        
                        return null;
                    }
                    
                    // User is valid and not locked out - record successful access
                    appLogger.Log("ExternalAuthMiddleware", $"Token authentication successful for user: {user.UserName}");
                                        
                    return user;
                }
                else
                {
                    appLogger.LogWarning("ExternalAuthMiddleware", $"Invalid or expired token provided from IP: {ipAddress}");
                    
                    // Record failed attempt for invalid token
                    // We don't have a user object here, so we'll record it as IP-only attempt
                    securityService.RecordFailedAttempt(null, ipAddress);
                }
                
                return null;
            }
            catch (Exception ex)
            {
                appLogger.LogError("ExternalAuthMiddleware", "Error during token authentication", ex);
                
                // Record failed attempt on exception as well
                try
                {
                    var securityService = context.RequestServices.GetRequiredService<ISecurityService>();
                    var ipAddress = context.GetClientIpAddress();
                    securityService.RecordFailedAttempt(null, ipAddress);
                }
                catch (Exception secEx)
                {
                    appLogger.LogError("ExternalAuthMiddleware", "Error recording failed attempt after token authentication exception", secEx);
                }
                
                return null;
            }
        }

        /// <summary>
        /// Returns user information as JSON response
        /// </summary>
        private async Task ReturnUserInfoAsync(HttpContext context, IApplicationLogger appLogger, User user, string authMethod)
        {
            try
            {
                // Determine user roles
                var roles = new List<string>();
                if (user.Administrator)
                {
                    roles.Add("Administrator");
                    roles.Add("admin");
                }
                roles.Add("user");

                var userInfo = new
                {
                    id = user.Id,
                    username = user.UserName,
                    email = user.Email,
                    displayName = user.FullName,
                    roles = roles.ToArray(),
                    authenticated = true,
                    authenticationMethod = authMethod,
                    isAdmin = user.Administrator,
                    hasTotp = user.HasTotp,
                    emailConfirmed = user.EmailConfirmed,
                    authenticationTime = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
                };

                await WriteJsonResponseAsync(context, userInfo);
                appLogger.Log("ExternalAuthMiddleware", $"User info returned for user: {user.UserName} ({authMethod} auth)");
            }
            catch (Exception ex)
            {
                appLogger.LogError("ExternalAuthMiddleware", "Error returning user info", ex);
                context.Response.StatusCode = 500;
                await context.Response.WriteAsync("Internal server error");
            }
        }

        /// <summary>
        /// Writes JSON response to HTTP context
        /// </summary>
        private static async Task WriteJsonResponseAsync(HttpContext context, object data)
        {
            context.Response.ContentType = "application/json";
            context.Response.StatusCode = 200;

            var json = JsonSerializer.Serialize(data, new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            });

            await context.Response.WriteAsync(json);
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
using Authly.Authorization.UserStorage;
using Authly.Extension;
using Authly.Models;
using Authly.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using OtpNet;
using System.Security.Claims;

namespace Authly.Authorization.Local
{
    /// <summary>
    /// Extension methods for registering local authentication services in the dependency injection container
    /// </summary>
    public static class LocalAuthExtension
    {
        /// <summary>
        /// Adds local authentication services to the service collection
        /// </summary>
        /// <param name="services">The service collection to add services to</param>
        /// <returns>The service collection for method chaining</returns>
        public static IServiceCollection AddLocalAuth(this IServiceCollection services)
        {
            services.AddScoped<ILocalAuth, LocalAuth>();
            return services;
        }
    }

    /// <summary>
    /// Interface for local username/password authentication with optional TOTP (Time-based One-Time Password) support
    /// </summary>
    public interface ILocalAuth
    {
        /// <summary>
        /// Indicates whether local authentication is enabled (always true for local auth)
        /// </summary>
        bool IsEnabled { get; init; }

        /// <summary>
        /// Handles local username/password login requests with security checks and optional TOTP validation
        /// </summary>
        /// <param name="context">The HTTP context for the current request</param>
        /// <returns>A task representing the asynchronous operation</returns>
        Task HandleLoginAsync(HttpContext context);
        
        /// <summary>
        /// Handles user logout requests, clearing sessions and authentication cookies
        /// </summary>
        /// <param name="context">The HTTP context for the current request</param>
        /// <returns>A task representing the asynchronous operation</returns>
        Task HandleLogoutAsync(HttpContext context);
        
        /// <summary>
        /// Determines if the current request is a logout request
        /// </summary>
        /// <param name="context">The HTTP context to check</param>
        /// <returns>True if this is a logout request, false otherwise</returns>
        bool IsLogout(HttpContext context);
        
        /// <summary>
        /// Determines if the current request is a login request
        /// </summary>
        /// <param name="context">The HTTP context to check</param>
        /// <returns>True if this is a login request, false otherwise</returns>
        bool IsLogin(HttpContext context);
        
        /// <summary>
        /// Determines if the current request is any local authentication related request (login or logout)
        /// </summary>
        /// <param name="context">The HTTP context to check</param>
        /// <returns>True if this is any local authentication request, false otherwise</returns>
        bool IsRequest(HttpContext context);
    }

    /// <summary>
    /// Local authentication service handling username/password authentication with comprehensive security features
    /// including brute force protection, IP rate limiting, user lockouts, and TOTP (Time-based One-Time Password) support
    /// </summary>
    public class LocalAuth : ILocalAuth
    {
        private readonly IApplicationLogger _appLogger;
        private readonly IUserStorage _userStorage;
        private readonly SignInManager<User> _signInManager;
        private readonly ISecurityService _securityService;
        private readonly IUrlValidator _urlValidator;
        private readonly IMetricsService _metricsService;
        private readonly ISessionTrackingService _sessionTrackingService;

        /// <summary>
        /// Initializes a new instance of the LocalAuth class with required dependencies
        /// </summary>
        /// <param name="configuration">Application configuration (not used for local auth but required for interface consistency)</param>
        /// <param name="appLogger">Logger for recording authentication events</param>
        /// <param name="userStorage">Service for user data operations</param>
        /// <param name="signInManager">ASP.NET Core Identity sign-in manager</param>
        /// <param name="securityService">Service for security checks, rate limiting, and lockout management</param>
        /// <param name="urlValidator">URL validation service to prevent open redirects</param>
        /// <param name="metricsService">Service for recording authentication metrics</param>
        /// <param name="sessionTrackingService">Service for tracking active user sessions</param>
        public LocalAuth(
            IConfiguration configuration, 
            IApplicationLogger appLogger,
            IUserStorage userStorage, 
            SignInManager<User> signInManager,
            ISecurityService securityService,
            IUrlValidator urlValidator,
            IMetricsService metricsService,
            ISessionTrackingService sessionTrackingService)
        {
            _appLogger = appLogger;
            _userStorage = userStorage;
            _signInManager = signInManager;
            _securityService = securityService;
            _urlValidator = urlValidator;
            _metricsService = metricsService;
            _sessionTrackingService = sessionTrackingService;

            IsEnabled = true; // Local authentication is always enabled
        }

        /// <summary>
        /// Indicates whether local authentication is enabled (always true for local auth)
        /// </summary>
        public bool IsEnabled { get; init; }
        
        /// <summary>
        /// The provider name identifier for local authentication
        /// </summary>
        public const string ProviderName = "Local";
        
        /// <summary>
        /// The URI path for login requests
        /// </summary>
        public const string LoginUri = "/login";
        
        /// <summary>
        /// The URI path for logout requests
        /// </summary>
        public const string LogoutUri = "/logout";

        /// <summary>
        /// Determines if the current request is any local authentication related request (login or logout)
        /// </summary>
        /// <param name="context">The HTTP context to check</param>
        /// <returns>True if this is any local authentication request, false otherwise</returns>
        public bool IsRequest(HttpContext context) => IsLogin(context) || IsLogout(context);
        
        /// <summary>
        /// Determines if the current request is a login request (POST to /login)
        /// </summary>
        /// <param name="context">The HTTP context to check</param>
        /// <returns>True if this is a login request, false otherwise</returns>
        public bool IsLogin(HttpContext context) => context.Request.Path == LoginUri && context.Request.Method == "POST";
        
        /// <summary>
        /// Determines if the current request is a logout request (POST to /logout)
        /// </summary>
        /// <param name="context">The HTTP context to check</param>
        /// <returns>True if this is a logout request, false otherwise</returns>
        public bool IsLogout(HttpContext context) => context.Request.Path == LogoutUri && context.Request.Method == "POST";

        /// <summary>
        /// Handles local username/password login requests with comprehensive security checks including
        /// IP rate limiting, user lockouts, brute force protection, and TOTP validation
        /// </summary>
        /// <param name="context">The HTTP context for the current request</param>
        /// <returns>A task representing the asynchronous operation</returns>
        public async Task HandleLoginAsync(HttpContext context)
        {
            try
            {
                // Extract client IP address for security tracking
                var ipAddress = context.GetClientIpAddress();

                // Parse login form data
                var form = await context.Request.ReadFormAsync();
                var username = form["username"].ToString();
                var password = form["password"].ToString();
                var totpCode = form["totpCode"].ToString();
                var returnUrl = form["returnUrl"].ToString();
                var rememberMe = form["rememberMe"].ToString() == "true";

                _appLogger.Log("LocalAuth", $"Processing login for user: {username} from IP: {ipAddress}");

                // Check IP ban status before proceeding
                if (_securityService.IsIpBanned(ipAddress))
                {
                    var banEnd = _securityService.GetIpBanEndTime(ipAddress);
                    _appLogger.LogWarning("LocalAuth", $"IP {ipAddress} is banned until {banEnd}");

                    var banEndFormatted = banEnd?.ToString("yyyy-MM-dd HH:mm:ss") ?? "unknown";
                    context.Response.Redirect($"/login?error=ip_banned&banEnd={Uri.EscapeDataString(banEndFormatted)}&returnUrl={Uri.EscapeDataString(returnUrl)}");
                    return;
                }

                // Handle TOTP validation scenario (when credentials are stored in session)
                if (!string.IsNullOrEmpty(totpCode) && string.IsNullOrEmpty(password))
                {
                    var sessionUsername = context.Session.GetString("TotpUsername");
                    var sessionPassword = context.Session.GetString("TotpPassword");

                    if (!string.IsNullOrEmpty(sessionUsername) && !string.IsNullOrEmpty(sessionPassword))
                    {
                        username = sessionUsername;
                        password = sessionPassword;
                        _appLogger.Log("LocalAuth", $"Retrieved credentials from session for TOTP validation: {username}");
                    }
                }

                // Find user for authentication and security tracking
                User? user = null;
                if (!string.IsNullOrEmpty(username))
                {
                    user = await _userStorage.FindUserByName(username);
                }

                if (user?.IsExternal == true)
                {
                    _appLogger.LogWarning("LocalAuth", $"User {username} is an external user and cannot log in via local authentication");
                    context.Response.Redirect($"/login?error=external_user&returnUrl={Uri.EscapeDataString(returnUrl)}");
                    return;
                }

                // Check user lockout status before credential validation
                if (user != null && _securityService.IsUserLockedOut(user))
                {
                    var lockoutEnd = _securityService.GetLockoutEndTime(user);
                    _appLogger.LogWarning("LocalAuth", $"User {username} is locked out until {lockoutEnd}");

                    var lockoutEndFormatted = lockoutEnd?.ToString("yyyy-MM-dd HH:mm:ss") ?? "unknown";
                    context.Response.Redirect($"/login?error=user_locked&lockoutEnd={Uri.EscapeDataString(lockoutEndFormatted)}&returnUrl={Uri.EscapeDataString(returnUrl)}");
                    return;
                }

                // Validate user credentials
                var isValidCredentials = user != null && user.PasswordHash == password;

                if (!isValidCredentials)
                {
                    // Record failed authentication attempt
                    var securityResult = _securityService.RecordFailedAttempt(user, ipAddress);

                    // Record metrics for failed login attempt
                    _metricsService.RecordLoginAttempt(false, securityResult.IsUserLockedOut ? "user_lockout" :
                                                             securityResult.IsIpBanned ? "ip_banned" : "invalid_credentials");

                    // Update user record if user exists
                    if (user != null)
                    {
                        await _userStorage.UpdateUser(user);
                    }

                    _appLogger.LogWarning("LocalAuth", $"Authentication failed for user: {username} from IP: {ipAddress}. Reason: {securityResult.ErrorMessage}");

                    // Handle different failure scenarios
                    if (securityResult.IsUserLockedOut)
                    {
                        var lockoutEndFormatted = securityResult.LockoutEndUtc?.ToString("yyyy-MM-dd HH:mm:ss") ?? "unknown";
                        context.Response.Redirect($"/login?error=user_locked&lockoutEnd={Uri.EscapeDataString(lockoutEndFormatted)}&returnUrl={Uri.EscapeDataString(returnUrl)}");
                        return;
                    }
                    else if (securityResult.IsIpBanned)
                    {
                        var banEndFormatted = securityResult.LockoutEndUtc?.ToString("yyyy-MM-dd HH:mm:ss") ?? "unknown";
                        context.Response.Redirect($"/login?error=ip_banned&banEnd={Uri.EscapeDataString(banEndFormatted)}&returnUrl={Uri.EscapeDataString(returnUrl)}");
                        return;
                    }
                    else
                    {
                        var remaining = securityResult.RemainingAttempts;
                        context.Response.Redirect($"/login?error=invalid&remaining={remaining}&returnUrl={Uri.EscapeDataString(returnUrl)}");
                        return;
                    }
                }

                // Credentials are valid - proceed with TOTP validation if required
                _appLogger.Log("LocalAuth", $"Basic credentials validated for user: {username}");

                // Check if TOTP (Two-Factor Authentication) is required
                if (user!.HasTotp && !string.IsNullOrEmpty(user.TotpSecret))
                {
                    // TOTP is required - check if code was provided
                    if (string.IsNullOrEmpty(totpCode))
                    {
                        _appLogger.Log("LocalAuth", $"User {username} has TOTP enabled but no code provided");

                        // Store credentials in session for TOTP validation
                        context.Session.SetString("TotpUsername", username);
                        context.Session.SetString("TotpPassword", password);
                        await context.Session.CommitAsync();

                        context.Response.Redirect($"/login?error=totp_required&username={Uri.EscapeDataString(username)}&returnUrl={Uri.EscapeDataString(returnUrl)}");
                        return;
                    }

                    // Validate TOTP code
                    var totp = new Totp(Base32Encoding.ToBytes(user.TotpSecret));
                    if (!totp.VerifyTotp(totpCode, out long timeStepMatched, new VerificationWindow(2, 2)))
                    {
                        _appLogger.LogWarning("LocalAuth", $"Invalid TOTP code provided for user: {username}");

                        // Record failed attempt for invalid TOTP
                        var securityResult = _securityService.RecordFailedAttempt(user, ipAddress);
                        await _userStorage.UpdateUser(user);

                        // Record TOTP failure metric
                        _metricsService.RecordLoginAttempt(false, "invalid_totp");

                        if (securityResult.IsUserLockedOut)
                        {
                            var lockoutEndFormatted = securityResult.LockoutEndUtc?.ToString("yyyy-MM-dd HH:mm:ss") ?? "unknown";
                            context.Response.Redirect($"/login?error=user_locked&lockoutEnd={Uri.EscapeDataString(lockoutEndFormatted)}&returnUrl={Uri.EscapeDataString(returnUrl)}");
                            return;
                        }
                        else if (securityResult.IsIpBanned)
                        {
                            var banEndFormatted = securityResult.LockoutEndUtc?.ToString("yyyy-MM-dd HH:mm:ss") ?? "unknown";
                            context.Response.Redirect($"/login?error=ip_banned&banEnd={Uri.EscapeDataString(banEndFormatted)}&returnUrl={Uri.EscapeDataString(returnUrl)}");
                            return;
                        }
                        else
                        {
                            var remaining = securityResult.RemainingAttempts;
                            context.Response.Redirect($"/login?error=invalid_totp&username={Uri.EscapeDataString(username)}&remaining={remaining}&returnUrl={Uri.EscapeDataString(returnUrl)}");
                            return;
                        }
                    }

                    _appLogger.Log("LocalAuth", $"TOTP code validated successfully for user: {username}");

                    // Clear TOTP session data after successful validation
                    context.Session.Remove("TotpUsername");
                    context.Session.Remove("TotpPassword");
                }

                // Clear failed login attempts on successful authentication
                _securityService.ClearUserFailedAttempts(user);
                await _userStorage.UpdateUser(user);

                await _signInManager.PasswordSignInAsync(
                    user.UserName!,
                    user.Password!,
                    rememberMe,
                    false);

                // Track the user session for metrics
                _sessionTrackingService.AddSession(user.UserName!);

                _appLogger.Log("LocalAuth", $"User {username} successfully signed in via local authentication");

                // Record successful login metric
                _metricsService.RecordLoginAttempt(true);

                // Redirect to dashboard or original return URL
                var validatedReturnUrl = _urlValidator.ValidateReturnUrl(returnUrl, context.Request.Host.Value);
                context.Response.Redirect(validatedReturnUrl);
            }
            catch (Exception ex)
            {
                _appLogger.LogError("LocalAuth", "Error during local authentication login", ex);

                // Clean up session data on error
                context.Session.Remove("TotpUsername");
                context.Session.Remove("TotpPassword");

                context.Response.Redirect("/login?error=server");
            }
        }

        /// <summary>
        /// Handles user logout requests by clearing authentication cookies and session data
        /// </summary>
        /// <param name="context">The HTTP context for the current request</param>
        /// <returns>A task representing the asynchronous operation</returns>
        public async Task HandleLogoutAsync(HttpContext context)
        {
            try
            {
                _appLogger.Log("LocalAuth", "Processing logout request");

                // Remove session from tracking before clearing session data
                var userName = context?.User?.Claims?.FirstOrDefault(x => x.Type == ClaimTypes.NameIdentifier)?.Value;
                _sessionTrackingService.RemoveSession(userName);

                // Clear any temporary session data
                context.Session.Remove("TotpUsername");
                context.Session.Remove("TotpPassword");

                await _signInManager.SignOutAsync();
                // Sign out user and clear authentication cookies
                //await context.SignOutAsync("Identity.Application");

                _appLogger.Log("LocalAuth", "User successfully signed out");

                // Redirect to login page
                context.Response.Redirect("/login");
            }
            catch (Exception ex)
            {
                _appLogger.LogError("LocalAuth", "Error during logout", ex);

                // Clean up session data on error
                context.Session.Remove("TotpUsername");
                context.Session.Remove("TotpPassword");

                context.Response.Redirect("/login");
            }
        }
    }
}

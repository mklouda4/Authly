using Authly.Authorization.UserStorage;
using Authly.Extension;
using Authly.Models;
using Authly.Services;
using Microsoft.AspNetCore.Identity;

namespace Authly.Authorization.Facebook
{
    /// <summary>
    /// Extension methods for registering Facebook OAuth authentication services in the dependency injection container
    /// </summary>
    public static class FacebookOAuthExtension
    {
        /// <summary>
        /// Adds Facebook OAuth authentication services to the service collection
        /// </summary>
        /// <param name="services">The service collection to add services to</param>
        /// <returns>The service collection for method chaining</returns>
        public static IServiceCollection AddFacebookOAuth(this IServiceCollection services)
        {
            services.AddScoped<IFacebookOAuth, FacebookOAuth>();
            return services;
        }
    }

    /// <summary>
    /// Interface for Facebook OAuth 2.0 authentication using Facebook Graph API v18.0
    /// </summary>
    public interface IFacebookOAuth
    {
        /// <summary>
        /// Indicates whether Facebook OAuth authentication is enabled in the application configuration
        /// </summary>
        bool IsEnabled { get; init; }

        /// <summary>
        /// Handles the initiation of Facebook OAuth login flow with state parameter validation
        /// </summary>
        /// <param name="context">The HTTP context for the current request</param>
        /// <returns>A task representing the asynchronous operation</returns>
        Task HandleLoginAsync(HttpContext context);
        
        /// <summary>
        /// Handles the Facebook OAuth callback after user authorization, including token exchange and user sign-in
        /// </summary>
        /// <param name="context">The HTTP context for the current request</param>
        /// <returns>A task representing the asynchronous operation</returns>
        Task HandleLoginCallback(HttpContext context);
        
        /// <summary>
        /// Determines if the current request is a Facebook OAuth callback request
        /// </summary>
        /// <param name="context">The HTTP context to check</param>
        /// <returns>True if this is a Facebook OAuth callback request, false otherwise</returns>
        bool IsCallback(HttpContext context);
        
        /// <summary>
        /// Determines if the current request is a Facebook OAuth login initiation request
        /// </summary>
        /// <param name="context">The HTTP context to check</param>
        /// <returns>True if this is a Facebook OAuth login request, false otherwise</returns>
        bool IsLogin(HttpContext context);
        
        /// <summary>
        /// Determines if the current request is any Facebook OAuth related request (login or callback)
        /// </summary>
        /// <param name="context">The HTTP context to check</param>
        /// <returns>True if this is any Facebook OAuth request, false otherwise</returns>
        bool IsRequest(HttpContext context);
    }

    /// <summary>
    /// Facebook OAuth 2.0 authentication service using Facebook Graph API v18.0
    /// Implements OAuth 2.0 Authorization Code Flow with state parameter validation for CSRF protection
    /// </summary>
    public class FacebookOAuth : IFacebookOAuth
    {
        private readonly string? _appId;
        private readonly string? _appSecret;
        private readonly IApplicationLogger _appLogger;
        private readonly IApplicationService _applicationService;
        private readonly ITemporaryRegistrationService _temporaryRegistrationService;
        private readonly IUserStorage _userStorage;
        private readonly SignInManager<User> _signInManager;
        private readonly ISecurityService _securityService;
        private readonly IUrlValidator _urlValidator;
        private readonly IMetricsService _metricsService;
        private readonly ISessionTrackingService _sessionTrackingService;

        /// <summary>
        /// Initializes a new instance of the FacebookOAuth class with required dependencies
        /// </summary>
        /// <param name="configuration">Application configuration for reading Facebook OAuth settings</param>
        /// <param name="appLogger">Logger for recording authentication events</param>
        /// <param name="applicationService">Service for application-level operations, such as retrieving configuration settings</param>
        /// <param name="temporaryRegistrationService">Service for managing temporary registration settings</param>"
        /// <param name="userStorage">Service for user data operations</param>
        /// <param name="signInManager">ASP.NET Core Identity sign-in manager</param>
        /// <param name="securityService">Service for security checks, rate limiting, and lockout management</param>
        /// <param name="urlValidator">URL validation service to prevent open redirects</param>
        /// <param name="metricsService">Service for recording authentication metrics</param>
        /// <param name="sessionTrackingService">Service for tracking active user sessions</param>
        public FacebookOAuth(
            IConfiguration configuration, 
            IApplicationLogger appLogger,
            IApplicationService applicationService,
            ITemporaryRegistrationService temporaryRegistrationService,
            IUserStorage userStorage, 
            SignInManager<User> signInManager,
            ISecurityService securityService,
            IUrlValidator urlValidator,
            IMetricsService metricsService,
            ISessionTrackingService sessionTrackingService)
        {
            _appLogger = appLogger;
            _applicationService = applicationService;
            _temporaryRegistrationService = temporaryRegistrationService;
            _userStorage = userStorage;
            _signInManager = signInManager;
            _securityService = securityService;
            _urlValidator = urlValidator;
            _metricsService = metricsService;
            _sessionTrackingService = sessionTrackingService;

            IsEnabled = configuration.GetValue<bool>("Application:ExternalAuth:EnableFacebook");
            _appId = configuration["Authentication:Facebook:AppId"];
            _appSecret = configuration["Authentication:Facebook:AppSecret"];
        }

        /// <summary>
        /// Indicates whether Facebook OAuth authentication is enabled in the application configuration
        /// </summary>
        public bool IsEnabled { get; init; }
        
        /// <summary>
        /// The provider name identifier for Facebook OAuth
        /// </summary>
        public const string ProviderName = "Facebook";
        
        /// <summary>
        /// The URI path for initiating Facebook OAuth login flow
        /// </summary>
        public const string LoginUri = "/facebook-login";
        
        /// <summary>
        /// The URI path for receiving Facebook OAuth callbacks
        /// </summary>
        public const string CallbackUri = "/facebook/oauth2/callback";

        /// <summary>
        /// Determines if the current request is any Facebook OAuth related request (login or callback)
        /// </summary>
        /// <param name="context">The HTTP context to check</param>
        /// <returns>True if this is any Facebook OAuth request, false otherwise</returns>
        public bool IsRequest(HttpContext context) => IsLogin(context) || IsCallback(context);
        
        /// <summary>
        /// Determines if the current request is a Facebook OAuth login initiation request
        /// </summary>
        /// <param name="context">The HTTP context to check</param>
        /// <returns>True if this is a Facebook OAuth login request, false otherwise</returns>
        public bool IsLogin(HttpContext context) => IsEnabled && context.Request.Path == LoginUri;
        
        /// <summary>
        /// Determines if the current request is a Facebook OAuth callback request
        /// </summary>
        /// <param name="context">The HTTP context to check</param>
        /// <returns>True if this is a Facebook OAuth callback request, false otherwise</returns>
        public bool IsCallback(HttpContext context) => IsEnabled && context.Request.Path == CallbackUri;

        /// <summary>
        /// Handles Facebook OAuth login initiation by generating state parameter and redirecting to Facebook OAuth.
        /// This method implements the OAuth 2.0 Authorization Code Flow with account re-authentication for enhanced security.
        /// </summary>
        /// <param name="context">The HTTP context for the current request</param>
        /// <returns>A task representing the asynchronous operation</returns>
        public async Task HandleLoginAsync(HttpContext context)
        {
            try
            {
                // Extract client IP address for security tracking
                var ipAddress = context.GetClientIpAddress();
                
                // Check IP ban status before proceeding with OAuth flow
                if (_securityService.IsIpBanned(ipAddress))
                {
                    var banEnd = _securityService.GetIpBanEndTime(ipAddress);
                    _appLogger.LogWarning("FacebookLogin", $"IP {ipAddress} is banned until {banEnd}, blocking OAuth login attempt");

                    var banEndFormatted = banEnd?.ToString("yyyy-MM-dd HH:mm:ss") ?? "unknown";
                    context.Response.Redirect($"/login?error=ip_banned&banEnd={Uri.EscapeDataString(banEndFormatted)}");
                    return;
                }

                var returnUrl = context.Request.Query["returnUrl"].ToString();
                var forceAccountSelection = true; // Force account selection for better security

                // Check if Facebook OAuth is enabled
                if (!IsEnabled)
                {
                    _appLogger.LogWarning("FacebookLogin", "Facebook authentication is disabled in configuration");
                    context.Response.Redirect($"/login?returnUrl={Uri.EscapeDataString(returnUrl)}");
                    return;
                }

                // Validate OAuth configuration
                if (string.IsNullOrEmpty(_appId) || string.IsNullOrEmpty(_appSecret))
                {
                    _appLogger.LogWarning("FacebookLogin", "Facebook OAuth credentials are missing from configuration");
                    context.Response.Redirect("/login?error=missing_config");
                    return;
                }

                // Generate state parameter for CSRF protection
                var state = Guid.NewGuid().ToString();

                _appLogger.Log("FacebookLogin", $"Generated OAuth state: {state}, Force account selection: {forceAccountSelection} for IP: {ipAddress}");

                // Store OAuth session data securely
                context.Session.SetString("oauth_return_url", returnUrl ?? "/dashboard");
                context.Session.SetString("oauth_provider", ProviderName);
                context.Session.SetString("oauth_state", state);

                // Commit session data before redirect
                await context.Session.CommitAsync();

                // Construct Facebook OAuth authorization URL
                var redirectUri = Uri.EscapeDataString($"{context.Request.Scheme}://{context.Request.Host}{CallbackUri}");
                var scopes = Uri.EscapeDataString("email,public_profile");

                var facebookUrl = $"https://www.facebook.com/v18.0/dialog/oauth?" +
                                 $"client_id={_appId}&" +
                                 $"response_type=code&" +
                                 $"scope={scopes}&" +
                                 $"redirect_uri={redirectUri}&" +
                                 $"state={state}";

                // Add account re-authentication parameter (Facebook equivalent of prompt=select_account)
                if (forceAccountSelection)
                {
                    facebookUrl += "&auth_type=rerequest";
                    _appLogger.Log("FacebookLogin", "Adding account re-authentication parameter");
                }

                _appLogger.Log("FacebookLogin", "Redirecting to Facebook OAuth authorization server");

                // Redirect user to Facebook OAuth
                context.Response.Redirect(facebookUrl);
            }
            catch (Exception ex)
            {
                _appLogger.LogError("FacebookLogin", $"Error during Facebook OAuth initiation: {ex.Message}", ex);
                context.Response.Redirect("/login?error=facebook_login_failed");
            }
        }

        /// <summary>
        /// Handles Facebook OAuth callback by validating state, exchanging authorization code for access token,
        /// retrieving user information from Facebook Graph API, and signing in the user
        /// </summary>
        /// <param name="context">The HTTP context for the current request</param>
        /// <returns>A task representing the asynchronous operation</returns>
        public async Task HandleLoginCallback(HttpContext context)
        {
            try
            {
                // Extract client IP address for security tracking
                var ipAddress = context.GetClientIpAddress();
                
                // Check IP ban status before proceeding with OAuth callback
                if (_securityService.IsIpBanned(ipAddress))
                {
                    var banEnd = _securityService.GetIpBanEndTime(ipAddress);
                    _appLogger.LogWarning("FacebookOAuth", $"IP {ipAddress} is banned until {banEnd}, blocking OAuth callback");

                    var banEndFormatted = banEnd?.ToString("yyyy-MM-dd HH:mm:ss") ?? "unknown";
                    context.Response.Redirect($"/login?error=ip_banned&banEnd={Uri.EscapeDataString(banEndFormatted)}");
                    return;
                }

                // Check if Facebook OAuth is still enabled
                if (!IsEnabled)
                {
                    _appLogger.LogWarning("FacebookCallback", "Facebook authentication is disabled - rejecting callback");
                    context.Response.Redirect("/login?error=facebook_disabled");
                    return;
                }

                // Extract callback parameters
                var state = context.Request.Query["state"].ToString();
                var code = context.Request.Query["code"].ToString();
                var error = context.Request.Query["error"].ToString();
                var errorDescription = context.Request.Query["error_description"].ToString();

                _appLogger.Log("FacebookOAuth", $"Processing OAuth callback for IP: {ipAddress}");

                // Handle OAuth errors from Facebook
                if (!string.IsNullOrEmpty(error))
                {
                    _appLogger.LogWarning("FacebookOAuth", $"Facebook OAuth error: {error} - {errorDescription}");
                    context.Response.Redirect($"/login?error=oauth_error&details={Uri.EscapeDataString($"{error}: {errorDescription}")}");
                    return;
                }

                // Validate required parameters
                if (string.IsNullOrEmpty(code) || string.IsNullOrEmpty(state))
                {
                    _appLogger.LogWarning("FacebookOAuth", "Missing required OAuth callback parameters");
                    context.Response.Redirect("/login?error=missing_params");
                    return;
                }

                // Retrieve and validate session data
                var sessionState = context.Session.GetString("oauth_state");
                var returnUrl = context.Session.GetString("oauth_return_url");
                var validatedReturnUrl = _urlValidator.ValidateReturnUrl(returnUrl, context.Request.Host.Value);

                // Validate state parameter for CSRF protection
                if (string.IsNullOrEmpty(sessionState) || sessionState != state)
                {
                    _appLogger.LogError("FacebookOAuth", $"OAuth state mismatch - Session: '{sessionState}', Received: '{state}'");
                    context.Response.Redirect("/login?error=state_mismatch");
                    return;
                }

                // Clean up session data
                context.Session.Remove("oauth_state");
                context.Session.Remove("oauth_return_url");
                context.Session.Remove("oauth_provider");

                var httpClient = context.RequestServices.GetRequiredService<HttpClient>();

                // Exchange authorization code for access token using Facebook Graph API
                var tokenUrl = $"https://graph.facebook.com/v18.0/oauth/access_token?" +
                              $"client_id={_appId}&" +
                              $"client_secret={_appSecret}&" +
                              $"code={code}&" +
                              $"redirect_uri={Uri.EscapeDataString($"{context.Request.Scheme}://{context.Request.Host}{CallbackUri}")}";

                var tokenResponse = await httpClient.GetAsync(tokenUrl);
                var tokenContent = await tokenResponse.Content.ReadAsStringAsync();

                if (!tokenResponse.IsSuccessStatusCode)
                {
                    _appLogger.LogError("FacebookOAuth", $"Token exchange failed: {tokenContent}");
                    context.Response.Redirect("/login?error=token_failed");
                    return;
                }

                // Parse token response and extract access token
                var tokenData = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, object>>(tokenContent);
                var accessToken = tokenData?["access_token"]?.ToString();

                if (string.IsNullOrEmpty(accessToken))
                {
                    _appLogger.LogError("FacebookOAuth", "No access token received from Facebook");
                    context.Response.Redirect("/login?error=no_access_token");
                    return;
                }

                // Retrieve user information from Facebook Graph API
                var userInfoUrl = $"https://graph.facebook.com/v18.0/me?fields=id,name,email&access_token={accessToken}";
                var userInfoResponse = await httpClient.GetAsync(userInfoUrl);
                var userInfoContent = await userInfoResponse.Content.ReadAsStringAsync();

                if (!userInfoResponse.IsSuccessStatusCode)
                {
                    _appLogger.LogError("FacebookOAuth", $"Failed to retrieve user info from Facebook: {userInfoContent}");
                    context.Response.Redirect("/login?error=userinfo_failed");
                    return;
                }

                _appLogger.Log("FacebookOAuth", "Successfully retrieved user information from Facebook");

                // Parse user information
                var userInfo = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, object>>(userInfoContent);
                var email = userInfo?["email"]?.ToString();
                var name = userInfo?["name"]?.ToString();
                var facebookId = userInfo?["id"]?.ToString();

                // Validate required user information
                if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(facebookId))
                {
                    _appLogger.LogWarning("FacebookOAuth", "Missing required user information from Facebook");
                    context.Response.Redirect("/login?error=missing_user_info");
                    return;
                }

                _appLogger.Log("FacebookOAuth", $"Facebook OAuth successful for email: {email} from IP: {ipAddress}");

                // Find or create user account
                var existingUser = await _userStorage.FindUserByName($"{ProviderName}:{email}");

                User user;
                if (existingUser != null)
                {
                    // Use existing user account
                    user = existingUser;
                    _appLogger.Log("FacebookOAuth", $"Existing user found for email: {email}");
                }
                else if (!_temporaryRegistrationService.IsRegistrationAllowed)
                {
                    _appLogger.LogError("FacebookOAuth", $"User registration is disabled: {email}");
                    context.Response.Redirect("/login?error=user_creation_failed");
                    return;
                }
                else
                {
                    // Create new user account for Facebook OAuth user
                    user = new User
                    {
                        UserName = $"{ProviderName}:{email}",
                        Email = email,
                        FullName = name ?? email,
                        EmailConfirmed = true, // Facebook verifies email addresses
                        SecurityStamp = Guid.NewGuid().ToString(),
                        PasswordHash = email, // Placeholder password for external users (consistent with Google implementation)
                        Administrator = false,
                        HasTotp = false,
                        FailedLoginAttempts = 0,
                        IsExternal = true
                    };

                    var createResult = await _userStorage.CreateUser(user);
                    if (!createResult)
                    {
                        _appLogger.LogError("FacebookOAuth", $"Failed to create user account for Facebook login: {email}");
                        context.Response.Redirect("/login?error=user_creation_failed");
                        return;
                    }

                    _appLogger.Log("FacebookOAuth", $"New user account created for Facebook login: {email}");
                }

                // Sign in the user
                await _signInManager.PasswordSignInAsync($"{ProviderName}:{email}", email, true, false);

                // Track the user session for metrics
                _sessionTrackingService.AddSession(user.UserName!);

                _appLogger.Log("FacebookOAuth", $"User {email} successfully signed in via Facebook OAuth from IP: {ipAddress}");

                // Record successful external authentication
                _metricsService.RecordLoginAttempt(true, "external_facebook");

                // Unban the IP address if it was previously banned
                _securityService.UnbanIpAddress(ipAddress);

                // Redirect to dashboard or original return URL
                context.Response.Redirect(validatedReturnUrl);
            }
            catch (Exception ex)
            {
                _appLogger.LogError("FacebookOAuth", $"Error during Facebook OAuth callback processing: {ex.Message}", ex);
                context.Response.Redirect("/login?error=callback_exception");
            }
        }
    }
}

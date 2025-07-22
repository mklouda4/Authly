using Authly.Authorization.UserStorage;
using Authly.Extension;
using Authly.Models;
using Authly.Services;
using Microsoft.AspNetCore.Identity;

namespace Authly.Authorization.Microsoft
{
    /// <summary>
    /// Extension methods for registering Microsoft OAuth authentication services in the dependency injection container
    /// </summary>
    public static class MicrosoftOAuthExtension
    {
        /// <summary>
        /// Adds Microsoft OAuth authentication services to the service collection
        /// </summary>
        /// <param name="services">The service collection to add services to</param>
        /// <returns>The service collection for method chaining</returns>
        public static IServiceCollection AddMicrosoftOAuth(this IServiceCollection services)
        {
            services.AddScoped<IMicrosoftOAuth, MicrosoftOAuth>();
            return services;
        }
    }

    /// <summary>
    /// Interface for Microsoft OAuth 2.0 authentication with PKCE (Proof Key for Code Exchange) support
    /// </summary>
    public interface IMicrosoftOAuth
    {
        /// <summary>
        /// Indicates whether Microsoft OAuth authentication is enabled in the application configuration
        /// </summary>
        bool IsEnabled { get; init; }

        /// <summary>
        /// Handles the initiation of Microsoft OAuth login flow with PKCE parameters
        /// </summary>
        /// <param name="context">The HTTP context for the current request</param>
        /// <returns>A task representing the asynchronous operation</returns>
        Task HandleLoginAsync(HttpContext context);

        /// <summary>
        /// Handles the Microsoft OAuth callback after user authorization, including token exchange and user sign-in
        /// </summary>
        /// <param name="context">The HTTP context for the current request</param>
        /// <returns>A task representing the asynchronous operation</returns>
        Task HandleLoginCallback(HttpContext context);

        /// <summary>
        /// Determines if the current request is a Microsoft OAuth callback request
        /// </summary>
        /// <param name="context">The HTTP context to check</param>
        /// <returns>True if this is a Microsoft OAuth callback request, false otherwise</returns>
        bool IsCallback(HttpContext context);

        /// <summary>
        /// Determines if the current request is a Microsoft OAuth login initiation request
        /// </summary>
        /// <param name="context">The HTTP context to check</param>
        /// <returns>True if this is a Microsoft OAuth login request, false otherwise</returns>
        bool IsLogin(HttpContext context);

        /// <summary>
        /// Determines if the current request is any Microsoft OAuth related request (login or callback)
        /// </summary>
        /// <param name="context">The HTTP context to check</param>
        /// <returns>True if this is any Microsoft OAuth request, false otherwise</returns>
        bool IsRequest(HttpContext context);
    }

    /// <summary>
    /// Microsoft OAuth 2.0 authentication service implementing PKCE (Proof Key for Code Exchange) flow
    /// for enhanced security against authorization code interception attacks
    /// </summary>
    public class MicrosoftOAuth : IMicrosoftOAuth
    {
        private readonly string? _clientId;
        private readonly string? _clientSecret;
        private readonly string? _tenantId;
        private readonly IApplicationLogger _appLogger;
        private readonly IApplicationService _applicationService;
        private readonly IUserStorage _userStorage;
        private readonly SignInManager<User> _signInManager;
        private readonly ISecurityService _securityService;
        private readonly IUrlValidator _urlValidator;
        private readonly IMetricsService _metricsService;
        private readonly ISessionTrackingService _sessionTrackingService;

        /// <summary>
        /// Initializes a new instance of the MicrosoftOAuth class with required dependencies
        /// </summary>
        /// <param name="configuration">Application configuration for reading Microsoft OAuth settings</param>
        /// <param name="appLogger">Logger for recording authentication events</param>
        /// <param name="applicationService">Service for application-level operations, such as retrieving configuration settings</param>
        /// <param name="userStorage">Service for user data operations</param>
        /// <param name="signInManager">ASP.NET Core Identity sign-in manager</param>
        /// <param name="securityService">Service for security checks, rate limiting, and lockout management</param>
        /// <param name="urlValidator">URL validation service to prevent open redirects</param>
        /// <param name="metricsService">Service for recording authentication metrics</param>
        /// <param name="sessionTrackingService">Service for tracking active user sessions</param>
        public MicrosoftOAuth(
            IConfiguration configuration, 
            IApplicationLogger appLogger,
            IApplicationService applicationService,
            IUserStorage userStorage, 
            SignInManager<User> signInManager,
            ISecurityService securityService,
            IUrlValidator urlValidator,
            IMetricsService metricsService,
            ISessionTrackingService sessionTrackingService)
        {
            _appLogger = appLogger;
            _applicationService = applicationService;
            _userStorage = userStorage;
            _signInManager = signInManager;
            _securityService = securityService;
            _urlValidator = urlValidator;
            _metricsService = metricsService;
            _sessionTrackingService = sessionTrackingService;

            IsEnabled = configuration.GetValue<bool>("Application:ExternalAuth:EnableMicrosoft");
            _clientId = configuration["Authentication:Microsoft:ClientId"];
            _clientSecret = configuration["Authentication:Microsoft:ClientSecret"];
            _tenantId = configuration["Authentication:Microsoft:TenantId"] ?? "common"; // Use 'common' for multi-tenant
        }

        /// <summary>
        /// Indicates whether Microsoft OAuth authentication is enabled in the application configuration
        /// </summary>
        public bool IsEnabled { get; init; }

        /// <summary>
        /// The provider name identifier for Microsoft OAuth
        /// </summary>
        public const string ProviderName = "Microsoft";

        /// <summary>
        /// The URI path for initiating Microsoft OAuth login flow
        /// </summary>
        public const string LoginUri = "/microsoft-login";

        /// <summary>
        /// The URI path for receiving Microsoft OAuth callbacks
        /// </summary>
        public const string CallbackUri = "/microsoft/oauth2/callback";

        /// <summary>
        /// Determines if the current request is any Microsoft OAuth related request (login or callback)
        /// </summary>
        /// <param name="context">The HTTP context to check</param>
        /// <returns>True if this is any Microsoft OAuth request, false otherwise</returns>
        public bool IsRequest(HttpContext context) => IsLogin(context) || IsCallback(context);

        /// <summary>
        /// Determines if the current request is a Microsoft OAuth login initiation request
        /// </summary>
        /// <param name="context">The HTTP context to check</param>
        /// <returns>True if this is a Microsoft OAuth login request, false otherwise</returns>
        public bool IsLogin(HttpContext context) => IsEnabled && context.Request.Path == LoginUri;

        /// <summary>
        /// Determines if the current request is a Microsoft OAuth callback request
        /// </summary>
        /// <param name="context">The HTTP context to check</param>
        /// <returns>True if this is a Microsoft OAuth callback request, false otherwise</returns>
        public bool IsCallback(HttpContext context) => IsEnabled && context.Request.Path == CallbackUri;

        /// <summary>
        /// Handles Microsoft OAuth login initiation by generating PKCE parameters and redirecting to Microsoft OAuth
        /// This method implements the OAuth 2.0 Authorization Code Flow with PKCE for enhanced security
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
                    _appLogger.LogWarning("MicrosoftLogin", $"IP {ipAddress} is banned until {banEnd}, blocking OAuth login attempt");

                    var banEndFormatted = banEnd?.ToString("yyyy-MM-dd HH:mm:ss") ?? "unknown";
                    context.Response.Redirect($"/login?error=ip_banned&banEnd={Uri.EscapeDataString(banEndFormatted)}");
                    return;
                }

                // Local function to generate cryptographically secure PKCE code verifier
                string GenerateCodeVerifier()
                {
                    var bytes = new byte[32];
                    using var rng = System.Security.Cryptography.RandomNumberGenerator.Create();
                    rng.GetBytes(bytes);
                    return Convert.ToBase64String(bytes)
                        .TrimEnd('=')
                        .Replace('+', '-')
                        .Replace('/', '_');
                }

                // Local function to generate SHA256 code challenge from verifier
                string GenerateCodeChallenge(string codeVerifier)
                {
                    using var sha256 = System.Security.Cryptography.SHA256.Create();
                    var challengeBytes = sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(codeVerifier));
                    return Convert.ToBase64String(challengeBytes)
                        .TrimEnd('=')
                        .Replace('+', '-')
                        .Replace('/', '_');
                }

                var returnUrl = context.Request.Query["returnUrl"].ToString();

                // Check if Microsoft OAuth is enabled
                if (!IsEnabled)
                {
                    _appLogger.LogWarning("MicrosoftLogin", "Microsoft authentication is disabled in configuration");
                    context.Response.Redirect($"/login?returnUrl={Uri.EscapeDataString(returnUrl)}");
                    return;
                }

                // Validate OAuth configuration
                if (string.IsNullOrEmpty(_clientId))
                {
                    _appLogger.LogError("MicrosoftLogin", "Microsoft OAuth Client ID is not configured");
                    context.Response.Redirect("/login?error=missing_config");
                    return;
                }

                // Generate PKCE parameters for enhanced security
                var codeVerifier = GenerateCodeVerifier();
                var codeChallenge = GenerateCodeChallenge(codeVerifier);
                var state = Guid.NewGuid().ToString();

                _appLogger.Log("MicrosoftLogin", $"Generated OAuth state: {state} for IP: {ipAddress}");

                // Store OAuth session data securely
                context.Session.SetString("oauth_return_url", returnUrl ?? "/dashboard");
                context.Session.SetString("oauth_provider", ProviderName);
                context.Session.SetString("oauth_state", state);
                context.Session.SetString("oauth_code_verifier", codeVerifier);

                // Commit session data before redirect
                await context.Session.CommitAsync();

                // Construct Microsoft OAuth authorization URL with PKCE
                var redirectUri = Uri.EscapeDataString($"{context.Request.Scheme}://{context.Request.Host}{CallbackUri}");
                var scopes = Uri.EscapeDataString("openid profile email");

                var microsoftUrl = $"https://login.microsoftonline.com/{_tenantId}/oauth2/v2.0/authorize?" +
                                 $"client_id={_clientId}&" +
                                 $"response_type=code&" +
                                 $"scope={scopes}&" +
                                 $"redirect_uri={redirectUri}&" +
                                 $"state={state}&" +
                                 $"code_challenge={codeChallenge}&" +
                                 $"code_challenge_method=S256&" +
                                 $"prompt=select_account";

                _appLogger.Log("MicrosoftLogin", "Redirecting to Microsoft OAuth authorization server");

                // Redirect user to Microsoft OAuth
                context.Response.Redirect(microsoftUrl);
            }
            catch (Exception ex)
            {
                _appLogger.LogError("MicrosoftLogin", $"Error during Microsoft OAuth initiation: {ex.Message}", ex);
                context.Response.Redirect("/login?error=microsoft_login_failed");
            }
        }

        /// <summary>
        /// Handles Microsoft OAuth callback by validating state, exchanging authorization code for tokens using PKCE,
        /// retrieving user information, and signing in the user
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
                    _appLogger.LogWarning("MicrosoftOAuth", $"IP {ipAddress} is banned until {banEnd}, blocking OAuth callback");

                    var banEndFormatted = banEnd?.ToString("yyyy-MM-dd HH:mm:ss") ?? "unknown";
                    context.Response.Redirect($"/login?error=ip_banned&banEnd={Uri.EscapeDataString(banEndFormatted)}");
                    return;
                }

                // Extract callback parameters
                var state = context.Request.Query["state"].ToString();
                var code = context.Request.Query["code"].ToString();
                var error = context.Request.Query["error"].ToString();

                _appLogger.Log("MicrosoftOAuth", $"Processing OAuth callback for IP: {ipAddress}");

                // Handle OAuth errors from Microsoft
                if (!string.IsNullOrEmpty(error))
                {
                    _appLogger.LogWarning("MicrosoftOAuth", $"Microsoft OAuth error: {error}");
                    context.Response.Redirect($"/login?error=oauth_error&details={Uri.EscapeDataString(error)}");
                    return;
                }

                // Validate required parameters
                if (string.IsNullOrEmpty(code) || string.IsNullOrEmpty(state))
                {
                    _appLogger.LogWarning("MicrosoftOAuth", "Missing required OAuth callback parameters");
                    context.Response.Redirect("/login?error=missing_params");
                    return;
                }

                // Retrieve and validate session data
                var sessionState = context.Session.GetString("oauth_state");
                var sessionCodeVerifier = context.Session.GetString("oauth_code_verifier");
                var returnUrl = context.Session.GetString("oauth_return_url");
                var validatedReturnUrl = _urlValidator.ValidateReturnUrl(returnUrl, context.Request.Host.Value);

                // Validate state parameter for CSRF protection
                if (string.IsNullOrEmpty(sessionState) || sessionState != state)
                {
                    _appLogger.LogError("MicrosoftOAuth", $"OAuth state mismatch - Session: '{sessionState}', Received: '{state}'");
                    context.Response.Redirect("/login?error=state_mismatch");
                    return;
                }

                // Validate PKCE code verifier
                if (string.IsNullOrEmpty(sessionCodeVerifier))
                {
                    _appLogger.LogError("MicrosoftOAuth", "PKCE code verifier missing from session");
                    context.Response.Redirect("/login?error=missing_verifier");
                    return;
                }

                // Clean up session data
                context.Session.Remove("oauth_state");
                context.Session.Remove("oauth_return_url");
                context.Session.Remove("oauth_provider");
                context.Session.Remove("oauth_code_verifier");

                var httpClient = context.RequestServices.GetRequiredService<HttpClient>();

                // Exchange authorization code for access token using PKCE
                var tokenRequestData = new Dictionary<string, string>
                {
                    ["client_id"] = _clientId!,
                    ["client_secret"] = _clientSecret!,
                    ["code"] = code,
                    ["grant_type"] = "authorization_code",
                    ["redirect_uri"] = $"{context.Request.Scheme}://{context.Request.Host}{CallbackUri}",
                    ["code_verifier"] = sessionCodeVerifier
                };

                var tokenRequest = new FormUrlEncodedContent(tokenRequestData);
                var tokenResponse = await httpClient.PostAsync($"https://login.microsoftonline.com/{_tenantId}/oauth2/v2.0/token", tokenRequest);
                var tokenContent = await tokenResponse.Content.ReadAsStringAsync();

                if (!tokenResponse.IsSuccessStatusCode)
                {
                    _appLogger.LogError("MicrosoftOAuth", $"Token exchange failed: {tokenContent}");
                    context.Response.Redirect($"/login?error=token_failed&details={Uri.EscapeDataString(tokenContent)}");
                    return;
                }

                // Parse token response and extract access token
                var tokenData = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, object>>(tokenContent);
                var accessToken = tokenData?["access_token"]?.ToString();

                if (string.IsNullOrEmpty(accessToken))
                {
                    _appLogger.LogError("MicrosoftOAuth", "No access token received from Microsoft");
                    context.Response.Redirect("/login?error=no_access_token");
                    return;
                }

                // Retrieve user information from Microsoft Graph API
                httpClient.DefaultRequestHeaders.Authorization =
                    new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);

                var userInfoResponse = await httpClient.GetAsync("https://graph.microsoft.com/v1.0/me");
                var userInfoContent = await userInfoResponse.Content.ReadAsStringAsync();

                if (!userInfoResponse.IsSuccessStatusCode)
                {
                    _appLogger.LogError("MicrosoftOAuth", $"Failed to retrieve user info: {userInfoContent}");
                    context.Response.Redirect("/login?error=userinfo_failed");
                    return;
                }

                _appLogger.LogInfo("MicrosoftOAuth", "Successfully retrieved user information from Microsoft");

                // Parse user information
                var userInfo = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, object>>(userInfoContent);
                var email = userInfo?["mail"]?.ToString() ?? userInfo?["userPrincipalName"]?.ToString();
                var displayName = userInfo?["displayName"]?.ToString();
                var microsoftId = userInfo?["id"]?.ToString();

                // Validate required user information
                if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(microsoftId))
                {
                    _appLogger.LogWarning("MicrosoftOAuth", "Missing required user information from Microsoft");
                    context.Response.Redirect("/login?error=missing_user_info");
                    return;
                }

                _appLogger.Log("MicrosoftOAuth", $"Microsoft OAuth successful for email: {email} from IP: {ipAddress}");

                // Find or create user account
                var existingUser = await _userStorage.FindUserByName($"{ProviderName}:{email}");

                User user;
                if (existingUser != null)
                {
                    // Use existing user account
                    user = existingUser;
                    _appLogger.Log("MicrosoftOAuth", $"Existing user found for email: {email}");
                }
                else if (!_applicationService.AllowRegistration)
                {
                    _appLogger.LogError("FacebookOAuth", $"User registration is disabled: {email}");
                    context.Response.Redirect("/login?error=user_creation_failed");
                    return;
                }
                else
                {
                    // Create new user account for Microsoft OAuth user
                    user = new User
                    {
                        Id = Guid.NewGuid().ToString(),
                        UserName = $"{ProviderName}:{email}",
                        Email = email,
                        FullName = displayName ?? email,
                        EmailConfirmed = true, // Microsoft verifies email addresses
                        SecurityStamp = Guid.NewGuid().ToString(),
                        PasswordHash = email, // Placeholder password for external users
                        Administrator = false,
                        HasTotp = false,
                        FailedLoginAttempts = 0,
                        IsExternal = true
                    };

                    var createResult = await _userStorage.CreateUser(user);
                    if (!createResult)
                    {
                        _appLogger.LogError("MicrosoftOAuth", $"Failed to create user account for Microsoft login: {email}");
                        context.Response.Redirect("/login?error=user_creation_failed");
                        return;
                    }

                    _appLogger.Log("MicrosoftOAuth", $"New user account created for Microsoft login: {email}");
                }

                // Sign in the user
                await _signInManager.PasswordSignInAsync($"{ProviderName}:{email}", email, true, false);

                // Track the user session for metrics
                _sessionTrackingService.AddSession(user.UserName!);

                _appLogger.LogInfo("MicrosoftOAuth", $"User {email} successfully signed in via Microsoft OAuth from IP: {ipAddress}");

                // Record successful external authentication
                _metricsService.RecordLoginAttempt(true, "external_microsoft");

                // Redirect to dashboard or original return URL
                context.Response.Redirect(validatedReturnUrl);
            }
            catch (Exception ex)
            {
                _appLogger.LogError("MicrosoftOAuth", $"Error during Microsoft OAuth callback processing: {ex.Message}", ex);
                context.Response.Redirect($"/login?error=callback_exception&details={Uri.EscapeDataString(ex.Message)}");
            }
        }
    }
}
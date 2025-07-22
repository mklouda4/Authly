using Authly.Authorization.UserStorage;
using Authly.Extension;
using Authly.Models;
using Authly.Services;
using Microsoft.AspNetCore.Identity;

namespace Authly.Authorization.GitHub
{
    /// <summary>
    /// Extension methods for registering GitHub OAuth authentication services in the dependency injection container
    /// </summary>
    public static class GitHubOAuthExtension
    {
        /// <summary>
        /// Adds GitHub OAuth authentication services to the service collection
        /// </summary>
        /// <param name="services">The service collection to add services to</param>
        /// <returns>The service collection for method chaining</returns>
        public static IServiceCollection AddGitHubOAuth(this IServiceCollection services)
        {
            services.AddScoped<IGitHubOAuth, GitHubOAuth>();
            return services;
        }
    }

    /// <summary>
    /// Interface for GitHub OAuth 2.0 authentication with PKCE (Proof Key for Code Exchange) support
    /// </summary>
    public interface IGitHubOAuth
    {
        /// <summary>
        /// Indicates whether GitHub OAuth authentication is enabled in the application configuration
        /// </summary>
        bool IsEnabled { get; init; }

        /// <summary>
        /// Handles the initiation of GitHub OAuth login flow with PKCE parameters
        /// </summary>
        /// <param name="context">The HTTP context for the current request</param>
        /// <returns>A task representing the asynchronous operation</returns>
        Task HandleLoginAsync(HttpContext context);

        /// <summary>
        /// Handles the GitHub OAuth callback after user authorization, including token exchange and user sign-in
        /// </summary>
        /// <param name="context">The HTTP context for the current request</param>
        /// <returns>A task representing the asynchronous operation</returns>
        Task HandleLoginCallback(HttpContext context);

        /// <summary>
        /// Determines if the current request is a GitHub OAuth callback request
        /// </summary>
        /// <param name="context">The HTTP context to check</param>
        /// <returns>True if this is a GitHub OAuth callback request, false otherwise</returns>
        bool IsCallback(HttpContext context);

        /// <summary>
        /// Determines if the current request is a GitHub OAuth login initiation request
        /// </summary>
        /// <param name="context">The HTTP context to check</param>
        /// <returns>True if this is a GitHub OAuth login request, false otherwise</returns>
        bool IsLogin(HttpContext context);

        /// <summary>
        /// Determines if the current request is any GitHub OAuth related request (login or callback)
        /// </summary>
        /// <param name="context">The HTTP context to check</param>
        /// <returns>True if this is any GitHub OAuth request, false otherwise</returns>
        bool IsRequest(HttpContext context);
    }

    /// <summary>
    /// GitHub OAuth 2.0 authentication service implementing PKCE (Proof Key for Code Exchange) flow
    /// for enhanced security against authorization code interception attacks
    /// </summary>
    public class GitHubOAuth : IGitHubOAuth
    {
        private readonly string? _clientId;
        private readonly string? _clientSecret;
        private readonly IApplicationLogger _appLogger;
        private readonly IApplicationService _applicationService;
        private readonly IUserStorage _userStorage;
        private readonly SignInManager<User> _signInManager;
        private readonly ISecurityService _securityService;
        private readonly IUrlValidator _urlValidator;
        private readonly IMetricsService _metricsService;
        private readonly ISessionTrackingService _sessionTrackingService;

        /// <summary>
        /// Initializes a new instance of the GitHubOAuth class with required dependencies
        /// </summary>
        /// <param name="configuration">Application configuration for reading GitHub OAuth settings</param>
        /// <param name="appLogger">Logger for recording authentication events</param>
        /// <param name="applicationService">Service for application-level operations, such as retrieving configuration settings</param>
        /// <param name="userStorage">Service for user data operations</param>
        /// <param name="signInManager">ASP.NET Core Identity sign-in manager</param>
        /// <param name="securityService">Service for security checks, rate limiting, and lockout management</param>
        /// <param name="urlValidator">URL validation service to prevent open redirects</param>
        /// <param name="metricsService">Service for recording authentication metrics</param>
        /// <param name="sessionTrackingService">Service for tracking active user sessions</param>
        public GitHubOAuth(
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

            IsEnabled = configuration.GetValue<bool>("Application:ExternalAuth:EnableGitHub");
            _clientId = configuration["Authentication:GitHub:ClientId"];
            _clientSecret = configuration["Authentication:GitHub:ClientSecret"];
        }

        /// <summary>
        /// Indicates whether GitHub OAuth authentication is enabled in the application configuration
        /// </summary>
        public bool IsEnabled { get; init; }

        /// <summary>
        /// The provider name identifier for GitHub OAuth
        /// </summary>
        public const string ProviderName = "GitHub";

        /// <summary>
        /// The URI path for initiating GitHub OAuth login flow
        /// </summary>
        public const string LoginUri = "/github-login";

        /// <summary>
        /// The URI path for receiving GitHub OAuth callbacks
        /// </summary>
        public const string CallbackUri = "/github/oauth2/callback";

        /// <summary>
        /// Determines if the current request is any GitHub OAuth related request (login or callback)
        /// </summary>
        /// <param name="context">The HTTP context to check</param>
        /// <returns>True if this is any GitHub OAuth request, false otherwise</returns>
        public bool IsRequest(HttpContext context) => IsLogin(context) || IsCallback(context);

        /// <summary>
        /// Determines if the current request is a GitHub OAuth login initiation request
        /// </summary>
        /// <param name="context">The HTTP context to check</param>
        /// <returns>True if this is a GitHub OAuth login request, false otherwise</returns>
        public bool IsLogin(HttpContext context) => IsEnabled && context.Request.Path == LoginUri;

        /// <summary>
        /// Determines if the current request is a GitHub OAuth callback request
        /// </summary>
        /// <param name="context">The HTTP context to check</param>
        /// <returns>True if this is a GitHub OAuth callback request, false otherwise</returns>
        public bool IsCallback(HttpContext context) => IsEnabled && context.Request.Path == CallbackUri;

        /// <summary>
        /// Handles GitHub OAuth login initiation by generating PKCE parameters and redirecting to GitHub OAuth
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
                    _appLogger.LogWarning("GitHubLogin", $"IP {ipAddress} is banned until {banEnd}, blocking OAuth login attempt");

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

                // Check if GitHub OAuth is enabled
                if (!IsEnabled)
                {
                    _appLogger.LogWarning("GitHubLogin", "GitHub authentication is disabled in configuration");
                    context.Response.Redirect($"/login?returnUrl={Uri.EscapeDataString(returnUrl)}");
                    return;
                }

                // Validate OAuth configuration
                if (string.IsNullOrEmpty(_clientId))
                {
                    _appLogger.LogError("GitHubLogin", "GitHub OAuth Client ID is not configured");
                    context.Response.Redirect("/login?error=missing_config");
                    return;
                }

                // Generate PKCE parameters for enhanced security
                var codeVerifier = GenerateCodeVerifier();
                var codeChallenge = GenerateCodeChallenge(codeVerifier);
                var state = Guid.NewGuid().ToString();

                _appLogger.Log("GitHubLogin", $"Generated OAuth state: {state} for IP: {ipAddress}");

                // Store OAuth session data securely
                context.Session.SetString("oauth_return_url", returnUrl ?? "/dashboard");
                context.Session.SetString("oauth_provider", ProviderName);
                context.Session.SetString("oauth_state", state);
                context.Session.SetString("oauth_code_verifier", codeVerifier);

                // Commit session data before redirect
                await context.Session.CommitAsync();

                // Construct GitHub OAuth authorization URL with PKCE
                var redirectUri = Uri.EscapeDataString($"{context.Request.Scheme}://{context.Request.Host}{CallbackUri}");
                var scopes = Uri.EscapeDataString("user:email read:user");

                var githubUrl = $"https://github.com/login/oauth/authorize?" +
                              $"client_id={_clientId}&" +
                              $"redirect_uri={redirectUri}&" +
                              $"scope={scopes}&" +
                              $"state={state}&" +
                              $"code_challenge={codeChallenge}&" +
                              $"code_challenge_method=S256&" +
                              $"allow_signup=true&" +
                              $"prompt=select_account";

                _appLogger.Log("GitHubLogin", "Redirecting to GitHub OAuth authorization server");

                // Redirect user to GitHub OAuth
                context.Response.Redirect(githubUrl);
            }
            catch (Exception ex)
            {
                _appLogger.LogError("GitHubLogin", $"Error during GitHub OAuth initiation: {ex.Message}", ex);
                context.Response.Redirect("/login?error=github_login_failed");
            }
        }

        /// <summary>
        /// Handles GitHub OAuth callback by validating state, exchanging authorization code for tokens using PKCE,
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
                    _appLogger.LogWarning("GitHubOAuth", $"IP {ipAddress} is banned until {banEnd}, blocking OAuth callback");

                    var banEndFormatted = banEnd?.ToString("yyyy-MM-dd HH:mm:ss") ?? "unknown";
                    context.Response.Redirect($"/login?error=ip_banned&banEnd={Uri.EscapeDataString(banEndFormatted)}");
                    return;
                }

                // Extract callback parameters
                var state = context.Request.Query["state"].ToString();
                var code = context.Request.Query["code"].ToString();
                var error = context.Request.Query["error"].ToString();

                _appLogger.Log("GitHubOAuth", $"Processing OAuth callback for IP: {ipAddress}");

                // Handle OAuth errors from GitHub
                if (!string.IsNullOrEmpty(error))
                {
                    _appLogger.LogWarning("GitHubOAuth", $"GitHub OAuth error: {error}");
                    context.Response.Redirect($"/login?error=oauth_error&details={Uri.EscapeDataString(error)}");
                    return;
                }

                // Validate required parameters
                if (string.IsNullOrEmpty(code) || string.IsNullOrEmpty(state))
                {
                    _appLogger.LogWarning("GitHubOAuth", "Missing required OAuth callback parameters");
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
                    _appLogger.LogError("GitHubOAuth", $"OAuth state mismatch - Session: '{sessionState}', Received: '{state}'");
                    context.Response.Redirect("/login?error=state_mismatch");
                    return;
                }

                // Validate PKCE code verifier
                if (string.IsNullOrEmpty(sessionCodeVerifier))
                {
                    _appLogger.LogError("GitHubOAuth", "PKCE code verifier missing from session");
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
                    ["redirect_uri"] = $"{context.Request.Scheme}://{context.Request.Host}{CallbackUri}",
                    ["code_verifier"] = sessionCodeVerifier
                };

                var tokenRequest = new FormUrlEncodedContent(tokenRequestData);

                // GitHub requires specific Accept header for token requests
                httpClient.DefaultRequestHeaders.Accept.Clear();
                httpClient.DefaultRequestHeaders.Accept.Add(
                    new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));

                var tokenResponse = await httpClient.PostAsync("https://github.com/login/oauth/access_token", tokenRequest);
                var tokenContent = await tokenResponse.Content.ReadAsStringAsync();

                if (!tokenResponse.IsSuccessStatusCode)
                {
                    _appLogger.LogError("GitHubOAuth", $"Token exchange failed: {tokenContent}");
                    context.Response.Redirect($"/login?error=token_failed&details={Uri.EscapeDataString(tokenContent)}");
                    return;
                }

                // Parse token response and extract access token
                var tokenData = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, object>>(tokenContent);
                var accessToken = tokenData?["access_token"]?.ToString();

                if (string.IsNullOrEmpty(accessToken))
                {
                    _appLogger.LogError("GitHubOAuth", "No access token received from GitHub");
                    context.Response.Redirect("/login?error=no_access_token");
                    return;
                }

                // Retrieve user information from GitHub API
                httpClient.DefaultRequestHeaders.Clear();
                httpClient.DefaultRequestHeaders.Authorization =
                    new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
                httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("Authly-OAuth-Client/1.0");

                var userInfoResponse = await httpClient.GetAsync("https://api.github.com/user");
                var userInfoContent = await userInfoResponse.Content.ReadAsStringAsync();

                if (!userInfoResponse.IsSuccessStatusCode)
                {
                    _appLogger.LogError("GitHubOAuth", $"Failed to retrieve user info: {userInfoContent}");
                    context.Response.Redirect("/login?error=userinfo_failed");
                    return;
                }

                // Get user email from GitHub (may require separate API call)
                var emailResponse = await httpClient.GetAsync("https://api.github.com/user/emails");
                var emailContent = await emailResponse.Content.ReadAsStringAsync();

                _appLogger.LogInfo("GitHubOAuth", "Successfully retrieved user information from GitHub");

                // Parse user information
                var userInfo = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, object>>(userInfoContent);
                var name = userInfo?["name"]?.ToString();
                var login = userInfo?["login"]?.ToString();
                var githubId = userInfo?["id"]?.ToString();

                // Parse email information (GitHub returns array of emails)
                string? email = null;
                if (emailResponse.IsSuccessStatusCode)
                {
                    var emails = System.Text.Json.JsonSerializer.Deserialize<System.Text.Json.JsonElement[]>(emailContent);
                    if (emails != null)
                    {
                        // Find primary email or first verified email
                        var primaryEmail = emails.FirstOrDefault(e =>
                            e.TryGetProperty("primary", out var primary) && primary.GetBoolean());

                        if (primaryEmail.ValueKind != System.Text.Json.JsonValueKind.Undefined)
                        {
                            email = primaryEmail.GetProperty("email").GetString();
                        }
                        else
                        {
                            // Fallback to first verified email
                            var verifiedEmail = emails.FirstOrDefault(e =>
                                e.TryGetProperty("verified", out var verified) && verified.GetBoolean());

                            if (verifiedEmail.ValueKind != System.Text.Json.JsonValueKind.Undefined)
                            {
                                email = verifiedEmail.GetProperty("email").GetString();
                            }
                        }
                    }
                }

                // Fallback if no email found - use login@github.local
                if (string.IsNullOrEmpty(email))
                {
                    email = $"{login}@github.local";
                    _appLogger.LogWarning("GitHubOAuth", $"No verified email found for GitHub user {login}, using fallback: {email}");
                }

                // Validate required user information
                if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(githubId))
                {
                    _appLogger.LogWarning("GitHubOAuth", "Missing required user information from GitHub");
                    context.Response.Redirect("/login?error=missing_user_info");
                    return;
                }

                _appLogger.Log("GitHubOAuth", $"GitHub OAuth successful for user: {login} ({email}) from IP: {ipAddress}");

                // Find or create user account
                var existingUser = await _userStorage.FindUserByName($"{ProviderName}:{email}");

                User user;
                if (existingUser != null)
                {
                    // Use existing user account
                    user = existingUser;
                    _appLogger.Log("GitHubOAuth", $"Existing user found for email: {email}");
                }
                else if (!_applicationService.AllowRegistration)
                {
                    _appLogger.LogError("FacebookOAuth", $"User registration is disabled: {email}");
                    context.Response.Redirect("/login?error=user_creation_failed");
                    return;
                }
                else
                {
                    // Create new user account for GitHub OAuth user
                    user = new User
                    {
                        Id = Guid.NewGuid().ToString(),
                        UserName = $"{ProviderName}:{email}",
                        Email = email,
                        FullName = name ?? login ?? email,
                        EmailConfirmed = !email.EndsWith("@github.local"), // Only confirm if real email
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
                        _appLogger.LogError("GitHubOAuth", $"Failed to create user account for GitHub login: {email}");
                        context.Response.Redirect("/login?error=user_creation_failed");
                        return;
                    }

                    _appLogger.Log("GitHubOAuth", $"New user account created for GitHub login: {email}");
                }

                // Sign in the user
                await _signInManager.PasswordSignInAsync($"{ProviderName}:{email}", email, true, false);

                // Track the user session for metrics
                _sessionTrackingService.AddSession(user.UserName!);

                _appLogger.LogInfo("GitHubOAuth", $"User {email} successfully signed in via GitHub OAuth from IP: {ipAddress}");

                // Record successful external authentication
                _metricsService.RecordLoginAttempt(true, "external_github");

                // Redirect to dashboard or original return URL
                context.Response.Redirect(validatedReturnUrl);
            }
            catch (Exception ex)
            {
                _appLogger.LogError("GitHubOAuth", $"Error during GitHub OAuth callback processing: {ex.Message}", ex);
                context.Response.Redirect($"/login?error=callback_exception&details={Uri.EscapeDataString(ex.Message)}");
            }
        }
    }
}
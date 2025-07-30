using Authly.Extension;
using Authly.Models;
using Authly.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Swashbuckle.AspNetCore.Annotations;

namespace Authly.Controllers
{
    /// <summary>
    /// OAuth Authorization Server endpoints
    /// </summary>
    [Route("oauth")]
    [ApiController]
    [SwaggerTag("OAuth 2.0 Authorization Server")]
    public class OAuthController(
        IOAuthAuthorizationService authorizationService,
        IOAuthClientService clientService,
        UserManager<User> userManager,
        SignInManager<User> signInManager,
        IApplicationLogger logger,
        ILocalizationService localizationService,
        ISecurityService securityService,
        ISharedKeys sharedKeys) : ControllerBase
    {

        /// <summary>
        /// OAuth Authorization endpoint - GET /oauth/authorize
        /// </summary>
        /// <param name="request">OAuth authorization request parameters</param>
        /// <returns>Redirects to login or consent page, or returns authorization code</returns>
        /// <response code="302">Redirects to login, consent, or callback URL</response>
        /// <response code="400">Invalid request parameters</response>
        [HttpGet("authorize")]
        [SwaggerOperation(
            Summary = "OAuth Authorization Endpoint",
            Description = "Initiates OAuth 2.0 authorization code flow. Redirects to login if user not authenticated, then to consent page if needed.",
            OperationId = "Authorize"
        )]
        [SwaggerResponse(302, "Redirect to login, consent, or callback URL")]
        [SwaggerResponse(400, "Bad Request", typeof(OAuthErrorResponse))]
        public async Task<IActionResult> Authorize([FromQuery] OAuthAuthorizationRequest request)
        {
            try
            {
                var ipAddress = HttpContext.GetClientIpAddress();
                // Check if IP is banned before processing
                if (securityService.IsIpBanned(ipAddress))
                {
                    var banEnd = securityService.GetIpBanEndTime(ipAddress);
                    logger.LogWarning("OAuth", $"IP {ipAddress} is banned until {banEnd} - denying userinfo request");
                    return Unauthorized(new { error = "ip_banned", error_description = $"IP address banned until {banEnd}" });
                }

                logger.Log("OAuth", $"Authorization request: client_id={request.ClientId}, response_type={request.ResponseType}");

                // Validate the authorization request
                var (isValid, error, errorDescription) = await authorizationService.ValidateAuthorizationRequestAsync(request);
                if (!isValid)
                {
                    logger.LogWarning("OAuth", $"Invalid authorization request: {error} - {errorDescription}");
                    return BadRequest(new OAuthErrorResponse
                    {
                        Error = error!,
                        ErrorDescription = errorDescription,
                        State = request.State
                    });
                }

                // Check if user is authenticated
                if (!User.Identity?.IsAuthenticated == true)
                {
                    logger.Log("OAuth", "User not authenticated, redirecting to login");

                    // Store authorization request in session for after login
                    HttpContext.Session.SetString("oauth_pending_request", System.Text.Json.JsonSerializer.Serialize(request));

                    // Redirect to login with return URL
                    var returnUrl = HttpContext.Request.QueryString.ToString();
                    return Redirect($"/login?returnUrl={Uri.EscapeDataString($"/oauth/authorize{returnUrl}")}");
                }

                // Get current user
                var currentUser = await userManager.GetUserAsync(User);
                if (currentUser == null)
                {
                    logger.LogError("OAuth", "Could not find current user after authentication");
                    return BadRequest(new OAuthErrorResponse
                    {
                        Error = "server_error",
                        ErrorDescription = "Unable to process request",
                        State = request.State
                    });
                }

                // Get client details for consent screen
                var client = await clientService.GetClientAsync(request.ClientId);
                if (client == null)
                {
                    return BadRequest(new OAuthErrorResponse
                    {
                        Error = "invalid_client",
                        ErrorDescription = "Client not found",
                        State = request.State
                    });
                }

                // Parse requested scopes
                var requestedScopes = string.IsNullOrEmpty(request.Scope)
                    ? new List<string> { "openid" }
                    : request.Scope.Split(' ').ToList();

                // Check if consent is needed (for now, auto-approve)
                // In production, you might want to show a consent screen
                return await CreateAuthorizationResponse(request, currentUser.Id!, requestedScopes);
            }
            catch (Exception ex)
            {
                logger.LogError("OAuth", $"Error in authorization endpoint: {ex.Message}", ex);
                return BadRequest(new OAuthErrorResponse
                {
                    Error = "server_error",
                    ErrorDescription = "Internal server error",
                    State = request.State
                });
            }
        }

        /// <summary>
        /// OAuth Token endpoint - POST /oauth/token
        /// </summary>
        /// <param name="request">OAuth token request</param>
        /// <returns>OAuth token response or error</returns>
        /// <response code="200">Token response</response>
        /// <response code="400">Invalid request</response>
        [HttpPost("token")]
        [SwaggerOperation(
            Summary = "OAuth Token Endpoint",
            Description = "Exchanges authorization code for access token or refreshes existing token",
            OperationId = "Token"
        )]
        [SwaggerResponse(200, "Token Response", typeof(OAuthTokenResponse))]
        [SwaggerResponse(400, "Bad Request", typeof(OAuthErrorResponse))]
        [Consumes("application/x-www-form-urlencoded")]
        public async Task<IActionResult> Token([FromForm] OAuthTokenRequest request)
        {
            try
            {
                var ipAddress = HttpContext.GetClientIpAddress();
                // Check if IP is banned before processing
                if (securityService.IsIpBanned(ipAddress))
                {
                    var banEnd = securityService.GetIpBanEndTime(ipAddress);
                    logger.LogWarning("OAuth", $"IP {ipAddress} is banned until {banEnd} - denying userinfo request");
                    return Unauthorized(new { error = "ip_banned", error_description = $"IP address banned until {banEnd}" });
                }

                logger.Log("OAuth", $"Token request: grant_type={request.GrantType}, client_id={request.ClientId}");

                if (request.GrantType == "authorization_code")
                {
                    var (isValid, tokenResponse, error, errorDescription) = await authorizationService.ExchangeAuthorizationCodeAsync(request);
                    if (!isValid)
                    {
                        logger.LogWarning("OAuth", $"Authorization code exchange failed: {error} - {errorDescription}");
                        return BadRequest(new OAuthErrorResponse
                        {
                            Error = error!,
                            ErrorDescription = errorDescription
                        });
                    }

                    logger.Log("OAuth", $"Token issued for client {request.ClientId}");
                    return Ok(tokenResponse);
                }
                else if (request.GrantType == "refresh_token")
                {
                    var (isValid, tokenResponse, error, errorDescription) = await authorizationService.RefreshTokenAsync(request);
                    if (!isValid)
                    {
                        logger.LogWarning("OAuth", $"Token refresh failed: {error} - {errorDescription}");
                        return BadRequest(new OAuthErrorResponse
                        {
                            Error = error!,
                            ErrorDescription = errorDescription
                        });
                    }

                    logger.Log("OAuth", $"Token refreshed for client {request.ClientId}");
                    return Ok(tokenResponse);
                }
                else
                {
                    logger.LogWarning("OAuth", $"Unsupported grant type: {request.GrantType}");
                    return BadRequest(new OAuthErrorResponse
                    {
                        Error = "unsupported_grant_type",
                        ErrorDescription = $"Grant type '{request.GrantType}' is not supported"
                    });
                }
            }
            catch (Exception ex)
            {
                logger.LogError("OAuth", $"Error in token endpoint: {ex.Message}", ex);
                return BadRequest(new OAuthErrorResponse
                {
                    Error = "server_error",
                    ErrorDescription = "Internal server error"
                });
            }
        }

        /// <summary>
        /// OAuth UserInfo endpoint - GET /oauth/userinfo
        /// </summary>
        /// <returns>User information</returns>
        /// <response code="200">User information</response>
        /// <response code="401">Invalid or missing access token</response>
        [HttpGet("userinfo")]
        [HttpPost("userinfo")]
        [SwaggerOperation(
            Summary = "OAuth UserInfo Endpoint",
            Description = "Returns user information for valid access token",
            OperationId = "UserInfo"
        )]
        [SwaggerResponse(200, "User Information", typeof(object))]
        [SwaggerResponse(401, "Unauthorized")]
        public async Task<IActionResult> UserInfo()
        {
            try
            {
                var ipAddress = HttpContext.GetClientIpAddress();

                // Check if IP is banned before processing
                if (securityService.IsIpBanned(ipAddress))
                {
                    var banEnd = securityService.GetIpBanEndTime(ipAddress);
                    logger.LogWarning("OAuth", $"IP {ipAddress} is banned until {banEnd} - denying userinfo request");
                    return Unauthorized(new { error = "ip_banned", error_description = $"IP address banned until {banEnd}" });
                }

                // Extract access token from Authorization header
                var authHeader = Request.Headers["Authorization"].ToString();
                if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer "))
                {
                    // Record unauthorized access attempt
                    _ = securityService.RecordFailedAttempt(null, ipAddress);
                    return Unauthorized(new { error = "invalid_token", error_description = "Missing or invalid access token" });
                }

                var accessToken = authHeader.Substring("Bearer ".Length);
                var userInfo = await authorizationService.GetUserInfoAsync(accessToken);

                if (userInfo == null)
                {
                    // Record failed attempt for invalid token
                    _ = securityService.RecordFailedAttempt(null, ipAddress);
                    return Unauthorized(new { error = "invalid_token", error_description = "Invalid access token" });
                }

                // Clear IP ban on successful OAuth authentication
                _ = securityService.UnbanIpAddress(ipAddress, "Auto");
                logger.Log("OAuth", $"IP ban cleared for {ipAddress} after successful OAuth userinfo request");

                logger.Log("OAuth", "UserInfo request completed successfully");
                return Ok(userInfo);
            }
            catch (Exception ex)
            {
                logger.LogError("OAuth", $"Error in userinfo endpoint: {ex.Message}", ex);
                return BadRequest(new { error = "server_error", error_description = "Internal server error" });
            }
        }

        /// <summary>
        /// OAuth UserInfo endpoint - GET /oauth/userinfo
        /// </summary>
        /// <returns>User information</returns>
        /// <response code="200">User information</response>
        /// <response code="401">Invalid or missing access token</response>
        [HttpGet("userinfo/emails")]
        [HttpPost("userinfo/emails")]
        [SwaggerOperation(
            Summary = "OAuth UserInfo emails Endpoint",
            Description = "Returns user emails information for valid access token",
            OperationId = "UserInfoEmails"
        )]
        [SwaggerResponse(200, "User Emails Information", typeof(object))]
        [SwaggerResponse(401, "Unauthorized")]
        public async Task<IActionResult> UserInfoEmails()
        {
            try
            {
                var ipAddress = HttpContext.GetClientIpAddress();

                // Check if IP is banned before processing
                if (securityService.IsIpBanned(ipAddress))
                {
                    var banEnd = securityService.GetIpBanEndTime(ipAddress);
                    logger.LogWarning("OAuth", $"IP {ipAddress} is banned until {banEnd} - denying userinfo/emails request");
                    return Unauthorized(new { error = "ip_banned", error_description = $"IP address banned until {banEnd}" });
                }

                // Extract access token from Authorization header
                var authHeader = Request.Headers["Authorization"].ToString();
                if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer "))
                {
                    // Record unauthorized access attempt
                    _ = securityService.RecordFailedAttempt(null, ipAddress);
                    return Unauthorized(new { error = "invalid_token", error_description = "Missing or invalid access token" });
                }

                var accessToken = authHeader.Substring("Bearer ".Length);
                var userInfo = await authorizationService.GetUserInfoAsync(accessToken);

                if (userInfo == null)
                {
                    // Record failed attempt for invalid token
                    _ = securityService.RecordFailedAttempt(null, ipAddress);
                    return Unauthorized(new { error = "invalid_token", error_description = "Invalid access token" });
                }

                var userNameModel = (Dictionary<string, object>)userInfo;

                if (userNameModel == null)
                {
                    // Record failed attempt for invalid token data
                    _ = securityService.RecordFailedAttempt(null, ipAddress);
                    return Unauthorized(new { error = "invalid_token", error_description = "Invalid access token" });
                }

                var email = userNameModel.TryGetValue("email", out var emailValue) ? emailValue?.ToString() : null;
                var emailVerified = userNameModel.TryGetValue("email_verified", out var emailVerifiedValue) ? emailVerifiedValue?.ToString() : null;

                // Clear IP ban on successful OAuth authentication
                _ = securityService.UnbanIpAddress(ipAddress, "Auto");
                logger.Log("OAuth", $"IP ban cleared for {ipAddress} after successful OAuth userinfo/emails request");

                logger.Log("OAuth", "UserInfoEmails request completed successfully");
                return Ok(new[]
                {
                    new {
                        email = email,
                        primary = true,
                        verified = emailVerifiedValue
                    }
                });
            }
            catch (Exception ex)
            {
                logger.LogError("OAuth", $"Error in userinfo/emails endpoint: {ex.Message}", ex);
                return BadRequest(new { error = "server_error", error_description = "Internal server error" });
            }
        }

        /// <summary>
        /// OAuth Token Revocation endpoint - POST /oauth/revoke
        /// </summary>
        /// <param name="token">Token to revoke</param>
        /// <param name="token_type_hint">Type hint for the token</param>
        /// <returns>Success response</returns>
        /// <response code="200">Token revoked successfully</response>
        [HttpPost("revoke")]
        [SwaggerOperation(
            Summary = "OAuth Token Revocation Endpoint",
            Description = "Revokes an access token or refresh token",
            OperationId = "RevokeToken"
        )]
        [SwaggerResponse(200, "Token revoked successfully")]
        [Consumes("application/x-www-form-urlencoded")]
        public async Task<IActionResult> Revoke([FromForm] string token, [FromForm] string? token_type_hint = null)
        {
            try
            {
                var ipAddress = HttpContext.GetClientIpAddress();
                // Check if IP is banned before processing
                if (securityService.IsIpBanned(ipAddress))
                {
                    var banEnd = securityService.GetIpBanEndTime(ipAddress);
                    logger.LogWarning("OAuth", $"IP {ipAddress} is banned until {banEnd} - denying userinfo request");
                    return Unauthorized(new { error = "ip_banned", error_description = $"IP address banned until {banEnd}" });
                }

                logger.Log("OAuth", "Token revocation request");

                var success = await authorizationService.RevokeTokenAsync(token);

                if (success)
                {
                    logger.Log("OAuth", "Token revoked successfully");
                }
                else
                {
                    logger.LogWarning("OAuth", "Token not found for revocation");
                }

                // Always return 200 OK as per RFC 7009
                return Ok();
            }
            catch (Exception ex)
            {
                logger.LogError("OAuth", $"Error in revoke endpoint: {ex.Message}", ex);
                return Ok(); // Still return 200 OK as per spec
            }
        }

        /// <summary>
        /// OAuth Discovery endpoint - GET /oauth/.well-known/oauth-authorization-server
        /// </summary>
        /// <returns>OAuth server metadata</returns>
        /// <response code="200">OAuth server metadata</response>
        [HttpGet(".well-known/oauth-authorization-server")]
        [SwaggerOperation(
            Summary = "OAuth Discovery Endpoint",
            Description = "Returns OAuth 2.0 Authorization Server metadata",
            OperationId = "Discovery"
        )]
        [SwaggerResponse(200, "OAuth Server Metadata")]
        public IActionResult Discovery()
        {
            var ipAddress = HttpContext.GetClientIpAddress();
            // Check if IP is banned before processing
            if (securityService.IsIpBanned(ipAddress))
            {
                var banEnd = securityService.GetIpBanEndTime(ipAddress);
                logger.LogWarning("OAuth", $"IP {ipAddress} is banned until {banEnd} - denying userinfo request");
                return Unauthorized(new { error = "ip_banned", error_description = $"IP address banned until {banEnd}" });
            }

            var baseUrl = $"{Request.Scheme}://{Request.Host}";

            var supportedAlgorithms = new List<string>();
            if (sharedKeys.RSAIsAvailable)
            {
                supportedAlgorithms.Add("RS256");
            }
            else if (sharedKeys.HMAC != null)
            {
                supportedAlgorithms.Add("HS256");
            }

            var metadata = new
            {
                issuer = baseUrl,
                authorization_endpoint = $"{baseUrl}/oauth/authorize",
                token_endpoint = $"{baseUrl}/oauth/token",
                userinfo_endpoint = $"{baseUrl}/oauth/userinfo",
                revocation_endpoint = $"{baseUrl}/oauth/revoke",

                response_types_supported = new[] { "code" },
                grant_types_supported = new[] { "authorization_code", "refresh_token" },
                code_challenge_methods_supported = new[] { "S256", "plain" },

                scopes_supported = clientService.GetAvailableScopes().Select(s => s.Name).ToArray(),

                token_endpoint_auth_methods_supported = new[] { "client_secret_post", "client_secret_basic" },

                subject_types_supported = new[] { "public" },
                id_token_signing_alg_values_supported = supportedAlgorithms.ToArray()
            };

            return Ok(metadata);
        }

        /// <summary>
        /// OAuth Consent page - GET /oauth/consent
        /// </summary>
        /// <param name="client_id">Client ID</param>
        /// <param name="scope">Requested scopes</param>
        /// <param name="state">OAuth state parameter</param>
        /// <returns>Consent page information</returns>
        /// <response code="200">Consent page data</response>
        /// <response code="400">Invalid request</response>
        [HttpGet("consent")]
        [Authorize]
        [SwaggerOperation(
            Summary = "OAuth Consent Page",
            Description = "Returns consent page information for OAuth authorization",
            OperationId = "Consent"
        )]
        [SwaggerResponse(200, "Consent page data")]
        [SwaggerResponse(400, "Bad Request")]
        public async Task<IActionResult> Consent([FromQuery] string client_id, [FromQuery] string scope, [FromQuery] string state)
        {
            try
            {
                var ipAddress = HttpContext.GetClientIpAddress();
                // Check if IP is banned before processing
                if (securityService.IsIpBanned(ipAddress))
                {
                    var banEnd = securityService.GetIpBanEndTime(ipAddress);
                    logger.LogWarning("OAuth", $"IP {ipAddress} is banned until {banEnd} - denying userinfo request");
                    return Unauthorized(new { error = "ip_banned", error_description = $"IP address banned until {banEnd}" });
                }

                var client = await clientService.GetClientAsync(client_id);
                if (client == null)
                {
                    return BadRequest("Invalid client");
                }

                var scopes = scope?.Split(' ') ?? Array.Empty<string>();
                var scopeDetails = clientService.GetAvailableScopes()
                    .Where(s => scopes.Contains(s.Name))
                    .ToList();

                var model = new
                {
                    Client = client,
                    Scopes = scopeDetails,
                    State = state
                };

                return Ok(model);
            }
            catch (Exception ex)
            {
                logger.LogError("OAuth", $"Error in consent endpoint: {ex.Message}", ex);
                return BadRequest("Error processing consent request");
            }
        }

        /// <summary>
        /// OAuth Consent form submission - POST /oauth/consent
        /// </summary>
        /// <param name="client_id">Client ID</param>
        /// <param name="approved_scopes">Approved scopes</param>
        /// <param name="state">OAuth state parameter</param>
        /// <param name="approved">Whether user approved the request</param>
        /// <returns>Redirect to callback URL</returns>
        /// <response code="302">Redirect to callback URL</response>
        /// <response code="400">Bad Request</response>
        [HttpPost("consent")]
        [Authorize]
        [SwaggerOperation(
            Summary = "OAuth Consent Submission",
            Description = "Processes OAuth consent form submission",
            OperationId = "ConsentPost"
        )]
        [SwaggerResponse(302, "Redirect to callback URL")]
        [SwaggerResponse(400, "Bad Request")]
        [Consumes("application/x-www-form-urlencoded")]
        public async Task<IActionResult> ConsentPost([FromForm] string client_id, [FromForm] string[] approved_scopes, [FromForm] string state, [FromForm] bool approved = false)
        {
            try
            {
                var ipAddress = HttpContext.GetClientIpAddress();
                // Check if IP is banned before processing
                if (securityService.IsIpBanned(ipAddress))
                {
                    var banEnd = securityService.GetIpBanEndTime(ipAddress);
                    logger.LogWarning("OAuth", $"IP {ipAddress} is banned until {banEnd} - denying userinfo request");
                    return Unauthorized(new { error = "ip_banned", error_description = $"IP address banned until {banEnd}" });
                }

                if (!approved)
                {
                    // User denied consent
                    var pendingRequest = GetPendingAuthorizationRequest();
                    if (pendingRequest != null)
                    {
                        var errorUrl = $"{pendingRequest.RedirectUri}?error=access_denied&state={Uri.EscapeDataString(state)}";
                        return Redirect(errorUrl);
                    }
                    return BadRequest("Access denied");
                }

                // Get pending authorization request
                var request = GetPendingAuthorizationRequest();
                if (request == null)
                {
                    return BadRequest("No pending authorization request");
                }

                var currentUser = await userManager.GetUserAsync(User);
                if (currentUser == null)
                {
                    return BadRequest("User not found");
                }

                return await CreateAuthorizationResponse(request, currentUser.Id!, approved_scopes.ToList());
            }
            catch (Exception ex)
            {
                logger.LogError("OAuth", $"Error in consent post endpoint: {ex.Message}", ex);
                return BadRequest("Error processing consent");
            }
        }

        // Private helper methods
        private async Task<IActionResult> CreateAuthorizationResponse(OAuthAuthorizationRequest request, string userId, List<string> approvedScopes)
        {
            try
            {
                // Create authorization code
                var authCode = await authorizationService.CreateAuthorizationCodeAsync(
                    request.ClientId,
                    userId,
                    request.RedirectUri,
                    approvedScopes,
                    request.CodeChallenge,
                    request.CodeChallengeMethod,
                    request.Nonce);

                // Clear pending request from session
                HttpContext.Session.Remove("oauth_pending_request");

                // Build redirect URL
                var redirectUrl = $"{request.RedirectUri}?code={Uri.EscapeDataString(authCode.Code)}&state={Uri.EscapeDataString(request.State)}";

                logger.Log("OAuth", $"Authorization successful, redirecting to: {request.RedirectUri}");
                return Redirect(redirectUrl);
            }
            catch (Exception ex)
            {
                logger.LogError("OAuth", $"Error creating authorization response: {ex.Message}", ex);
                var errorUrl = $"{request.RedirectUri}?error=server_error&error_description={Uri.EscapeDataString("Internal server error")}&state={Uri.EscapeDataString(request.State)}";
                return Redirect(errorUrl);
            }
        }

        private OAuthAuthorizationRequest? GetPendingAuthorizationRequest()
        {
            var pendingRequestJson = HttpContext.Session.GetString("oauth_pending_request");
            if (string.IsNullOrEmpty(pendingRequestJson))
            {
                return null;
            }

            try
            {
                return System.Text.Json.JsonSerializer.Deserialize<OAuthAuthorizationRequest>(pendingRequestJson);
            }
            catch
            {
                return null;
            }
        }
    }
}
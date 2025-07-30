using Authly.Authorization;
using Authly.Extension;
using Authly.Models;
using Authly.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;

namespace Authly.Controllers
{
    /// <summary>
    /// OIDC Discovery Controller - poskytuje metadata o OIDC provideru
    /// </summary>
    [ApiController]
    [Route(".well-known")]
    public class OidcDiscoveryController(
        IOptions<OidcOptions> oidcOptions,
        IApplicationLogger logger,
        ISecurityService securityService,
        ISharedKeys sharedKeys) : ControllerBase
    {

        /// <summary>
        /// OIDC Discovery endpoint - vrací metadata o OIDC provideru
        /// RFC: https://openid.net/specs/openid-connect-discovery-1_0.html
        /// </summary>
        [HttpGet("openid-configuration")]
        [AllowAnonymous]
        public IActionResult GetOpenIdConfiguration()
        {
            try
            {
                if (!oidcOptions.Value.Enabled)
                {
                    return NotFound(new { error = "oidc_disabled", error_description = "OIDC provider is disabled" });
                }

                var ipAddress = HttpContext.GetClientIpAddress();

                // Check if IP is banned before processing
                if (securityService.IsIpBanned(ipAddress))
                {
                    var banEnd = securityService.GetIpBanEndTime(ipAddress);
                    logger.LogWarning(nameof(OidcConnectController),$"IP {ipAddress} is banned until {banEnd} - denying userinfo request");
                    return Unauthorized(new { error = "ip_banned", error_description = $"IP address banned until {banEnd}" });
                }

                var baseUrl = $"{Request.Scheme}://{Request.Host}";

                var supportedAlgorithms = new List<string>();
                if (sharedKeys.RSAIsAvailable)
                {
                    supportedAlgorithms.Add("RS256");
                }
                if (sharedKeys.HMAC != null)
                {
                    supportedAlgorithms.Add("HS256");
                }

                var configuration = new
                {
                    issuer = oidcOptions.Value.Issuer ?? baseUrl,
                    authorization_endpoint = $"{baseUrl}/connect/authorize",
                    token_endpoint = $"{baseUrl}/connect/token",
                    userinfo_endpoint = $"{baseUrl}/connect/userinfo",
                    end_session_endpoint = $"{baseUrl}/connect/endsession",
                    jwks_uri = $"{baseUrl}/.well-known/jwks.json",
                    response_types_supported = new[]
                    {
                        "code",
                        "id_token",
                        "code id_token"
                    },
                    subject_types_supported = new[] { "public" },
                    id_token_signing_alg_values_supported = supportedAlgorithms.ToArray(),
                    token_endpoint_auth_signing_alg_values_supported = supportedAlgorithms.ToArray(),
                    scopes_supported = new[]
                    {
                        "openid",
                        "profile",
                        "email",
                        "offline_access"
                    },
                    token_endpoint_auth_methods_supported = new[]
                    {
                        "client_secret_post",
                        "client_secret_basic",
                        "none"
                    },
                    claims_supported = new[]
                    {
                        "sub",
                        "iss",
                        "aud",
                        "exp",
                        "iat",
                        "auth_time",
                        "nonce",
                        "name",
                        "given_name",
                        "family_name",
                        "preferred_username",
                        "email",
                        "email_verified",
                        "role",
                        "roles"
                    },
                    grant_types_supported = new[]
                    {
                        "authorization_code",
                        "refresh_token"
                    },
                    response_modes_supported = new[]
                    {
                        "query",
                        "form_post"
                    },
                    code_challenge_methods_supported = new[]
                    {
                        "S256",
                        "plain"
                    },
                    request_uri_parameter_supported = false,
                    request_parameter_supported = false,
                    require_request_uri_registration = false,
                    claims_parameter_supported = false,
                };

                return Ok(configuration);
            }
            catch (Exception ex)
            {
                logger.LogError(nameof(OidcDiscoveryController), "Error generating OpenID configuration", ex);
                return StatusCode(500, new { error = "server_error", error_description = "Internal server error" });
            }
        }

        /// <summary>
        /// JWKS endpoint - vrací veřejné klíče pro ověření JWT tokenů
        /// RFC: https://tools.ietf.org/html/rfc7517
        /// </summary>
        [HttpGet("jwks.json")]
        [AllowAnonymous]
        public IActionResult GetJwks()
        {
            try
            {
                if (!oidcOptions.Value.Enabled)
                {
                    return NotFound(new { error = "oidc_disabled" });
                }

                var ipAddress = HttpContext.GetClientIpAddress();

                // Check if IP is banned before processing
                if (securityService.IsIpBanned(ipAddress))
                {
                    var banEnd = securityService.GetIpBanEndTime(ipAddress);
                    logger.LogWarning(nameof(OidcConnectController),$"IP {ipAddress} is banned until {banEnd} - denying userinfo request");
                    return Unauthorized(new { error = "ip_banned", error_description = $"IP address banned until {banEnd}" });
                }
                if (!sharedKeys.RSAIsAvailable || sharedKeys.RSA == null)
                {
                    return Ok(new { keys = new object[0] });
                }
                try
                {
                    var rsa = sharedKeys.RSA;
                    var parameters = rsa.ExportParameters(false);

                    var jwks = new
                    {
                        keys = new[]
                        {
                            new
                            {
                                kty = "RSA",
                                use = "sig",
                                kid = oidcOptions.Value.SigningKey,
                                alg = "RS256",
                                n = Base64UrlEncode(parameters.Modulus!),
                                e = Base64UrlEncode(parameters.Exponent!)
                            }
                        }
                    };
                    return Ok(jwks);
                }
                catch (Exception ex)
                {
                    logger.LogError(nameof(OidcDiscoveryController), "Error generating JWKS", ex);
                    throw;
                }                
            }
            catch (Exception ex)
            {
                logger.LogError(nameof(OidcDiscoveryController), "Error generating JWKS", ex);
                return StatusCode(500, new { error = "server_error" });
            }
        }

        private static string Base64UrlEncode(byte[] input)
        {
            return Convert.ToBase64String(input)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');
        }
    }

    /// <summary>
    /// OIDC Connect Controller - hlavní OIDC endpointy
    /// </summary>
    [ApiController]
    [Route("connect")]
    public class OidcConnectController(
        IOptions<OidcOptions> oidcOptions,
        CustomUserManager userManager,
        CustomSignInManager signInManager,
        ISecurityService securityService,
        IOAuthClientService clientService,
        IApplicationLogger logger,
        IOAuthAuthorizationService authorizationService
        ) : ControllerBase
    {

        /// <summary>
        /// Authorization endpoint - začátek OIDC Authorization Code flow
        /// RFC: https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
        /// </summary>
        [HttpGet("authorize")]
        [AllowAnonymous]
        public async Task<IActionResult> Authorize([FromQuery] OAuthAuthorizationRequest authRequest)
        {
            try
            {
                if (!oidcOptions.Value.Enabled)
                {
                    return BadRequest(new { error = "server_error", error_description = "OIDC is disabled" });
                }

                var ipAddress = HttpContext.GetClientIpAddress();

                // Check if IP is banned before processing
                if (securityService.IsIpBanned(ipAddress))
                {
                    var banEnd = securityService.GetIpBanEndTime(ipAddress);
                    logger.LogWarning(nameof(OidcConnectController),$"IP {ipAddress} is banned until {banEnd} - denying authorization request");
                    return Unauthorized(new { error = "ip_banned", error_description = $"IP address banned until {banEnd}" });
                }

                var (isValid, error, errorDescription) = await authorizationService.ValidateAuthorizationRequestAsync(authRequest);

                if (!isValid)
                {
                    logger.LogWarning(nameof(OidcConnectController),$"Authorization request validation failed: {error} - {errorDescription}");

                    // Pokud je redirect_uri validní, přesměruj s chybou, jinak vrať BadRequest
                    if (!string.IsNullOrEmpty(authRequest.RedirectUri) && await clientService.IsValidRedirectUriAsync(authRequest.ClientId, authRequest.RedirectUri))
                    {
                        var errorUrl = BuildErrorRedirectUrl(authRequest.RedirectUri, error!, errorDescription, authRequest.State);
                        return Redirect(errorUrl);
                    }

                    return BadRequest(new { error, error_description = errorDescription });
                }

                // Validace specifická pro OIDC
                if (authRequest.Scope?.Split(' ')?.Contains("openid") != true)
                {
                    var errorUrl = BuildErrorRedirectUrl(authRequest.RedirectUri, "invalid_scope", "Scope must contain 'openid'", authRequest.State);
                    return Redirect(errorUrl);
                }

                // Check if user is authenticated
                if (User.Identity?.IsAuthenticated != true)
                {
                    // Redirect to login page
                    var returnUrl = Request.GetEncodedUrl();
                    var loginUrl = $"/Login?returnUrl={Uri.EscapeDataString(returnUrl)}";
                    return Redirect(loginUrl);
                }

                // Get the authenticated user
                var user = await userManager.GetUserAsync(User);
                if (user == null)
                {
                    logger.LogError(nameof(OidcConnectController),"Authenticated user not found in database");
                    var errorUrl = BuildErrorRedirectUrl(authRequest.RedirectUri, "server_error", "User not found", authRequest.State);
                    return Redirect(errorUrl);
                }

                // Vytvoř authorization code
                var requestedScopes = authRequest.Scope.Split(' ').ToList();
                var authCode = await authorizationService.CreateAuthorizationCodeAsync(
                    authRequest.ClientId,
                    user.Id!,
                    authRequest.RedirectUri,
                    requestedScopes,
                    authRequest.CodeChallenge,
                    authRequest.CodeChallengeMethod,
                    authRequest.Nonce);

                // Redirect s authorization code
                var redirectUrl = BuildSuccessRedirectUrl(authRequest.RedirectUri, authCode.Code, authRequest.State);

                logger.Log(nameof(OidcConnectController),$"Authorization code issued for client {authRequest.ClientId}, user {user.Id}");
                return Redirect(redirectUrl);
            }
            catch (Exception ex)
            {
                logger.LogError(nameof(OidcConnectController), "Error in authorization endpoint", ex);

                // Pokusíme se přesměrovat s chybou, pokud máme validní redirect_uri
                if (!string.IsNullOrEmpty(authRequest.RedirectUri) && await clientService.IsValidRedirectUriAsync(authRequest.ClientId, authRequest.RedirectUri))
                {
                    var errorUrl = BuildErrorRedirectUrl(authRequest.RedirectUri, "server_error", "Internal server error", authRequest.State);
                    return Redirect(errorUrl);
                }

                return StatusCode(500, new { error = "server_error", error_description = "Internal server error" });
            }
        }

        /// <summary>
        /// Token endpoint - creates tokens from authorization code
        /// RFC: https://openid.net/specs/openid-connect-core-1_0.html#TokenRequest
        /// </summary>
        [HttpPost("token")]
        [AllowAnonymous]
        public async Task<IActionResult> Token([FromForm] OAuthTokenRequest request)
        {
            try
            {
                if (!oidcOptions.Value.Enabled)
                {
                    return BadRequest(new { error = "server_error", error_description = "OIDC is disabled" });
                }

                var ipAddress = HttpContext.GetClientIpAddress();
                // Check if IP is banned before processing
                if (securityService.IsIpBanned(ipAddress))
                {
                    var banEnd = securityService.GetIpBanEndTime(ipAddress);
                    logger.LogWarning(nameof(OidcConnectController),$"IP {ipAddress} is banned until {banEnd} - denying userinfo request");
                    return Unauthorized(new { error = "ip_banned", error_description = $"IP address banned until {banEnd}" });
                }

                logger.Log(nameof(OidcConnectController), $"Token request: grant_type={request.GrantType}, client_id={request.ClientId}");

                if (request.GrantType == "authorization_code")
                {
                    var (isValid, tokenResponse, error, errorDescription) = await authorizationService.ExchangeAuthorizationCodeAsync(request);
                    if (!isValid)
                    {
                        logger.LogWarning(nameof(OidcConnectController),$"Authorization code exchange failed: {error} - {errorDescription}");
                        return BadRequest(new OAuthErrorResponse
                        {
                            Error = error!,
                            ErrorDescription = errorDescription
                        });
                    }

                    logger.Log(nameof(OidcConnectController),$"Token issued for client {request.ClientId}");
                    return Ok((OidcTokenResponse)tokenResponse);
                }
                else if (request.GrantType == "refresh_token")
                {
                    var (isValid, tokenResponse, error, errorDescription) = await authorizationService.RefreshTokenAsync(request);
                    if (!isValid)
                    {
                        logger.LogWarning(nameof(OidcConnectController),$"Token refresh failed: {error} - {errorDescription}");
                        return BadRequest(new OAuthErrorResponse
                        {
                            Error = error!,
                            ErrorDescription = errorDescription
                        });
                    }

                    logger.Log(nameof(OidcConnectController),$"Token refreshed for client {request.ClientId}");
                    return Ok((OidcTokenResponse)tokenResponse);
                }
                else
                {
                    logger.LogWarning(nameof(OidcConnectController),$"Unsupported grant type: {request.GrantType}");
                    return BadRequest(new OAuthErrorResponse
                    {
                        Error = "unsupported_grant_type",
                        ErrorDescription = $"Grant type '{request.GrantType}' is not supported"
                    });
                }
            }
            catch (Exception ex)
            {
                logger.LogError(nameof(OidcConnectController), "Error in token endpoint", ex);
                return StatusCode(500, new { error = "server_error", error_description = "Internal server error" });
            }
        }

        /// <summary>
        /// UserInfo endpoint - vrací informace o uživateli
        /// RFC: https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
        /// </summary>
        [HttpGet("userinfo")]
        [Authorize(AuthenticationSchemes = "OidcJwt")]
        public async Task<IActionResult> UserInfo()
        {
            try
            {
                if (!oidcOptions.Value.Enabled)
                {
                    return BadRequest(new { error = "server_error", error_description = "OIDC is disabled" });
                }

                var ipAddress = HttpContext.GetClientIpAddress();

                // Check if IP is banned before processing
                if (securityService.IsIpBanned(ipAddress))
                {
                    var banEnd = securityService.GetIpBanEndTime(ipAddress);
                    logger.LogWarning(nameof(OidcConnectController),$"IP {ipAddress} is banned until {banEnd} - denying userinfo request");
                    return Unauthorized(new { error = "ip_banned", error_description = $"IP address banned until {banEnd}" });
                }

                var authHeader = Request.Headers["Authorization"].FirstOrDefault();
                if (authHeader?.StartsWith("Bearer ") != true)
                    return Unauthorized(new { error = "invalid_token", error_description = "Missing or invalid authorization header" });

                var token = authHeader.Substring("Bearer ".Length);

                var (isValid, principal, clientId) = await authorizationService.ValidateAccessTokenAsync(token);
                if (!isValid)
                    return Unauthorized(new { error = "invalid_token", error_description = "Invalid or expired access token" });

                var scopes = principal.FindFirst("scope")?.Value?.Split(' ') ?? Array.Empty<string>();
                if (!scopes.Contains("openid"))
                    return BadRequest(new { error = "insufficient_scope", error_description = "Token does not contain required 'openid' scope" });

                var userInfo = await authorizationService.GetUserInfoAsync(token);
                if (userInfo == null)
                    return Unauthorized(new { error = "invalid_token", error_description = "Unable to retrieve user information" });

                return Ok(userInfo);
            }
            catch (Exception ex)
            {
                logger.LogError(nameof(OidcConnectController), "Error in userinfo endpoint", ex);
                return StatusCode(500, new { error = "server_error", error_description = "Internal server error" });
            }
        }

        /// <summary>
        /// End session endpoint - odhlášení
        /// RFC: https://openid.net/specs/openid-connect-rpinitiated-1_0.html
        /// </summary>
        [HttpGet("endsession")]
        [AllowAnonymous]
        public async Task<IActionResult> EndSession(
            [FromQuery] string? post_logout_redirect_uri,
            [FromQuery] string? id_token_hint,
            [FromQuery] string? state)
        {
            try
            {
                if (!oidcOptions.Value.Enabled)
                {
                    return BadRequest(new { error = "server_error", error_description = "OIDC is disabled" });
                }
                if (!string.IsNullOrEmpty(id_token_hint))
                {
                    _ = await authorizationService.RevokeTokenAsync(id_token_hint);
                }

                // Sign out the user
                if (User.Identity?.IsAuthenticated == true)
                {
                    await signInManager.SignOutAsync();
                }

                if (!string.IsNullOrEmpty(post_logout_redirect_uri))
                {
                    var redirectUrl = post_logout_redirect_uri;
                    if (!string.IsNullOrEmpty(state))
                    {
                        var separator = redirectUrl.Contains('?') ? "&" : "?";
                        redirectUrl += $"{separator}state={Uri.EscapeDataString(state)}";
                    }
                    return Redirect(redirectUrl);
                }

                return Ok(new { message = "Sign out successful" });
            }
            catch (Exception ex)
            {
                logger.LogError(nameof(OidcConnectController), "Error in endsession endpoint", ex);
                return StatusCode(500, new { error = "server_error", error_description = "Internal server error" });
            }
        }

        #region Private Helper Methods
        private static string BuildSuccessRedirectUrl(string redirectUri, string code, string? state)
        {
            var uriBuilder = new UriBuilder(redirectUri);
            var query = System.Web.HttpUtility.ParseQueryString(uriBuilder.Query);

            query["code"] = code;
            if (!string.IsNullOrEmpty(state))
            {
                query["state"] = state;
            }

            uriBuilder.Query = query.ToString();
            return uriBuilder.ToString();
        }

        private static string BuildErrorRedirectUrl(string redirectUri, string error, string? errorDescription, string? state)
        {
            var uriBuilder = new UriBuilder(redirectUri);
            var query = System.Web.HttpUtility.ParseQueryString(uriBuilder.Query);

            query["error"] = error;
            if (!string.IsNullOrEmpty(errorDescription))
            {
                query["error_description"] = errorDescription;
            }
            if (!string.IsNullOrEmpty(state))
            {
                query["state"] = state;
            }

            uriBuilder.Query = query.ToString();
            return uriBuilder.ToString();
        }

        #endregion
    }
}
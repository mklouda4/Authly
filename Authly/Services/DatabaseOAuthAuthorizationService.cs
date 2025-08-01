﻿using Authly.Models;
using Authly.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using System.Security.Cryptography;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Microsoft.Extensions.Options;
using Authly.Configuration;

namespace Authly.Services
{
    /// <summary>
    /// Interface for OAuth Authorization Server service
    /// </summary>
    public interface IOAuthAuthorizationService
    {
        /// <summary>
        /// Handle OAuth authorization request
        /// </summary>
        Task<(bool IsValid, string? Error, string? ErrorDescription)> ValidateAuthorizationRequestAsync(OAuthAuthorizationRequest request);

        /// <summary>
        /// Create authorization code
        /// </summary>
        Task<OAuthAuthorizationCode> CreateAuthorizationCodeAsync(string clientId, string userId, string redirectUri, List<string> scopes, string? codeChallenge, string? codeChallengeMethod, string? nonce);

        /// <summary>
        /// Exchange authorization code for tokens
        /// </summary>
        Task<(bool IsValid, OAuthTokenResponse? TokenResponse, string? Error, string? ErrorDescription)> ExchangeAuthorizationCodeAsync(OAuthTokenRequest request);

        /// <summary>
        /// Refresh access token
        /// </summary>
        Task<(bool IsValid, OAuthTokenResponse? TokenResponse, string? Error, string? ErrorDescription)> RefreshTokenAsync(OAuthTokenRequest request);

        /// <summary>
        /// Validate access token
        /// </summary>
        Task<(bool IsValid, ClaimsPrincipal? Principal, string? ClientId)> ValidateAccessTokenAsync(string accessToken);

        /// <summary>
        /// Revoke token
        /// </summary>
        Task<bool> RevokeTokenAsync(string token);

        /// <summary>
        /// Get user info from access token
        /// </summary>
        Task<object?> GetUserInfoAsync(string accessToken);

        /// <summary>
        /// Clean up expired and used tokens (maintenance operation)
        /// </summary>
        Task CleanupExpiredTokensAsync();
    }
    /// <summary>
    /// Database-based OAuth authorization service
    /// </summary>
    public class DatabaseOAuthAuthorizationService : IOAuthAuthorizationService
    {
        private readonly AuthlyDbContext _context;
        private readonly IApplicationLogger _logger;
        private readonly IOAuthClientService _clientService;
        private readonly UserManager<User> _userManager;
        private readonly ISharedKeys? _sharedKeys;
        private readonly IOptions<OidcOptions> _oidcOptions;

        public DatabaseOAuthAuthorizationService(
            AuthlyDbContext context, 
            IApplicationLogger logger,
            IOAuthClientService clientService,
            UserManager<User> userManager,
            IConfiguration configuration,
            IOptions<OidcOptions> oidcOptions,
            ISharedKeys sharedKeys)
        {
            _context = context;
            _logger = logger;
            _clientService = clientService;
            _userManager = userManager;
            _oidcOptions = oidcOptions;
            _sharedKeys = sharedKeys;
        }

        public async Task<(bool IsValid, string? Error, string? ErrorDescription)> ValidateAuthorizationRequestAsync(OAuthAuthorizationRequest request)
        {
            // Validate client
            var client = await _clientService.GetClientAsync(request.ClientId);
            if (client == null || !client.Enabled)
            {
                return (false, "invalid_client", "Client not found or disabled");
            }

            // Validate response type
            if (request.ResponseType != "code")
            {
                return (false, "unsupported_response_type", "Only authorization code flow is supported");
            }

            // Validate redirect URI
            if (!await _clientService.IsValidRedirectUriAsync(request.ClientId, request.RedirectUri))
            {
                return (false, "invalid_redirect_uri", "Invalid redirect URI");
            }

            // Validate grant type
            if (!client.AllowedGrantTypes.Contains(OAuthGrantType.AuthorizationCode))
            {
                return (false, "unauthorized_client", "Client not authorized for authorization code grant");
            }

            // Validate PKCE if required
            if (client.RequirePkce)
            {
                if (string.IsNullOrEmpty(request.CodeChallenge))
                {
                    return (false, "invalid_request", "PKCE code challenge required");
                }

                var method = request.CodeChallengeMethod ?? "plain";
                if (method != "S256" && method != "plain")
                {
                    return (false, "invalid_request", "Invalid code challenge method");
                }

                if (method == "plain" && !client.AllowPlainTextPkce)
                {
                    return (false, "invalid_request", "Plain text PKCE not allowed");
                }
            }

            // Validate scopes
            if (!string.IsNullOrEmpty(request.Scope))
            {
                var requestedScopes = request.Scope.Split(' ');
                var invalidScopes = requestedScopes.Where(s => !client.AllowedScopes.Contains(s)).ToList();
                if (invalidScopes.Any())
                {
                    return (false, "invalid_scope", $"Invalid scopes: {string.Join(", ", invalidScopes)}");
                }
            }

            return (true, null, null);
        }

        // Authorization Codes
        public async Task<OAuthAuthorizationCode> CreateAuthorizationCodeAsync(string clientId, string userId, string redirectUri, List<string> scopes, string? codeChallenge = null, string? codeChallengeMethod = null, string? nonce = null)
        {
            try
            {
                var code = GenerateAuthorizationCode();
                var authCode = new OAuthAuthorizationCode
                {
                    Code = code,
                    ClientId = clientId,
                    UserId = userId,
                    RedirectUri = redirectUri,
                    Scopes = scopes,
                    CodeChallenge = codeChallenge,
                    CodeChallengeMethod = codeChallengeMethod,
                    Nonce = nonce,
                    CreatedUtc = DateTime.UtcNow,
                    ExpiresUtc = DateTime.UtcNow.AddMinutes(10) // 10 minutes
                };

                _context.OAuthAuthorizationCodes.Add(authCode);
                await _context.SaveChangesAsync();

                _logger.LogDebug("DatabaseOAuthAuthorizationService", $"Created authorization code for client {clientId}, user {userId}");
                return authCode;
            }
            catch (Exception ex)
            {
                _logger.LogError("DatabaseOAuthAuthorizationService", $"Error creating authorization code: {ex.Message}", ex);
                throw;
            }
        }

        public async Task<(bool IsValid, OAuthTokenResponse? TokenResponse, string? Error, string? ErrorDescription)> ExchangeAuthorizationCodeAsync(OAuthTokenRequest request)
        {
            try
            {
                // Validate client credentials
                if (!await _clientService.ValidateClientCredentialsAsync(request.ClientId, request.ClientSecret))
                {
                    return (false, null, "invalid_client", "Invalid client credentials");
                }

                // Find and validate authorization code
                var authCode = await _context.OAuthAuthorizationCodes
                    .FirstOrDefaultAsync(c => c.Code == request.Code && !c.IsUsed && !(DateTime.UtcNow > c.ExpiresUtc));

                if (authCode == null)
                {
                    return (false, null, "invalid_grant", "Invalid or expired authorization code");
                }

                // Validate client ID
                if (authCode.ClientId != request.ClientId)
                {
                    return (false, null, "invalid_grant", "Authorization code issued to different client");
                }

                // Validate redirect URI
                if (authCode.RedirectUri != request.RedirectUri)
                {
                    return (false, null, "invalid_grant", "Redirect URI mismatch");
                }

                // Validate PKCE if present
                if (!string.IsNullOrEmpty(authCode.CodeChallenge))
                {
                    if (string.IsNullOrEmpty(request.CodeVerifier))
                    {
                        return (false, null, "invalid_request", "Code verifier required");
                    }

                    var isValidPkce = ValidatePkce(authCode.CodeChallenge, authCode.CodeChallengeMethod, request.CodeVerifier);
                    if (!isValidPkce)
                    {
                        return (false, null, "invalid_grant", "Invalid code verifier");
                    }
                }

                // Mark authorization code as used
                authCode.IsUsed = true;
                await _context.SaveChangesAsync();

                // Get client and user
                var client = await _clientService.GetClientAsync(request.ClientId);
                var user = await _userManager.FindByIdAsync(authCode.UserId);
                
                if (client == null || user == null)
                {
                    return (false, null, "server_error", "Internal server error");
                }

                // Create access token
                var accessToken = await CreateAccessTokenAsync(client, user, authCode.Scopes, authCode.Nonce);
                
                // Create refresh token if allowed
                string? refreshToken = null;
                if (client.RefreshTokenLifetime.HasValue && client.AllowedGrantTypes.Contains(OAuthGrantType.RefreshToken))
                {
                    refreshToken = await CreateRefreshTokenAsync(client, user, authCode.Scopes, accessToken.TokenId);
                }

                var tokenResponse = new OAuthTokenResponse
                {
                    AccessToken = accessToken.AccessToken,
                    TokenType = "Bearer",
                    ExpiresIn = client.AccessTokenLifetime,
                    RefreshToken = refreshToken,
                    Scope = string.Join(" ", authCode.Scopes)
                };

                var isOidcFlow = authCode.Scopes.Contains("openid");
                if (isOidcFlow)
                {
                    var idToken = CreateIdToken(client, user, authCode.Scopes, authCode.Nonce);

                    tokenResponse = new OidcTokenResponse
                    {
                        AccessToken = tokenResponse.AccessToken,
                        IdToken = idToken,
                        TokenType = tokenResponse.TokenType,
                        ExpiresIn = tokenResponse.ExpiresIn,
                        RefreshToken = tokenResponse.RefreshToken,
                        Scope = tokenResponse.Scope
                    };
                }

                _logger.LogDebug("DatabaseOAuthAuthorizationService", $"Exchanged authorization code for tokens: client {request.ClientId}, user {authCode.UserId}");
                return (true, tokenResponse, null, null);
            }
            catch (Exception ex)
            {
                _logger.LogError("DatabaseOAuthAuthorizationService", $"Error exchanging authorization code: {ex.Message}", ex);
                return (false, null, "server_error", "Internal server error");
            }
        }

        public async Task<(bool IsValid, OAuthTokenResponse? TokenResponse, string? Error, string? ErrorDescription)> RefreshTokenAsync(OAuthTokenRequest request)
        {
            try
            {
                // Validate client credentials
                if (!await _clientService.ValidateClientCredentialsAsync(request.ClientId, request.ClientSecret))
                {
                    return (false, null, "invalid_client", "Invalid client credentials");
                }

                // Find refresh token
                var refreshTokenObj = await _context.OAuthRefreshTokens
                    .FirstOrDefaultAsync(t => t.RefreshToken == request.RefreshToken && !t.IsRevoked && !(DateTime.UtcNow > t.ExpiresUtc));

                if (refreshTokenObj == null)
                {
                    return (false, null, "invalid_grant", "Invalid or expired refresh token");
                }

                // Validate client
                if (refreshTokenObj.ClientId != request.ClientId)
                {
                    return (false, null, "invalid_grant", "Refresh token issued to different client");
                }

                // Get client and user
                var client = await _clientService.GetClientAsync(request.ClientId);
                var user = await _userManager.FindByIdAsync(refreshTokenObj.UserId);
                
                if (client == null || user == null)
                {
                    return (false, null, "server_error", "Internal server error");
                }

                // Revoke old tokens
                refreshTokenObj.IsRevoked = true;
                var oldAccessToken = await _context.OAuthAccessTokens
                    .FirstOrDefaultAsync(t => t.TokenId == refreshTokenObj.AccessTokenId);
                if (oldAccessToken != null)
                {
                    oldAccessToken.IsRevoked = true;
                }

                // Create new access token
                var scopes = refreshTokenObj.Scopes;
                if (!string.IsNullOrEmpty(request.Scope))
                {
                    var requestedScopes = request.Scope.Split(' ').ToList();
                    // Can only reduce scope, not expand
                    scopes = scopes.Intersect(requestedScopes).ToList();
                }

                var accessToken = await CreateAccessTokenAsync(client, user, scopes, null);
                
                // Create new refresh token
                var newRefreshToken = await CreateRefreshTokenAsync(client, user, scopes, accessToken.TokenId);

                await _context.SaveChangesAsync();

                var tokenResponse = new OAuthTokenResponse
                {
                    AccessToken = accessToken.AccessToken,
                    TokenType = "Bearer",
                    ExpiresIn = client.AccessTokenLifetime,
                    RefreshToken = newRefreshToken,
                    Scope = string.Join(" ", scopes)
                };

                var isOidcFlow = scopes.Contains("openid");
                if (isOidcFlow)
                {
                    var idToken = CreateIdToken(client, user, scopes, null);

                    tokenResponse = new OidcTokenResponse
                    {
                        AccessToken = tokenResponse.AccessToken,
                        IdToken = idToken,
                        TokenType = tokenResponse.TokenType,
                        ExpiresIn = tokenResponse.ExpiresIn,
                        RefreshToken = tokenResponse.RefreshToken,
                        Scope = tokenResponse.Scope
                    };
                }

                _logger.LogDebug("DatabaseOAuthAuthorizationService", $"Refreshed tokens: client {request.ClientId}, user {refreshTokenObj.UserId}");
                return (true, tokenResponse, null, null);
            }
            catch (Exception ex)
            {
                _logger.LogError("DatabaseOAuthAuthorizationService", $"Error refreshing token: {ex.Message}", ex);
                return (false, null, "server_error", "Internal server error");
            }
        }

        public async Task<(bool IsValid, ClaimsPrincipal? Principal, string? ClientId)> ValidateAccessTokenAsync(string accessToken)
        {
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var validationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = GetValidationKey(),
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.Zero,
                    TryAllIssuerSigningKeys = true
                };

                var principal = tokenHandler.ValidateToken(accessToken, validationParameters, out var validatedToken);
                
                // Additional validation - check if token is in our store and not revoked
                var tokenId = principal.FindFirst("jti")?.Value;
                string? clientId = null;
                if (!string.IsNullOrEmpty(tokenId))
                {
                    var storedToken = await _context.OAuthAccessTokens
                        .FirstOrDefaultAsync(t => t.TokenId == tokenId && !t.IsRevoked && !(DateTime.UtcNow > t.ExpiresUtc));

                    clientId = storedToken?.ClientId;
                    if (storedToken == null)
                    {
                        return (false, null, clientId);
                    }
                }

                return (true, principal, clientId);
            }
            catch (Exception ex)
            {
                _logger.LogWarning("DatabaseOAuthAuthorizationService", $"Token validation failed: {ex.Message}");
                return (false, null, null);
            }
        }

        public async Task<bool> RevokeTokenAsync(string token)
        {
            // Try to revoke as access token
            var accessToken = await _context.OAuthAccessTokens
                .FirstOrDefaultAsync(t => t.AccessToken == token);
            if (accessToken != null)
            {
                accessToken.IsRevoked = true;
                await _context.SaveChangesAsync();
                _logger.LogDebug("DatabaseOAuthAuthorizationService", $"Revoked access token: {accessToken.TokenId}");
                return true;
            }

            // Try to revoke as refresh token
            var refreshToken = await _context.OAuthRefreshTokens
                .FirstOrDefaultAsync(t => t.RefreshToken == token);
            if (refreshToken != null)
            {
                refreshToken.IsRevoked = true;
                
                // Also revoke associated access token
                var relatedAccessToken = await _context.OAuthAccessTokens
                    .FirstOrDefaultAsync(t => t.TokenId == refreshToken.AccessTokenId);
                if (relatedAccessToken != null)
                {
                    relatedAccessToken.IsRevoked = true;
                }
                
                await _context.SaveChangesAsync();
                _logger.LogDebug("DatabaseOAuthAuthorizationService", $"Revoked refresh token: {refreshToken.TokenId}");
                return true;
            }

            return false;
        }

        public async Task<object?> GetUserInfoAsync(string accessToken)
        {
            var (isValid, principal, clientId) = await ValidateAccessTokenAsync(accessToken);
            if (!isValid || principal == null)
            {
                return null;
            }

            var userId = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userId))
            {
                return null;
            }

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return null;
            }

            var scopes = principal.FindFirst("scope")?.Value?.Split(' ') ?? Array.Empty<string>();
            
            var userInfo = new Dictionary<string, object>
            {
                ["sub"] = user.Id!
            };

            if (scopes.Contains("profile"))
            {
                userInfo["name"] = user.FullName;
                userInfo["preferred_username"] = user.UserName!;
                userInfo["given_name"] = user.FullName!;
            }

            if (scopes.Contains("email"))
            {
                userInfo["email"] = user.Email!;
                userInfo["email_verified"] = user.EmailConfirmed;
            }
            var roles = new List<string>() { "user" };
            if (user.Administrator)
            {
                userInfo["role"] = "admin";
                roles.Insert(0, "admin");
            }
            else
            {
                userInfo["role"] = "user";
            }
            userInfo["roles"] = roles.ToArray();

            return userInfo;
        }

        public async Task CleanupExpiredTokensAsync()
        {
            try
            {
                var now = DateTime.UtcNow;
                var cleanedCount = 0;

                // Clean up expired authorization codes
                var expiredCodes = await _context.OAuthAuthorizationCodes
                    .Where(c => c.ExpiresUtc < now)
                    .ToListAsync();
                
                if (expiredCodes.Any())
                {
                    _context.OAuthAuthorizationCodes.RemoveRange(expiredCodes);
                    cleanedCount += expiredCodes.Count;
                }

                // Clean up expired access tokens
                var expiredAccessTokens = await _context.OAuthAccessTokens
                    .Where(t => t.ExpiresUtc < now)
                    .ToListAsync();
                
                if (expiredAccessTokens.Any())
                {
                    _context.OAuthAccessTokens.RemoveRange(expiredAccessTokens);
                    cleanedCount += expiredAccessTokens.Count;
                }

                // Clean up expired refresh tokens
                var expiredRefreshTokens = await _context.OAuthRefreshTokens
                    .Where(t => t.ExpiresUtc < now)
                    .ToListAsync();
                
                if (expiredRefreshTokens.Any())
                {
                    _context.OAuthRefreshTokens.RemoveRange(expiredRefreshTokens);
                    cleanedCount += expiredRefreshTokens.Count;
                }

                await _context.SaveChangesAsync();

                if (cleanedCount > 0)
                {
                    _logger.Log("DatabaseOAuthAuthorizationService", $"Cleaned up {cleanedCount} expired OAuth tokens");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError("DatabaseOAuthAuthorizationService", $"Error cleaning up expired tokens: {ex.Message}", ex);
            }
        }

        // Private helper methods
        private async Task<OAuthAccessToken> CreateAccessTokenAsync(OAuthClient client, User user, List<string> scopes, string? nonce)
        {
            var isOidcFlow = scopes.Contains("openid");
            var jwtId = Guid.NewGuid().ToString();

            var claims = new List<Claim>
            {
                new(ClaimTypes.NameIdentifier, user.Id!),
                new(ClaimTypes.Name, user.UserName!),
                new("client_id", client.ClientId),
                new("scope", string.Join(" ", scopes)),
                new(JwtRegisteredClaimNames.Jti, jwtId),
                new(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64)
            };

            if (!string.IsNullOrEmpty(nonce))
            {
                claims.Add(new Claim("nonce", nonce));
            }

            if (isOidcFlow)
            {
                claims.Add(new(JwtRegisteredClaimNames.Sub, user.Id!));  // Standard OIDC sub claim
            }
            if (scopes.Contains("profile"))
            {
                if (!string.IsNullOrEmpty(user.FullName))
                    claims.Add(new("name", user.FullName));
                claims.Add(new("preferred_username", user.UserName!));
            }
            if (scopes.Contains("email"))
            {
                claims.Add(new("email", user.Email!));
                claims.Add(new("email_verified", user.EmailConfirmed.ToString().ToLower()));
            }

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Issuer = _oidcOptions.Value.Issuer,
                Audience = _oidcOptions.Value.Audience,
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddSeconds(client.AccessTokenLifetime),
                SigningCredentials = GetSigningCredentials()
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var token = tokenHandler.CreateToken(tokenDescriptor);
            var tokenString = tokenHandler.WriteToken(token);

            var accessToken = new OAuthAccessToken
            {
                TokenId = jwtId,
                AccessToken = tokenString,
                ClientId = client.ClientId,
                UserId = user.Id!,
                Scopes = scopes,
                CreatedUtc = DateTime.UtcNow,
                ExpiresUtc = DateTime.UtcNow.AddSeconds(client.AccessTokenLifetime)
            };

            _context.OAuthAccessTokens.Add(accessToken);
            await _context.SaveChangesAsync();
            
            return accessToken;
        }

        private async Task<string> CreateRefreshTokenAsync(OAuthClient client, User user, List<string> scopes, string accessTokenId)
        {
            var refreshToken = new OAuthRefreshToken
            {
                TokenId = Guid.NewGuid().ToString(),
                RefreshToken = GenerateRefreshToken(),
                AccessTokenId = accessTokenId,
                ClientId = client.ClientId,
                UserId = user.Id!,
                Scopes = scopes,
                CreatedUtc = DateTime.UtcNow,
                ExpiresUtc = DateTime.UtcNow.AddSeconds(client.RefreshTokenLifetime!.Value)
            };

            _context.OAuthRefreshTokens.Add(refreshToken);
            await _context.SaveChangesAsync();
            
            return refreshToken.RefreshToken;
        }

        private string CreateIdToken(OAuthClient client, User user, List<string> scopes, string? nonce)
        {
            var claims = new List<Claim>
            {
                new(JwtRegisteredClaimNames.Sub, user.Id!),
                new(JwtRegisteredClaimNames.Aud, client.ClientId),
                new(JwtRegisteredClaimNames.Iss, _oidcOptions.Value.Issuer!),
                new(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString()),
                new(JwtRegisteredClaimNames.AuthTime, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString())
            };

            if (!string.IsNullOrEmpty(nonce))
            {
                claims.Add(new Claim("nonce", nonce));
            }

            if (scopes.Contains("profile"))
            {
                if (!string.IsNullOrEmpty(user.FullName))
                    claims.Add(new("name", user.FullName));
                claims.Add(new("preferred_username", user.UserName!));
            }

            if (scopes.Contains("email"))
            {
                claims.Add(new("email", user.Email!));
                claims.Add(new("email_verified", user.EmailConfirmed.ToString().ToLower()));
            }

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Issuer = _oidcOptions.Value.Issuer,
                Audience = client.ClientId,
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddMinutes(_oidcOptions.Value.IdTokenLifetimeMinutes),
                SigningCredentials = GetSigningCredentials()
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        private static string GenerateAuthorizationCode()
        {
            var bytes = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(bytes);
            return Convert.ToBase64String(bytes)
                .Replace("+", "-")
                .Replace("/", "_")
                .TrimEnd('=');
        }

        private static string GenerateRefreshToken()
        {
            var bytes = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(bytes);
            return Convert.ToBase64String(bytes);
        }

        private static bool ValidatePkce(string codeChallenge, string? codeChallengeMethod, string codeVerifier)
        {
            if (codeChallengeMethod == "S256")
            {
                using var sha256 = SHA256.Create();
                var hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(codeVerifier));
                var computedChallenge = Convert.ToBase64String(hash)
                    .TrimEnd('=' )
                    .Replace('+', '-')
                    .Replace('/', '_');
                return computedChallenge == codeChallenge;
            }
            else
            {
                // Plain text
                return codeVerifier == codeChallenge;
            }
        }

        private SigningCredentials GetSigningCredentials()
        {
            if (_sharedKeys.RSAIsAvailable && _sharedKeys.RSA != null)
            {
                var rsaKey = new RsaSecurityKey(_sharedKeys.RSA) { KeyId = "authly-rsa-key-1" };
                return new SigningCredentials(rsaKey, SecurityAlgorithms.RsaSha256);
            }
            else if (_sharedKeys.HMAC != null)
            {
                return new SigningCredentials(_sharedKeys.HMAC, SecurityAlgorithms.HmacSha256Signature);
            }

            throw new InvalidOperationException("No signing key available");
        }
        private SecurityKey GetValidationKey()
        {
            if (_sharedKeys.RSAIsAvailable && _sharedKeys.RSA != null)
            {
                return new RsaSecurityKey(_sharedKeys.RSA) { KeyId = _oidcOptions.Value.SigningKey };
            }
            else if (_sharedKeys.HMAC != null)
            {
                return _sharedKeys.HMAC;
            }

            throw new InvalidOperationException("No validation key available");
        }
    }
}
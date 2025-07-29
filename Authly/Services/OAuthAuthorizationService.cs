using Authly.Models;
using System.Text.Json;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;

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
        Task<string> CreateAuthorizationCodeAsync(string clientId, string userId, string redirectUri, List<string> scopes, string? codeChallenge, string? codeChallengeMethod, string? nonce);

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
    /// OAuth Authorization Server service
    /// </summary>
    public class OAuthAuthorizationService : IOAuthAuthorizationService
    {
        private readonly IOAuthClientService _clientService;
        private readonly UserManager<User> _userManager;
        private readonly IApplicationLogger _logger;
        private readonly IWebHostEnvironment _environment;
        private readonly string _authCodesPath;
        private readonly string _accessTokensPath;
        private readonly string _refreshTokensPath;
        private static SymmetricSecurityKey _signingKey;
        private readonly object _lock = new();

        public OAuthAuthorizationService(
            IOAuthClientService clientService,
            UserManager<User> userManager,
            IApplicationLogger logger,
            IWebHostEnvironment environment,
            IConfiguration configuration)
        {
            _clientService = clientService;
            _userManager = userManager;
            _logger = logger;
            _environment = environment;

            var dataDir = Path.Combine(_environment.WebRootPath ?? _environment.ContentRootPath, "data");
            
            Directory.CreateDirectory(dataDir);
            _authCodesPath = Path.Combine(dataDir, "oauth-auth-codes.json");
            _accessTokensPath = Path.Combine(dataDir, "oauth-access-tokens.json");
            _refreshTokensPath = Path.Combine(dataDir, "oauth-refresh-tokens.json");

            // Get or generate JWT signing key
            var signingKeyString = configuration["OAuth:SigningKey"] ?? Environment.GetEnvironmentVariable("OAUTH_SIGNING_KEY");
            if (string.IsNullOrEmpty(signingKeyString))
            {
                // Generate a new key (should be persisted in production)
                var key = new byte[32];
                using var rng = RandomNumberGenerator.Create();
                rng.GetBytes(key);
                signingKeyString = Convert.ToBase64String(key);
                _logger.LogWarning("OAuthAuthorizationService", "Generated new signing key. In production, persist this key!");
            }

            _signingKey ??= new SymmetricSecurityKey(Convert.FromBase64String(signingKeyString))
            {
                KeyId = "authly-key-1"
            };
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

        public async Task<string> CreateAuthorizationCodeAsync(string clientId, string userId, string redirectUri, List<string> scopes, string? codeChallenge, string? codeChallengeMethod, string? nonce)
        {
            var authCode = new OAuthAuthorizationCode
            {
                Code = GenerateAuthorizationCode(),
                ClientId = clientId,
                UserId = userId,
                RedirectUri = redirectUri,
                Scopes = scopes,
                CodeChallenge = codeChallenge,
                CodeChallengeMethod = codeChallengeMethod,
                Nonce = nonce,
                CreatedUtc = DateTime.UtcNow,
                ExpiresUtc = DateTime.UtcNow.AddMinutes(10)
            };

            await SaveAuthorizationCodeAsync(authCode);
            _logger.Log("OAuthAuthorizationService", $"Created authorization code for client {clientId}, user {userId}");
            
            return authCode.Code;
        }

        public async Task<(bool IsValid, OAuthTokenResponse? TokenResponse, string? Error, string? ErrorDescription)> ExchangeAuthorizationCodeAsync(OAuthTokenRequest request)
        {
            // Validate client credentials
            if (!await _clientService.ValidateClientCredentialsAsync(request.ClientId, request.ClientSecret))
            {
                return (false, null, "invalid_client", "Invalid client credentials");
            }

            // Find and validate authorization code
            var authCode = await GetAuthorizationCodeAsync(request.Code!);
            if (authCode == null || authCode.IsExpired || authCode.IsUsed)
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

            // Remove authorization code immediately after successful validation
            await RemoveAuthorizationCodeAsync(authCode.Code);

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

            _logger.Log("OAuthAuthorizationService", $"Exchanged authorization code for tokens: client {request.ClientId}, user {authCode.UserId}");
            return (true, tokenResponse, null, null);
        }

        public async Task<(bool IsValid, OAuthTokenResponse? TokenResponse, string? Error, string? ErrorDescription)> RefreshTokenAsync(OAuthTokenRequest request)
        {
            // Validate client credentials
            if (!await _clientService.ValidateClientCredentialsAsync(request.ClientId, request.ClientSecret))
            {
                return (false, null, "invalid_client", "Invalid client credentials");
            }

            // Find refresh token
            var refreshTokenObj = await GetRefreshTokenAsync(request.RefreshToken!);
            if (refreshTokenObj == null || refreshTokenObj.IsExpired || refreshTokenObj.IsRevoked)
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

            // Remove old access token and refresh token immediately
            await RemoveAccessTokenAsync(refreshTokenObj.AccessTokenId);
            await RemoveRefreshTokenAsync(refreshTokenObj.RefreshToken);

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

            var tokenResponse = new OAuthTokenResponse
            {
                AccessToken = accessToken.AccessToken,
                TokenType = "Bearer",
                ExpiresIn = client.AccessTokenLifetime,
                RefreshToken = newRefreshToken,
                Scope = string.Join(" ", scopes)
            };

            _logger.Log("OAuthAuthorizationService", $"Refreshed tokens: client {request.ClientId}, user {refreshTokenObj.UserId}");
            return (true, tokenResponse, null, null);
        }

        public async Task<(bool IsValid, ClaimsPrincipal? Principal, string? ClientId)> ValidateAccessTokenAsync(string accessToken)
        {
            try
            {
                string? clientId = null;
                var tokenHandler = new JwtSecurityTokenHandler();
                var validationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = _signingKey,
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.Zero,
                    TryAllIssuerSigningKeys = true
                };

                var principal = tokenHandler.ValidateToken(accessToken, validationParameters, out var validatedToken);
                
                // Additional validation - check if token is in our store and not revoked
                var tokenId = principal.FindFirst("jti")?.Value;
                if (!string.IsNullOrEmpty(tokenId))
                {
                    var storedToken = await GetAccessTokenAsync(tokenId);
                    clientId = storedToken?.ClientId;
                    if (storedToken == null || storedToken.IsRevoked || storedToken.IsExpired)
                    {
                        return (false, null, clientId);
                    }
                }

                return (true, principal, clientId);
            }
            catch (Exception ex)
            {
                _logger.LogWarning("OAuthAuthorizationService", $"Token validation failed: {ex.Message}");
                return (false, null, null);
            }
        }

        public async Task<bool> RevokeTokenAsync(string token)
        {
            // Try to revoke as access token
            var accessToken = await GetAccessTokenByValueAsync(token);
            if (accessToken != null)
            {
                await RemoveAccessTokenAsync(accessToken.TokenId);
                _logger.Log("OAuthAuthorizationService", $"Revoked and removed access token: {accessToken.TokenId}");
                return true;
            }

            // Try to revoke as refresh token
            var refreshToken = await GetRefreshTokenAsync(token);
            if (refreshToken != null)
            {
                // Remove associated access token first
                await RemoveAccessTokenAsync(refreshToken.AccessTokenId);
                
                // Remove refresh token
                await RemoveRefreshTokenAsync(refreshToken.RefreshToken);
                
                _logger.Log("OAuthAuthorizationService", $"Revoked and removed refresh token: {refreshToken.TokenId}");
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
                ["sub"] = user.Id!,
                ["aud"] = clientId ?? string.Empty, // Audience
                ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(), // Issued at
                ["exp"] = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds() // Expiration
            };

            if (scopes.Contains("profile"))
            {
                userInfo["name"] = user.FullName;
                userInfo["preferred_username"] = user.UserName!;
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

        /// <summary>
        /// Clean up expired and used tokens for maintenance
        /// </summary>
        public async Task CleanupExpiredTokensAsync()
        {
            try
            {
                _logger.Log("OAuthAuthorizationService", "Starting scheduled token cleanup");

                // Cleanup authorization codes
                var authCodes = await LoadAuthorizationCodesAsync();
                var expiredAuthCodes = authCodes.Count(c => c.IsExpired || c.IsUsed);
                if (expiredAuthCodes > 0)
                {
                    await SaveAuthorizationCodesAsync(authCodes); // This will trigger cleanup
                }

                // Cleanup access tokens
                var accessTokens = await LoadAccessTokensAsync();
                var expiredAccessTokens = accessTokens.Count(t => t.IsExpired || t.IsRevoked);
                if (expiredAccessTokens > 0)
                {
                    await SaveAccessTokensAsync(accessTokens); // This will trigger cleanup
                }

                // Cleanup refresh tokens
                var refreshTokens = await LoadRefreshTokensAsync();
                var expiredRefreshTokens = refreshTokens.Count(t => t.IsExpired || t.IsRevoked);
                if (expiredRefreshTokens > 0)
                {
                    await SaveRefreshTokensAsync(refreshTokens); // This will trigger cleanup
                }

                _logger.Log("OAuthAuthorizationService", 
                    $"Cleanup completed: {expiredAuthCodes} auth codes, {expiredAccessTokens} access tokens, {expiredRefreshTokens} refresh tokens removed");
            }
            catch (Exception ex)
            {
                _logger.LogError("OAuthAuthorizationService", "Error during token cleanup", ex);
            }
        }

        // Private helper methods
        private async Task<OAuthAccessToken> CreateAccessTokenAsync(OAuthClient client, User user, List<string> scopes, string? nonce)
        {
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

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddSeconds(client.AccessTokenLifetime),
                SigningCredentials = new SigningCredentials(_signingKey, SecurityAlgorithms.HmacSha256Signature)
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

            await SaveAccessTokenAsync(accessToken);
            return accessToken;
        }

        private async Task<string> CreateRefreshTokenAsync(OAuthClient client, User user, List<string> scopes, string accessTokenId)
        {
            var refreshToken = new OAuthRefreshToken
            {
                TokenId = GenerateTokenId(),
                RefreshToken = GenerateRefreshToken(),
                AccessTokenId = accessTokenId,
                ClientId = client.ClientId,
                UserId = user.Id!,
                Scopes = scopes,
                CreatedUtc = DateTime.UtcNow,
                ExpiresUtc = DateTime.UtcNow.AddSeconds(client.RefreshTokenLifetime!.Value)
            };

            await SaveRefreshTokenAsync(refreshToken);
            return refreshToken.RefreshToken;
        }

        private static bool ValidatePkce(string codeChallenge, string? codeChallengeMethod, string codeVerifier)
        {
            if (codeChallengeMethod == "S256")
            {
                using var sha256 = SHA256.Create();
                var hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(codeVerifier));
                var computedChallenge = Convert.ToBase64String(hash)
                    .TrimEnd('=')
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

        // Token generation methods
        private static string GenerateAuthorizationCode()
        {
            var bytes = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(bytes);
            return Convert.ToBase64String(bytes).Replace("+", "-").Replace("/", "_").TrimEnd('=');
        }

        private static string GenerateTokenId()
        {
            return Guid.NewGuid().ToString();
        }

        private static string GenerateRefreshToken()
        {
            var bytes = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(bytes);
            return Convert.ToBase64String(bytes);
        }

        // Storage methods for authorization codes
        private async Task SaveAuthorizationCodeAsync(OAuthAuthorizationCode authCode)
        {
            var codes = await LoadAuthorizationCodesAsync();
            var existingIndex = codes.FindIndex(c => c.Code == authCode.Code);
            
            if (existingIndex >= 0)
            {
                codes[existingIndex] = authCode;
            }
            else
            {
                codes.Add(authCode);
            }
            
            await SaveAuthorizationCodesAsync(codes);
        }

        private async Task<OAuthAuthorizationCode?> GetAuthorizationCodeAsync(string code)
        {
            var codes = await LoadAuthorizationCodesAsync();
            return codes.FirstOrDefault(c => c.Code == code);
        }

        private async Task RemoveAuthorizationCodeAsync(string code)
        {
            var codes = await LoadAuthorizationCodesAsync();
            codes.RemoveAll(c => c.Code == code);
            await SaveAuthorizationCodesAsync(codes);
            _logger.Log("OAuthAuthorizationService", $"Removed authorization code: {code}");
        }

        private async Task<List<OAuthAuthorizationCode>> LoadAuthorizationCodesAsync()
        {
            if (!File.Exists(_authCodesPath))
            {
                return new List<OAuthAuthorizationCode>();
            }

            try
            {
                var json = await File.ReadAllTextAsync(_authCodesPath);
                return JsonSerializer.Deserialize<List<OAuthAuthorizationCode>>(json) ?? new List<OAuthAuthorizationCode>();
            }
            catch
            {
                return new List<OAuthAuthorizationCode>();
            }
        }

        private async Task SaveAuthorizationCodesAsync(List<OAuthAuthorizationCode> codes)
        {
            // Clean up expired and used codes
            var originalCount = codes.Count;
            codes.RemoveAll(c => c.IsExpired || c.IsUsed);
            
            if (codes.Count != originalCount)
            {
                _logger.Log("OAuthAuthorizationService", $"Cleaned up {originalCount - codes.Count} expired/used authorization codes");
            }
            
            var json = JsonSerializer.Serialize(codes, new JsonSerializerOptions { WriteIndented = true });
            await File.WriteAllTextAsync(_authCodesPath, json);
        }

        // Storage methods for access tokens
        private async Task SaveAccessTokenAsync(OAuthAccessToken token)
        {
            var tokens = await LoadAccessTokensAsync();
            var existingIndex = tokens.FindIndex(t => t.TokenId == token.TokenId);
            
            if (existingIndex >= 0)
            {
                tokens[existingIndex] = token;
            }
            else
            {
                tokens.Add(token);
            }
            
            await SaveAccessTokensAsync(tokens);
        }

        private async Task<OAuthAccessToken?> GetAccessTokenAsync(string tokenId)
        {
            var tokens = await LoadAccessTokensAsync();
            return tokens.FirstOrDefault(t => t.TokenId == tokenId);
        }

        private async Task<OAuthAccessToken?> GetAccessTokenByValueAsync(string accessToken)
        {
            var tokens = await LoadAccessTokensAsync();
            return tokens.FirstOrDefault(t => t.AccessToken == accessToken);
        }

        private async Task RemoveAccessTokenAsync(string tokenId)
        {
            var tokens = await LoadAccessTokensAsync();
            var originalCount = tokens.Count;
            tokens.RemoveAll(t => t.TokenId == tokenId);
            
            if (tokens.Count != originalCount)
            {
                await SaveAccessTokensAsync(tokens);
                _logger.Log("OAuthAuthorizationService", $"Removed access token: {tokenId}");
            }
        }

        private async Task RevokeAccessTokenAsync(string tokenId)
        {
            var tokens = await LoadAccessTokensAsync();
            var token = tokens.FirstOrDefault(t => t.TokenId == tokenId);
            if (token != null)
            {
                token.IsRevoked = true;
                await SaveAccessTokensAsync(tokens);
            }
        }

        private async Task<List<OAuthAccessToken>> LoadAccessTokensAsync()
        {
            if (!File.Exists(_accessTokensPath))
            {
                return new List<OAuthAccessToken>();
            }

            try
            {
                var json = await File.ReadAllTextAsync(_accessTokensPath);
                return JsonSerializer.Deserialize<List<OAuthAccessToken>>(json) ?? new List<OAuthAccessToken>();
            }
            catch
            {
                return new List<OAuthAccessToken>();
            }
        }

        private async Task SaveAccessTokensAsync(List<OAuthAccessToken> tokens)
        {
            // Clean up expired and revoked tokens
            var originalCount = tokens.Count;
            tokens.RemoveAll(t => t.IsExpired || t.IsRevoked);
            
            if (tokens.Count != originalCount)
            {
                _logger.Log("OAuthAuthorizationService", $"Cleaned up {originalCount - tokens.Count} expired/revoked access tokens");
            }
            
            var json = JsonSerializer.Serialize(tokens, new JsonSerializerOptions { WriteIndented = true });
            await File.WriteAllTextAsync(_accessTokensPath, json);
        }

        // Storage methods for refresh tokens
        private async Task SaveRefreshTokenAsync(OAuthRefreshToken token)
        {
            var tokens = await LoadRefreshTokensAsync();
            var existingIndex = tokens.FindIndex(t => t.TokenId == token.TokenId);
            
            if (existingIndex >= 0)
            {
                tokens[existingIndex] = token;
            }
            else
            {
                tokens.Add(token);
            }
            
            await SaveRefreshTokensAsync(tokens);
        }

        private async Task<OAuthRefreshToken?> GetRefreshTokenAsync(string refreshToken)
        {
            var tokens = await LoadRefreshTokensAsync();
            return tokens.FirstOrDefault(t => t.RefreshToken == refreshToken);
        }

        private async Task RemoveRefreshTokenAsync(string refreshToken)
        {
            var tokens = await LoadRefreshTokensAsync();
            var originalCount = tokens.Count;
            tokens.RemoveAll(t => t.RefreshToken == refreshToken);
            
            if (tokens.Count != originalCount)
            {
                await SaveRefreshTokensAsync(tokens);
                _logger.Log("OAuthAuthorizationService", $"Removed refresh token: {refreshToken.Substring(0, Math.Min(8, refreshToken.Length))}...");
            }
        }

        private async Task<List<OAuthRefreshToken>> LoadRefreshTokensAsync()
        {
            if (!File.Exists(_refreshTokensPath))
            {
                return new List<OAuthRefreshToken>();
            }

            try
            {
                var json = await File.ReadAllTextAsync(_refreshTokensPath);
                return JsonSerializer.Deserialize<List<OAuthRefreshToken>>(json) ?? new List<OAuthRefreshToken>();
            }
            catch
            {
                return new List<OAuthRefreshToken>();
            }
        }

        private async Task SaveRefreshTokensAsync(List<OAuthRefreshToken> tokens)
        {
            // Clean up expired and revoked tokens
            var originalCount = tokens.Count;
            tokens.RemoveAll(t => t.IsExpired || t.IsRevoked);
            
            if (tokens.Count != originalCount)
            {
                _logger.Log("OAuthAuthorizationService", $"Cleaned up {originalCount - tokens.Count} expired/revoked refresh tokens");
            }
            
            var json = JsonSerializer.Serialize(tokens, new JsonSerializerOptions { WriteIndented = true });
            await File.WriteAllTextAsync(_refreshTokensPath, json);
        }
    }

    /// <summary>
    /// Extension methods for OAuth authorization service registration
    /// </summary>
    public static class OAuthAuthorizationServiceExtensions
    {
        public static IServiceCollection AddOAuthAuthorizationService(this IServiceCollection services)
        {
            services.AddScoped<IOAuthAuthorizationService, OAuthAuthorizationService>();
            return services;
        }
    }
}
using Authly.Models;
using Authly.Authorization.UserStorage;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Authly.Services
{
    /// <summary>
    /// Interface for token management service
    /// </summary>
    public interface ITokenService
    {
        /// <summary>
        /// Creates a new long-lived token for a user
        /// </summary>
        /// <param name="request">Token creation request</param>
        /// <param name="createdFromIp">IP address creating the token</param>
        /// <param name="userAgent">User agent string</param>
        /// <returns>Created token response with token value</returns>
        Task<CreateTokenResponse?> CreateTokenAsync(CreateTokenRequest request, string? createdFromIp = null, string? userAgent = null);

        /// <summary>
        /// Validates a token and returns the associated user
        /// </summary>
        /// <param name="tokenValue">Token value to validate</param>
        /// <returns>User associated with the token if valid, null otherwise</returns>
        Task<User?> ValidateTokenAsync(string tokenValue);

        /// <summary>
        /// Gets all tokens for a specific user
        /// </summary>
        /// <param name="userId">User ID</param>
        /// <returns>List of tokens for the user</returns>
        Task<List<Token>> GetUserTokensAsync(string userId);

        /// <summary>
        /// Gets all tokens in the system (admin only)
        /// </summary>
        /// <returns>List of all tokens</returns>
        Task<List<Token>> GetAllTokensAsync();

        /// <summary>
        /// Revokes a specific token
        /// </summary>
        /// <param name="tokenId">Token ID to revoke</param>
        /// <returns>True if revoked successfully</returns>
        Task<bool> RevokeTokenAsync(string tokenId);

        /// <summary>
        /// Revokes all tokens for a specific user
        /// </summary>
        /// <param name="userId">User ID</param>
        /// <returns>Number of tokens revoked</returns>
        Task<int> RevokeUserTokensAsync(string userId);

        /// <summary>
        /// Updates the last used timestamp for a token
        /// </summary>
        /// <param name="tokenValue">Token value</param>
        /// <returns>True if updated successfully</returns>
        Task<bool> UpdateLastUsedAsync(string tokenValue);

        /// <summary>
        /// Cleans up expired tokens
        /// </summary>
        /// <returns>Number of tokens cleaned up</returns>
        Task<int> CleanupExpiredTokensAsync();
    }

    /// <summary>
    /// Token management service implementation
    /// </summary>
    public class TokenService : ITokenService
    {
        private readonly IUserStorage _userStorage;
        private readonly IApplicationLogger _logger;
        private readonly IWebHostEnvironment _environment;
        private readonly ConcurrentDictionary<string, Token> _tokens = new();
        private readonly string _tokensFilePath;
        private readonly JsonSerializerOptions _jsonSerializerOptions;

        public TokenService(
            IUserStorage userStorage,
            IApplicationLogger logger,
            IWebHostEnvironment environment)
        {
            _userStorage = userStorage;
            _logger = logger;
            _environment = environment;
            
            _tokensFilePath = Path.Combine(_environment.WebRootPath ?? _environment.ContentRootPath, "data", "tokens.json");
            _jsonSerializerOptions = new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true,
                WriteIndented = true
            };

            // Load existing tokens from file
            LoadTokensFromFile();
        }

        /// <summary>
        /// Creates a new long-lived token for a user
        /// </summary>
        public async Task<CreateTokenResponse?> CreateTokenAsync(CreateTokenRequest request, string? createdFromIp = null, string? userAgent = null)
        {
            try
            {
                // Validate user exists
                var user = await _userStorage.FindUserById(request.UserId);
                if (user == null)
                {
                    _logger.LogWarning("TokenService", $"Cannot create token for non-existent user ID: {request.UserId}");
                    return null;
                }

                // Generate secure token
                var tokenValue = GenerateSecureToken();
                var tokenId = Guid.NewGuid().ToString();

                var token = new Token
                {
                    Id = tokenId,
                    UserId = request.UserId,
                    TokenValue = HashToken(tokenValue), // Store hashed version
                    Name = request.Name,
                    CreatedUtc = DateTime.UtcNow,
                    ExpiresUtc = request.ExpiresUtc,
                    IsActive = true,
                    CreatedFromIp = createdFromIp,
                    CreatedFromUserAgent = userAgent,
                    Scopes = request.Scopes
                };

                // Store token
                _tokens.TryAdd(tokenId, token);
                SaveTokensToFile();

                _logger.Log("TokenService", $"Created token '{request.Name}' for user {user.UserName} (ID: {request.UserId})");

                return new CreateTokenResponse
                {
                    Token = token,
                    TokenValue = tokenValue // Return unhashed token value (only time it's shown)
                };
            }
            catch (Exception ex)
            {
                _logger.LogError("TokenService", $"Failed to create token for user {request.UserId}: {ex.Message}", ex);
                return null;
            }
        }

        /// <summary>
        /// Validates a token and returns the associated user
        /// </summary>
        public async Task<User?> ValidateTokenAsync(string tokenValue)
        {
            try
            {
                if (string.IsNullOrEmpty(tokenValue))
                    return null;

                var hashedToken = HashToken(tokenValue);
                var token = _tokens.Values.FirstOrDefault(t => t.TokenValue == hashedToken && t.IsValid);

                if (token == null)
                {
                    return null;
                }

                // Update last used timestamp
                await UpdateLastUsedAsync(tokenValue);

                // Get and return the user
                return await _userStorage.FindUserById(token.UserId);
            }
            catch (Exception ex)
            {
                _logger.LogError("TokenService", $"Failed to validate token: {ex.Message}", ex);
                return null;
            }
        }

        /// <summary>
        /// Gets all tokens for a specific user
        /// </summary>
        public async Task<List<Token>> GetUserTokensAsync(string userId)
        {
            await Task.CompletedTask;
            try
            {
                return _tokens.Values
                    .Where(t => t.UserId == userId)
                    .OrderByDescending(t => t.CreatedUtc)
                    .ToList();
            }
            catch (Exception ex)
            {
                _logger.LogError("TokenService", $"Failed to get tokens for user {userId}: {ex.Message}", ex);
                return [];
            }
        }

        /// <summary>
        /// Gets all tokens in the system (admin only)
        /// </summary>
        public async Task<List<Token>> GetAllTokensAsync()
        {
            await Task.CompletedTask;
            try
            {
                return [.. _tokens.Values.OrderByDescending(t => t.CreatedUtc)];
            }
            catch (Exception ex)
            {
                _logger.LogError("TokenService", $"Failed to get all tokens: {ex.Message}", ex);
                return [];
            }
        }

        /// <summary>
        /// Revokes a specific token
        /// </summary>
        public async Task<bool> RevokeTokenAsync(string tokenId)
        {
            await Task.CompletedTask;
            try
            {
                if (_tokens.TryGetValue(tokenId, out var token))
                {
                    token.IsActive = false;
                    SaveTokensToFile();
                    _logger.Log("TokenService", $"Revoked token {tokenId} ('{token.Name}') for user {token.UserId}");
                    return true;
                }

                _logger.LogWarning("TokenService", $"Token {tokenId} not found for revocation");
                return false;
            }
            catch (Exception ex)
            {
                _logger.LogError("TokenService", $"Failed to revoke token {tokenId}: {ex.Message}", ex);
                return false;
            }
        }

        /// <summary>
        /// Revokes all tokens for a specific user
        /// </summary>
        public async Task<int> RevokeUserTokensAsync(string userId)
        {
            await Task.CompletedTask;
            try
            {
                var userTokens = _tokens.Values.Where(t => t.UserId == userId && t.IsActive).ToList();
                var revokedCount = 0;

                foreach (var token in userTokens)
                {
                    token.IsActive = false;
                    revokedCount++;
                }

                if (revokedCount > 0)
                {
                    SaveTokensToFile();
                    _logger.Log("TokenService", $"Revoked {revokedCount} tokens for user {userId}");
                }

                return revokedCount;
            }
            catch (Exception ex)
            {
                _logger.LogError("TokenService", $"Failed to revoke tokens for user {userId}: {ex.Message}", ex);
                return 0;
            }
        }

        /// <summary>
        /// Updates the last used timestamp for a token
        /// </summary>
        public async Task<bool> UpdateLastUsedAsync(string tokenValue)
        {
            await Task.CompletedTask;
            try
            {
                var hashedToken = HashToken(tokenValue);
                var token = _tokens.Values.FirstOrDefault(t => t.TokenValue == hashedToken);

                if (token != null)
                {
                    token.LastUsedUtc = DateTime.UtcNow;
                    // Save periodically (every hour) to avoid too frequent file writes
                    if (token.LastUsedUtc.Value.Minute == 0)
                    {
                        SaveTokensToFile();
                    }
                    return true;
                }

                return false;
            }
            catch (Exception ex)
            {
                _logger.LogError("TokenService", $"Failed to update last used for token: {ex.Message}", ex);
                return false;
            }
        }

        /// <summary>
        /// Cleans up expired tokens
        /// </summary>
        public async Task<int> CleanupExpiredTokensAsync()
        {
            await Task.CompletedTask;
            try
            {
                var now = DateTime.UtcNow;
                var expiredTokens = _tokens.Values
                    .Where(t => t.ExpiresUtc.HasValue && t.ExpiresUtc <= now)
                    .ToList();

                var cleanedCount = 0;
                foreach (var token in expiredTokens)
                {
                    if (_tokens.TryRemove(token.Id, out _))
                    {
                        cleanedCount++;
                    }
                }

                if (cleanedCount > 0)
                {
                    SaveTokensToFile();
                    _logger.Log("TokenService", $"Cleaned up {cleanedCount} expired tokens");
                }

                return cleanedCount;
            }
            catch (Exception ex)
            {
                _logger.LogError("TokenService", $"Failed to cleanup expired tokens: {ex.Message}", ex);
                return 0;
            }
        }

        /// <summary>
        /// Generates a cryptographically secure random token
        /// </summary>
        private static string GenerateSecureToken()
        {
            const int tokenLength = 32; // 256 bits
            var randomBytes = new byte[tokenLength];
            
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomBytes);
            }
            
            return Convert.ToBase64String(randomBytes)
                .Replace("+", "-")
                .Replace("/", "_")
                .Replace("=", "");
        }

        /// <summary>
        /// Hashes a token for secure storage
        /// </summary>
        private static string HashToken(string token)
        {
            using var sha256 = SHA256.Create();
            var hashedBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(token));
            return Convert.ToBase64String(hashedBytes);
        }

        /// <summary>
        /// Loads tokens from file
        /// </summary>
        private void LoadTokensFromFile()
        {
            try
            {
                var directory = Path.GetDirectoryName(_tokensFilePath);
                if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
                {
                    Directory.CreateDirectory(directory);
                }

                if (File.Exists(_tokensFilePath))
                {
                    var json = File.ReadAllText(_tokensFilePath);
                    var tokens = JsonSerializer.Deserialize<List<Token>>(json, _jsonSerializerOptions);

                    if (tokens != null)
                    {
                        foreach (var token in tokens)
                        {
                            _tokens.TryAdd(token.Id, token);
                        }

                        _logger.Log("TokenService", $"Loaded {tokens.Count} tokens from file");
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError("TokenService", $"Failed to load tokens from file: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Saves tokens to file
        /// </summary>
        private void SaveTokensToFile()
        {
            try
            {
                var tokensToSave = _tokens.Values.ToList();
                var json = JsonSerializer.Serialize(tokensToSave, _jsonSerializerOptions);
                File.WriteAllText(_tokensFilePath, json);

                _logger.Log("TokenService", $"Saved {tokensToSave.Count} tokens to file");
            }
            catch (Exception ex)
            {
                _logger.LogError("TokenService", $"Failed to save tokens to file: {ex.Message}", ex);
            }
        }
    }
}
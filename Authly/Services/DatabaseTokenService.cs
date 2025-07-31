using Authly.Models;
using Authly.Data;
using Authly.Authorization.UserStorage;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;

namespace Authly.Services
{/// <summary>
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
    /// Database-based token management service for long-lived authentication tokens
    /// </summary>
    public class DatabaseTokenService : ITokenService
    {
        private readonly AuthlyDbContext _context;
        private readonly IUserStorage _userStorage;
        private readonly IApplicationLogger _logger;

        public DatabaseTokenService(AuthlyDbContext context, IUserStorage userStorage, IApplicationLogger logger)
        {
            _context = context;
            _userStorage = userStorage;
            _logger = logger;
        }

        public async Task<List<Token>> GetUserTokensAsync(string userId)
        {
            try
            {
                var tokens = await _context.Tokens
                    .Where(t => t.UserId == userId)
                    .OrderByDescending(t => t.CreatedUtc)
                    .ToListAsync();

                _logger.Log("DatabaseTokenService", $"Retrieved {tokens.Count} tokens for user {userId}");
                return tokens;
            }
            catch (Exception ex)
            {
                _logger.LogError("DatabaseTokenService", $"Error retrieving tokens for user {userId}: {ex.Message}", ex);
                return new List<Token>();
            }
        }

        public async Task<List<Token>> GetAllTokensAsync()
        {
            try
            {
                var tokens = await _context.Tokens
                    .OrderByDescending(t => t.CreatedUtc)
                    .ToListAsync();

                return tokens;
            }
            catch (Exception ex)
            {
                _logger.LogError("DatabaseTokenService", $"Error retrieving all tokens: {ex.Message}", ex);
                return new List<Token>();
            }
        }

        public async Task<User?> ValidateTokenAsync(string tokenValue)
        {
            try
            {
                var hashedToken = HashToken(tokenValue);
                var token = await _context.Tokens
                    .FirstOrDefaultAsync(t => t.TokenValue == hashedToken && t.IsActive && 
                                            (t.ExpiresUtc == null || t.ExpiresUtc > DateTime.UtcNow));

                if (token != null)
                {
                    // Update last used timestamp
                    token.LastUsedUtc = DateTime.UtcNow;
                    await _context.SaveChangesAsync();

                    _logger.Log("DatabaseTokenService", $"Token validated successfully for user {token.UserId}");
                    
                    // Get and return the user
                    return await _userStorage.FindUserById(token.UserId);
                }

                return null;
            }
            catch (Exception ex)
            {
                _logger.LogError("DatabaseTokenService", $"Error validating token: {ex.Message}", ex);
                return null;
            }
        }

        public async Task<CreateTokenResponse?> CreateTokenAsync(CreateTokenRequest request, string? createdFromIp = null, string? createdFromUserAgent = null)
        {
            try
            {
                // Validate user exists
                var user = await _userStorage.FindUserById(request.UserId);
                if (user == null)
                {
                    _logger.LogWarning("DatabaseTokenService", $"Cannot create token for non-existent user ID: {request.UserId}");
                    return null;
                }

                var tokenValue = GenerateSecureToken();
                var hashedToken = HashToken(tokenValue);

                var token = new Token
                {
                    Id = Guid.NewGuid().ToString(),
                    UserId = request.UserId,
                    TokenValue = hashedToken,
                    Name = request.Name,
                    CreatedUtc = DateTime.UtcNow,
                    ExpiresUtc = request.ExpiresUtc,
                    IsActive = true,
                    CreatedFromIp = createdFromIp,
                    CreatedFromUserAgent = createdFromUserAgent,
                    Scopes = request.Scopes
                };

                _context.Tokens.Add(token);
                await _context.SaveChangesAsync();

                _logger.Log("DatabaseTokenService", $"Created token '{request.Name}' for user {user.UserName} (ID: {request.UserId})");

                return new CreateTokenResponse
                {
                    Token = token,
                    TokenValue = tokenValue // Return the unhashed token value
                };
            }
            catch (Exception ex)
            {
                _logger.LogError("DatabaseTokenService", $"Error creating token: {ex.Message}", ex);
                return null;
            }
        }

        public async Task<bool> RevokeTokenAsync(string tokenId)
        {
            try
            {
                var token = await _context.Tokens.FirstOrDefaultAsync(t => t.Id == tokenId);
                if (token == null)
                {
                    _logger.LogWarning("DatabaseTokenService", $"Token {tokenId} not found for revocation");
                    return false;
                }

                token.IsActive = false;
                await _context.SaveChangesAsync();

                _logger.Log("DatabaseTokenService", $"Revoked token {tokenId} ('{token.Name}') for user {token.UserId}");
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError("DatabaseTokenService", $"Error revoking token {tokenId}: {ex.Message}", ex);
                return false;
            }
        }

        public async Task<int> RevokeUserTokensAsync(string userId)
        {
            try
            {
                var tokens = await _context.Tokens
                    .Where(t => t.UserId == userId && t.IsActive)
                    .ToListAsync();

                var revokedCount = 0;
                foreach (var token in tokens)
                {
                    token.IsActive = false;
                    revokedCount++;
                }

                if (revokedCount > 0)
                {
                    await _context.SaveChangesAsync();
                    _logger.Log("DatabaseTokenService", $"Revoked {revokedCount} tokens for user {userId}");
                }

                return revokedCount;
            }
            catch (Exception ex)
            {
                _logger.LogError("DatabaseTokenService", $"Error revoking tokens for user {userId}: {ex.Message}", ex);
                return 0;
            }
        }

        public async Task<bool> UpdateLastUsedAsync(string tokenValue)
        {
            try
            {
                var hashedToken = HashToken(tokenValue);
                var token = await _context.Tokens.FirstOrDefaultAsync(t => t.TokenValue == hashedToken);

                if (token != null)
                {
                    token.LastUsedUtc = DateTime.UtcNow;
                    await _context.SaveChangesAsync();
                    return true;
                }

                return false;
            }
            catch (Exception ex)
            {
                _logger.LogError("DatabaseTokenService", $"Error updating last used for token: {ex.Message}", ex);
                return false;
            }
        }

        public async Task<int> CleanupExpiredTokensAsync()
        {
            try
            {
                var expiredTokens = await _context.Tokens
                    .Where(t => (t.ExpiresUtc.HasValue && t.ExpiresUtc < DateTime.UtcNow) || t.IsActive != true)
                    .ToListAsync();

                _context.Tokens.RemoveRange(expiredTokens);
                await _context.SaveChangesAsync();

                _logger.Log("DatabaseTokenService", $"Cleaned up {expiredTokens.Count} expired tokens");
                return expiredTokens.Count;
            }
            catch (Exception ex)
            {
                _logger.LogError("DatabaseTokenService", $"Error cleaning up expired tokens: {ex.Message}", ex);
                return 0;
            }
        }

        /// <summary>
        /// Generates a cryptographically secure random token
        /// </summary>
        private static string GenerateSecureToken()
        {
            var randomBytes = new byte[32];
            
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
            var hashedBytes = sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(token));
            return Convert.ToBase64String(hashedBytes);
        }
    }
}
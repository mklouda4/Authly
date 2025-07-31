using Authly.Models;
using Authly.Data;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;

namespace Authly.Services
{
    /// <summary>
    /// Interface for OAuth client management service
    /// </summary>
    public interface IOAuthClientService
    {
        /// <summary>
        /// Get all OAuth clients
        /// </summary>
        Task<List<OAuthClient>> GetAllClientsAsync();

        /// <summary>
        /// Get OAuth client by ID
        /// </summary>
        Task<OAuthClient?> GetClientAsync(string clientId);

        /// <summary>
        /// Create new OAuth client
        /// </summary>
        Task<OAuthClient> CreateClientAsync(CreateOAuthClientRequest request, string createdBy);

        /// <summary>
        /// Update OAuth client
        /// </summary>
        Task<bool> UpdateClientAsync(OAuthClient client);

        /// <summary>
        /// Update OAuth client from request
        /// </summary>
        Task<bool> UpdateClientAsync(UpdateOAuthClientRequest request, string modifiedBy);

        /// <summary>
        /// Delete OAuth client
        /// </summary>
        Task<bool> DeleteClientAsync(string clientId);

        /// <summary>
        /// Validate OAuth client credentials
        /// </summary>
        Task<bool> ValidateClientCredentialsAsync(string clientId, string? clientSecret);

        /// <summary>
        /// Check if redirect URI is valid for client
        /// </summary>
        Task<bool> IsValidRedirectUriAsync(string clientId, string redirectUri);

        /// <summary>
        /// Generate new client secret
        /// </summary>
        Task<string> RegenerateClientSecretAsync(string clientId);

        /// <summary>
        /// Get available OAuth scopes
        /// </summary>
        List<OAuthScope> GetAvailableScopes();
    }
    /// <summary>
    /// Database-based OAuth client management service
    /// </summary>
    public class DatabaseOAuthClientService : IOAuthClientService
    {
        private readonly AuthlyDbContext _context;
        private readonly IApplicationLogger _logger;

        private readonly List<OAuthScope> _availableScopes = new()
        {
            new OAuthScope { Name = "openid", DisplayName = "OpenID Connect", Description = "Access to user identity", Required = true },
            new OAuthScope { Name = "profile", DisplayName = "Profile", Description = "Access to user profile information" },
            new OAuthScope { Name = "email", DisplayName = "Email", Description = "Access to user email address" },
            new OAuthScope { Name = "read", DisplayName = "Read Access", Description = "Read access to user data" },
            new OAuthScope { Name = "write", DisplayName = "Write Access", Description = "Write access to user data", Emphasize = true },
            new OAuthScope { Name = "admin", DisplayName = "Admin Access", Description = "Administrative access", Emphasize = true }
        };

        public DatabaseOAuthClientService(AuthlyDbContext context, IApplicationLogger logger)
        {
            _context = context;
            _logger = logger;
        }

        public async Task<List<OAuthClient>> GetAllClientsAsync()
        {
            try
            {
                var clients = await _context.OAuthClients.ToListAsync();
                return clients;
            }
            catch (Exception ex)
            {
                _logger.LogError("DatabaseOAuthClientService", $"Error loading OAuth clients: {ex.Message}", ex);
                return new List<OAuthClient>();
            }
        }

        public async Task<OAuthClient?> GetClientAsync(string clientId)
        {
            return await _context.OAuthClients.FirstOrDefaultAsync(c => c.ClientId == clientId);
        }

        public async Task<OAuthClient> CreateClientAsync(CreateOAuthClientRequest request, string createdBy)
        {
            var client = new OAuthClient
            {
                ClientId = GenerateClientId(),
                ClientSecret = request.ClientType == OAuthClientType.Confidential ? GenerateClientSecret() : null,
                ClientName = request.ClientName,
                Description = request.Description,
                ClientType = request.ClientType,
                RedirectUris = request.RedirectUris,
                AllowedGrantTypes = request.AllowedGrantTypes,
                AllowedScopes = request.AllowedScopes,
                AccessTokenLifetime = request.AccessTokenLifetime,
                RefreshTokenLifetime = request.RefreshTokenLifetime,
                RequirePkce = request.RequirePkce,
                AllowPlainTextPkce = request.AllowPlainTextPkce,
                LogoUri = request.LogoUri,
                ClientUri = request.ClientUri,
                TosUri = request.TosUri,
                PolicyUri = request.PolicyUri,
                CreatedBy = createdBy,
                CreatedUtc = DateTime.UtcNow,
                ModifiedUtc = DateTime.UtcNow
            };

            _context.OAuthClients.Add(client);
            await _context.SaveChangesAsync();

            _logger.LogDebug("DatabaseOAuthClientService", $"Created OAuth client: {client.ClientId} ({client.ClientName}) by {createdBy}");
            return client;
        }

        public async Task<bool> UpdateClientAsync(OAuthClient client)
        {
            var existingClient = await _context.OAuthClients.FirstOrDefaultAsync(c => c.ClientId == client.ClientId);
            if (existingClient == null)
            {
                return false;
            }

            // Update properties
            existingClient.ClientName = client.ClientName;
            existingClient.Description = client.Description;
            existingClient.RedirectUris = client.RedirectUris;
            existingClient.AllowedScopes = client.AllowedScopes;
            existingClient.AccessTokenLifetime = client.AccessTokenLifetime;
            existingClient.RefreshTokenLifetime = client.RefreshTokenLifetime;
            existingClient.RequirePkce = client.RequirePkce;
            existingClient.AllowPlainTextPkce = client.AllowPlainTextPkce;
            existingClient.LogoUri = client.LogoUri;
            existingClient.ClientUri = client.ClientUri;
            existingClient.TosUri = client.TosUri;
            existingClient.PolicyUri = client.PolicyUri;
            existingClient.Enabled = client.Enabled;
            existingClient.ModifiedUtc = DateTime.UtcNow;

            await _context.SaveChangesAsync();
            _logger.LogDebug("DatabaseOAuthClientService", $"Updated OAuth client: {client.ClientId}");
            return true;
        }

        public async Task<bool> UpdateClientAsync(UpdateOAuthClientRequest request, string modifiedBy)
        {
            var client = await _context.OAuthClients.FirstOrDefaultAsync(c => c.ClientId == request.ClientId);
            if (client == null)
            {
                return false;
            }

            // Update client properties (but preserve ClientType and secret)
            client.ClientName = request.ClientName;
            client.Description = request.Description;
            client.RedirectUris = request.RedirectUris;
            client.AllowedScopes = request.AllowedScopes;
            client.AccessTokenLifetime = request.AccessTokenLifetime;
            client.RefreshTokenLifetime = request.RefreshTokenLifetime;
            client.RequirePkce = request.RequirePkce;
            client.AllowPlainTextPkce = request.AllowPlainTextPkce;
            client.LogoUri = request.LogoUri;
            client.ClientUri = request.ClientUri;
            client.TosUri = request.TosUri;
            client.PolicyUri = request.PolicyUri;
            client.Enabled = request.Enabled;
            client.ModifiedUtc = DateTime.UtcNow;

            await _context.SaveChangesAsync();
            _logger.LogDebug("DatabaseOAuthClientService", $"Updated OAuth client: {client.ClientId} by {modifiedBy}");
            return true;
        }

        public async Task<bool> DeleteClientAsync(string clientId)
        {
            var client = await _context.OAuthClients.FirstOrDefaultAsync(c => c.ClientId == clientId);
            if (client == null)
            {
                return false;
            }

            _context.OAuthClients.Remove(client);
            await _context.SaveChangesAsync();
            
            _logger.LogDebug("DatabaseOAuthClientService", $"Deleted OAuth client: {clientId} ({client.ClientName})");
            return true;
        }

        public async Task<bool> ValidateClientCredentialsAsync(string clientId, string? clientSecret)
        {
            var client = await _context.OAuthClients.FirstOrDefaultAsync(c => c.ClientId == clientId);
            if (client == null || !client.Enabled)
            {
                return false;
            }

            // Public clients don't require secret
            if (client.ClientType == OAuthClientType.Public)
            {
                return true;
            }

            // Confidential clients require secret
            return !string.IsNullOrEmpty(clientSecret) && client.ClientSecret == clientSecret;
        }

        public async Task<bool> IsValidRedirectUriAsync(string clientId, string redirectUri)
        {
            var client = await _context.OAuthClients.FirstOrDefaultAsync(c => c.ClientId == clientId);
            if (client == null || !client.Enabled)
            {
                return false;
            }

            return client.RedirectUris.Contains(redirectUri);
        }

        public async Task<string> RegenerateClientSecretAsync(string clientId)
        {
            var client = await _context.OAuthClients.FirstOrDefaultAsync(c => c.ClientId == clientId);
            if (client == null || client.ClientType != OAuthClientType.Confidential)
            {
                throw new InvalidOperationException("Client not found or is not confidential");
            }

            var newSecret = GenerateClientSecret();
            client.ClientSecret = newSecret;
            client.ModifiedUtc = DateTime.UtcNow;
            
            await _context.SaveChangesAsync();
            _logger.LogDebug("DatabaseOAuthClientService", $"Regenerated client secret for: {clientId}");
            
            return newSecret;
        }

        public List<OAuthScope> GetAvailableScopes()
        {
            return _availableScopes;
        }

        private static string GenerateClientId()
        {
            // Generate a URL-safe client ID
            var bytes = new byte[16];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(bytes);
            return Convert.ToBase64String(bytes)
                .Replace("+", "-")
                .Replace("/", "_")
                .TrimEnd('=');
        }

        private static string GenerateClientSecret()
        {
            // Generate a strong client secret
            var bytes = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(bytes);
            return Convert.ToBase64String(bytes);
        }
    }
}
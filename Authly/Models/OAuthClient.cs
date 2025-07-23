using System.ComponentModel.DataAnnotations;

namespace Authly.Models
{
    /// <summary>
    /// OAuth Client application model for registered third-party applications
    /// </summary>
    public class OAuthClient
    {
        /// <summary>
        /// Unique client identifier
        /// </summary>
        public string ClientId { get; set; } = string.Empty;

        /// <summary>
        /// Client secret for confidential clients
        /// </summary>
        public string? ClientSecret { get; set; }

        /// <summary>
        /// Human-readable client name
        /// </summary>
        public string ClientName { get; set; } = string.Empty;

        /// <summary>
        /// Client description
        /// </summary>
        public string? Description { get; set; }

        /// <summary>
        /// Client type (public, confidential)
        /// </summary>
        public OAuthClientType ClientType { get; set; } = OAuthClientType.Confidential;

        /// <summary>
        /// Allowed redirect URIs (JSON array)
        /// </summary>
        public List<string> RedirectUris { get; set; } = new();

        /// <summary>
        /// Allowed grant types
        /// </summary>
        public List<OAuthGrantType> AllowedGrantTypes { get; set; } = new();

        /// <summary>
        /// Allowed scopes
        /// </summary>
        public List<string> AllowedScopes { get; set; } = new();

        /// <summary>
        /// Access token lifetime in seconds
        /// </summary>
        public int AccessTokenLifetime { get; set; } = 3600; // 1 hour

        /// <summary>
        /// Refresh token lifetime in seconds (null for no refresh tokens)
        /// </summary>
        public int? RefreshTokenLifetime { get; set; } = 86400; // 24 hours

        /// <summary>
        /// Whether the client requires PKCE
        /// </summary>
        public bool RequirePkce { get; set; } = true;

        /// <summary>
        /// Whether the client allows plain text PKCE (not recommended)
        /// </summary>
        public bool AllowPlainTextPkce { get; set; } = false;

        /// <summary>
        /// Client logo URL
        /// </summary>
        public string? LogoUri { get; set; }

        /// <summary>
        /// Client website URL
        /// </summary>
        public string? ClientUri { get; set; }

        /// <summary>
        /// Terms of service URL
        /// </summary>
        public string? TosUri { get; set; }

        /// <summary>
        /// Privacy policy URL
        /// </summary>
        public string? PolicyUri { get; set; }

        /// <summary>
        /// When the client was created
        /// </summary>
        public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// When the client was last modified
        /// </summary>
        public DateTime ModifiedUtc { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// Whether the client is enabled
        /// </summary>
        public bool Enabled { get; set; } = true;

        /// <summary>
        /// Who created this client
        /// </summary>
        public string? CreatedBy { get; set; }

        /// <summary>
        /// Additional custom properties
        /// </summary>
        public Dictionary<string, string> Properties { get; set; } = new();
    }

    /// <summary>
    /// OAuth client types
    /// </summary>
    public enum OAuthClientType
    {
        /// <summary>
        /// Confidential client (can securely store credentials)
        /// </summary>
        Confidential,
        
        /// <summary>
        /// Public client (cannot securely store credentials)
        /// </summary>
        Public
    }

    /// <summary>
    /// OAuth grant types
    /// </summary>
    public enum OAuthGrantType
    {
        /// <summary>
        /// Authorization Code Grant
        /// </summary>
        AuthorizationCode,
        
        /// <summary>
        /// Client Credentials Grant
        /// </summary>
        ClientCredentials,
        
        /// <summary>
        /// Refresh Token Grant
        /// </summary>
        RefreshToken,
        
        /// <summary>
        /// Device Code Grant
        /// </summary>
        DeviceCode
    }

    /// <summary>
    /// OAuth authorization request
    /// </summary>
    public class OAuthAuthorizationRequest
    {
        public string ClientId { get; set; } = string.Empty;
        public string RedirectUri { get; set; } = string.Empty;
        public string ResponseType { get; set; } = string.Empty;
        public string State { get; set; } = string.Empty;
        public string? Scope { get; set; }
        public string? CodeChallenge { get; set; }
        public string? CodeChallengeMethod { get; set; }
        public string? Nonce { get; set; }
    }

    /// <summary>
    /// OAuth token request
    /// </summary>
    public class OAuthTokenRequest
    {
        public string GrantType { get; set; } = string.Empty;
        public string ClientId { get; set; } = string.Empty;
        public string? ClientSecret { get; set; }
        public string? Code { get; set; }
        public string? RedirectUri { get; set; }
        public string? CodeVerifier { get; set; }
        public string? RefreshToken { get; set; }
        public string? Scope { get; set; }
    }

    /// <summary>
    /// OAuth token response
    /// </summary>
    public class OAuthTokenResponse
    {
        public string AccessToken { get; set; } = string.Empty;
        public string TokenType { get; set; } = "Bearer";
        public int ExpiresIn { get; set; }
        public string? RefreshToken { get; set; }
        public string? Scope { get; set; }
    }

    /// <summary>
    /// OAuth error response
    /// </summary>
    public class OAuthErrorResponse
    {
        public string Error { get; set; } = string.Empty;
        public string? ErrorDescription { get; set; }
        public string? ErrorUri { get; set; }
        public string? State { get; set; }
    }

    /// <summary>
    /// OAuth authorization code
    /// </summary>
    public class OAuthAuthorizationCode
    {
        public string Code { get; set; } = string.Empty;
        public string ClientId { get; set; } = string.Empty;
        public string UserId { get; set; } = string.Empty;
        public string RedirectUri { get; set; } = string.Empty;
        public List<string> Scopes { get; set; } = new();
        public string? CodeChallenge { get; set; }
        public string? CodeChallengeMethod { get; set; }
        public string? Nonce { get; set; }
        public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
        public DateTime ExpiresUtc { get; set; } = DateTime.UtcNow.AddMinutes(10); // 10 minutes
        public bool IsExpired => DateTime.UtcNow > ExpiresUtc;
        public bool IsUsed { get; set; } = false;
    }

    /// <summary>
    /// OAuth access token
    /// </summary>
    public class OAuthAccessToken
    {
        public string TokenId { get; set; } = string.Empty;
        public string AccessToken { get; set; } = string.Empty;
        public string ClientId { get; set; } = string.Empty;
        public string UserId { get; set; } = string.Empty;
        public List<string> Scopes { get; set; } = new();
        public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
        public DateTime ExpiresUtc { get; set; }
        public bool IsExpired => DateTime.UtcNow > ExpiresUtc;
        public bool IsRevoked { get; set; } = false;
    }

    /// <summary>
    /// OAuth refresh token
    /// </summary>
    public class OAuthRefreshToken
    {
        public string TokenId { get; set; } = string.Empty;
        public string RefreshToken { get; set; } = string.Empty;
        public string AccessTokenId { get; set; } = string.Empty;
        public string ClientId { get; set; } = string.Empty;
        public string UserId { get; set; } = string.Empty;
        public List<string> Scopes { get; set; } = new();
        public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
        public DateTime ExpiresUtc { get; set; }
        public bool IsExpired => DateTime.UtcNow > ExpiresUtc;
        public bool IsRevoked { get; set; } = false;
    }

    /// <summary>
    /// Request model for creating OAuth client
    /// </summary>
    public class CreateOAuthClientRequest
    {
        [Required]
        [StringLength(100, MinimumLength = 1)]
        public string ClientName { get; set; } = string.Empty;

        [StringLength(500)]
        public string? Description { get; set; }

        [Required]
        public OAuthClientType ClientType { get; set; } = OAuthClientType.Confidential;

        [Required]
        [MinLength(1)]
        public List<string> RedirectUris { get; set; } = new();

        [Required]
        [MinLength(1)]
        public List<OAuthGrantType> AllowedGrantTypes { get; set; } = new();

        [Required]
        [MinLength(1)]
        public List<string> AllowedScopes { get; set; } = new();

        [Range(300, 86400)] // 5 minutes to 24 hours
        public int AccessTokenLifetime { get; set; } = 3600;

        [Range(300, 2592000)] // 5 minutes to 30 days
        public int? RefreshTokenLifetime { get; set; } = 86400;

        public bool RequirePkce { get; set; } = true;

        public bool AllowPlainTextPkce { get; set; } = false;

        [Url]
        public string? LogoUri { get; set; }

        [Url]
        public string? ClientUri { get; set; }

        [Url]
        public string? TosUri { get; set; }

        [Url]
        public string? PolicyUri { get; set; }
    }

    /// <summary>
    /// Request model for updating OAuth client
    /// </summary>
    public class UpdateOAuthClientRequest
    {
        [Required]
        public string ClientId { get; set; } = string.Empty;

        [Required]
        [StringLength(100, MinimumLength = 1)]
        public string ClientName { get; set; } = string.Empty;

        [StringLength(500)]
        public string? Description { get; set; }

        [Required]
        [MinLength(1)]
        public List<string> RedirectUris { get; set; } = new();

        [Required]
        [MinLength(1)]
        public List<string> AllowedScopes { get; set; } = new();

        [Range(300, 86400)] // 5 minutes to 24 hours
        public int AccessTokenLifetime { get; set; } = 3600;

        [Range(300, 2592000)] // 5 minutes to 30 days
        public int? RefreshTokenLifetime { get; set; } = 86400;

        public bool RequirePkce { get; set; } = true;

        public bool AllowPlainTextPkce { get; set; } = false;

        [Url]
        public string? LogoUri { get; set; }

        [Url]
        public string? ClientUri { get; set; }

        [Url]
        public string? TosUri { get; set; }

        [Url]
        public string? PolicyUri { get; set; }

        public bool Enabled { get; set; } = true;
    }

    /// <summary>
    /// OAuth scope definition
    /// </summary>
    public class OAuthScope
    {
        public string Name { get; set; } = string.Empty;
        public string DisplayName { get; set; } = string.Empty;
        public string? Description { get; set; }
        public bool Required { get; set; } = false;
        public bool Emphasize { get; set; } = false;
    }
}
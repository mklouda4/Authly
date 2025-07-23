using System.ComponentModel.DataAnnotations;

namespace Authly.Models
{
    /// <summary>
    /// Model for long-lived authentication tokens
    /// </summary>
    public class Token
    {
        /// <summary>
        /// Unique token ID
        /// </summary>
        public string Id { get; set; } = string.Empty;

        /// <summary>
        /// Reference to the user who owns this token
        /// </summary>
        public string UserId { get; set; } = string.Empty;

        /// <summary>
        /// The actual token value (should be securely generated)
        /// </summary>
        public string TokenValue { get; set; } = string.Empty;

        /// <summary>
        /// Human-readable name/description for the token
        /// </summary>
        public string Name { get; set; } = string.Empty;

        /// <summary>
        /// When the token was created
        /// </summary>
        public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// When the token was last used (null if never used)
        /// </summary>
        public DateTime? LastUsedUtc { get; set; }

        /// <summary>
        /// When the token expires (null for infinite/long-lived tokens)
        /// </summary>
        public DateTime? ExpiresUtc { get; set; }

        /// <summary>
        /// Whether the token is currently active
        /// </summary>
        public bool IsActive { get; set; } = true;

        /// <summary>
        /// IP address from which the token was created
        /// </summary>
        public string? CreatedFromIp { get; set; }

        /// <summary>
        /// User agent string from when the token was created
        /// </summary>
        public string? CreatedFromUserAgent { get; set; }

        /// <summary>
        /// Additional scopes or permissions for this token (JSON string)
        /// </summary>
        public string? Scopes { get; set; }

        /// <summary>
        /// Indicates if the token is currently valid (active and not expired)
        /// </summary>
        public bool IsValid => IsActive && (ExpiresUtc == null || ExpiresUtc > DateTime.UtcNow);
    }

    /// <summary>
    /// Request model for creating a new token
    /// </summary>
    public class CreateTokenRequest
    {
        /// <summary>
        /// User ID for whom to create the token
        /// </summary>
        [Required]
        public string UserId { get; set; } = string.Empty;

        /// <summary>
        /// Human-readable name for the token
        /// </summary>
        [Required]
        [StringLength(100, MinimumLength = 1)]
        public string Name { get; set; } = string.Empty;

        /// <summary>
        /// Token expiration date (null for infinite)
        /// </summary>
        public DateTime? ExpiresUtc { get; set; }

        /// <summary>
        /// Additional scopes or permissions
        /// </summary>
        public string? Scopes { get; set; }
    }

    /// <summary>
    /// Response model when creating a token
    /// </summary>
    public class CreateTokenResponse
    {
        /// <summary>
        /// The created token information
        /// </summary>
        public Token Token { get; set; } = new();

        /// <summary>
        /// The actual token value (only shown once)
        /// </summary>
        public string TokenValue { get; set; } = string.Empty;
    }
}
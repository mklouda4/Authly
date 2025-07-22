namespace Authly.Models
{
    /// <summary>
    /// Request model for authentication endpoints
    /// </summary>
    public class LoginRequest
    {
        /// <summary>
        /// Username for authentication
        /// </summary>
        public string Username { get; set; } = string.Empty;

        /// <summary>
        /// Password for authentication
        /// </summary>
        public string Password { get; set; } = string.Empty;

        /// <summary>
        /// TOTP code for two-factor authentication (optional)
        /// </summary>
        public string? TotpCode { get; set; }

        /// <summary>
        /// Keep user signed in for extended period
        /// </summary>
        public bool IsPersistent { get; set; } = true;

        /// <summary>
        /// URL to redirect to after successful login
        /// </summary>
        public string? ReturnUrl { get; set; }
    }
}

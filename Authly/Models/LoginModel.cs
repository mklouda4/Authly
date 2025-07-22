namespace Authly.Models
{
    /// <summary>
    /// Model for user login requests
    /// </summary>
    public class LoginModel
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
        public string TotpCode { get; set; } = string.Empty;
    }
}
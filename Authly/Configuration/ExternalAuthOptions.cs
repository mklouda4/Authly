namespace Authly.Configuration
{
    /// <summary>
    /// External authentication configuration options
    /// </summary>
    public class ExternalAuthOptions
    {
        /// <summary>
        /// Enable Google authentication
        /// </summary>
        public bool EnableGoogle { get; set; } = false;
        
        /// <summary>
        /// Enable Facebook authentication
        /// </summary>
        public bool EnableFacebook { get; set; } = false;

        /// <summary>
        /// Enable Microsoft authentication
        /// </summary>
        public bool EnableMicrosoft { get; set; } = false;

        /// <summary>
        /// Enable GitHub authentication
        /// </summary>
        public bool EnableGitHub { get; set; } = false;
    }
}
namespace Authly.Configuration
{
    /// <summary>
    /// IP-based rate limiting configuration options
    /// </summary>
    public class IpRateLimitingOptions
    {
        /// <summary>
        /// Enable IP-based rate limiting functionality
        /// </summary>
        public bool Enabled { get; set; } = false;

        /// <summary>
        /// Maximum number of attempts per IP address
        /// </summary>
        public int MaxAttemptsPerIp { get; set; } = 10;

        /// <summary>
        /// Duration of IP ban in minutes
        /// </summary>
        public int BanDurationMinutes { get; set; } = 60;

        /// <summary>
        /// Use sliding window for IP attempts tracking
        /// </summary>
        public bool SlidingWindow { get; set; } = true;

        /// <summary>
        /// Time window in minutes for sliding window
        /// </summary>
        public int WindowMinutes { get; set; } = 15;
    }
}
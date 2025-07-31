namespace Authly.Configuration
{
    /// <summary>
    /// User lockout configuration options
    /// </summary>
    public class UserLockoutOptions
    {
        /// <summary>
        /// Enable user lockout functionality
        /// </summary>
        public bool Enabled { get; set; } = false;

        /// <summary>
        /// Maximum number of failed attempts before lockout
        /// </summary>
        public int MaxFailedAttempts { get; set; } = 5;

        /// <summary>
        /// Duration of user lockout in minutes
        /// </summary>
        public int LockoutDurationMinutes { get; set; } = 30;

        /// <summary>
        /// Use sliding window for failed attempts tracking
        /// </summary>
        public bool SlidingWindow { get; set; } = true;

        /// <summary>
        /// Time window in minutes for sliding window
        /// </summary>
        public int WindowMinutes { get; set; } = 15;
    }
}
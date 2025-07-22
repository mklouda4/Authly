namespace Authly.Models
{
    /// <summary>
    /// Authentication attempt result
    /// </summary>
    public class AuthenticationResult
    {
        /// <summary>
        /// Indicates if authentication was successful
        /// </summary>
        public bool Success { get; set; } = false;

        /// <summary>
        /// User if authentication was successful
        /// </summary>
        public User? User { get; set; }

        /// <summary>
        /// Error message if authentication failed
        /// </summary>
        public string? ErrorMessage { get; set; }

        /// <summary>
        /// Indicates if user is locked out
        /// </summary>
        public bool IsUserLockedOut { get; set; } = false;

        /// <summary>
        /// Indicates if IP is banned
        /// </summary>
        public bool IsIpBanned { get; set; } = false;

        /// <summary>
        /// Lockout/ban end time
        /// </summary>
        public DateTime? LockoutEndUtc { get; set; }

        /// <summary>
        /// Remaining failed attempts before lockout
        /// </summary>
        public int RemainingAttempts { get; set; } = 0;

        /// <summary>
        /// Creates a successful authentication result
        /// </summary>
        public static AuthenticationResult SuccessResult(User user)
        {
            return new AuthenticationResult
            {
                Success = true,
                User = user
            };
        }

        /// <summary>
        /// Creates a failed authentication result
        /// </summary>
        public static AuthenticationResult FailedResult(string errorMessage, int remainingAttempts = 0)
        {
            return new AuthenticationResult
            {
                Success = false,
                ErrorMessage = errorMessage,
                RemainingAttempts = remainingAttempts
            };
        }

        /// <summary>
        /// Creates a locked out user result
        /// </summary>
        public static AuthenticationResult LockedOutResult(DateTime lockoutEnd)
        {
            return new AuthenticationResult
            {
                Success = false,
                IsUserLockedOut = true,
                LockoutEndUtc = lockoutEnd,
                ErrorMessage = "User is locked out"
            };
        }

        /// <summary>
        /// Creates an IP banned result
        /// </summary>
        public static AuthenticationResult IpBannedResult(DateTime banEnd)
        {
            return new AuthenticationResult
            {
                Success = false,
                IsIpBanned = true,
                LockoutEndUtc = banEnd,
                ErrorMessage = "IP address is banned"
            };
        }
    }
}
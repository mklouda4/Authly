using Microsoft.AspNetCore.Identity;

namespace Authly.Models
{
    /// <summary>
    /// Application user model extending ASP.NET Core Identity
    /// </summary>
    public class User : IdentityUser
    {
        /// <summary>
        /// User's full display name
        /// </summary>
        public string FullName { get; set; } = string.Empty;
        
        /// <summary>
        /// Indicates if TOTP (Time-based One-Time Password) is enabled for this user
        /// </summary>
        public bool HasTotp { get; set; } = false;
        
        /// <summary>
        /// TOTP secret key for generating authentication codes
        /// </summary>
        public string? TotpSecret { get; set; }

        /// <summary>
        /// Password property for compatibility (maps to PasswordHash)
        /// </summary>
        public string? Password
        {
            get => PasswordHash;
            set => PasswordHash = value;
        }

        /// <summary>
        /// Number of failed login attempts for this user
        /// </summary>
        public int FailedLoginAttempts { get; set; } = 0;

        /// <summary>
        /// Timestamp of the last failed login attempt
        /// </summary>
        public DateTime? LastFailedLoginAttempt { get; set; }

        /// <summary>
        /// Timestamp when the user lockout starts
        /// </summary>
        public DateTime? LockoutStart { get; set; }

        /// <summary>
        /// Timestamp when the user lockout ends
        /// </summary>
        public new DateTime? LockoutEnd { get; set; }

        /// <summary>
        /// Indicates if the user is currently locked out
        /// </summary>
        public bool IsLockedOut => LockoutEnd.HasValue && LockoutEnd > DateTime.UtcNow;

        /// <summary>
        /// Indicates if the user has administrator privileges
        /// </summary>
        public bool Administrator { get; set; } = false;

        /// <summary>
        /// Indicates if the user is an external user (e.g., from an external identity provider)
        /// </summary>
        public bool IsExternal { get; set; } = false;
    }

    public class SaveUserModel
    {
        /// <summary>
        /// User's login name
        /// </summary>
        public string UserName { get; set; } = string.Empty;

        /// <summary>
        /// User's email address
        /// </summary>
        public string Email { get; set; } = string.Empty;

        /// <summary>
        /// User's full display name
        /// </summary>
        public string FullName { get; set; } = string.Empty;

        /// <summary>
        /// Indicates if TOTP (Time-based One-Time Password) is enabled for this user
        /// </summary>
        public bool HasTotp { get; set; } = false;

        /// <summary>
        /// TOTP secret key for generating authentication codes
        /// </summary>
        public string? TotpSecret { get; set; }

        /// <summary>
        /// Password property for compatibility (maps to PasswordHash)
        /// </summary>
        public string? Password { get; set; }

        /// <summary>
        /// Number of failed login attempts for this user
        /// </summary>
        public int FailedLoginAttempts { get; set; } = 0;

        /// <summary>
        /// Timestamp of the last failed login attempt
        /// </summary>
        public DateTime? LastFailedLoginAttempt { get; set; }

        /// <summary>
        /// Timestamp when the user lockout starts
        /// </summary>
        public DateTime? LockoutStart { get; set; }

        /// <summary>
        /// Timestamp when the user lockout ends
        /// </summary>
        public DateTime? LockoutEnd { get; set; }

        /// <summary>
        /// Indicates if the user is currently locked out
        /// </summary>
        public bool IsLockedOut => LockoutEnd.HasValue && LockoutEnd > DateTime.UtcNow;

        /// <summary>
        /// Indicates if the user has administrator privileges
        /// </summary>
        public bool Administrator { get; set; } = false;

        /// <summary>
        /// Indicates if the user is an external user (e.g., from an external identity provider)
        /// </summary>
        public bool IsExternal { get; set; } = false;
    }
}
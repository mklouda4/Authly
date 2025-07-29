using System.Text.Json.Serialization;

namespace Authly.Models
{
    /// <summary>
    /// Model for tracking IP-based login attempts
    /// </summary>
    public class IpLoginAttempt
    {
        /// <summary>
        /// IP address
        /// </summary>
        public string IpAddress { get; set; } = string.Empty;

        /// <summary>
        /// Number of failed attempts
        /// </summary>
        public int FailedAttempts { get; set; } = 0;

        /// <summary>
        /// First failed attempt timestamp
        /// </summary>
        public DateTime FirstAttemptUtc { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// Last failed attempt timestamp
        /// </summary>
        public DateTime LastAttemptUtc { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// Indicates if IP is currently banned
        /// </summary>
        public bool IsBanned { get; set; } = false;

        /// <summary>
        /// Ban end time (UTC)
        /// </summary>
        public DateTime? BanEndUtc { get; set; }

        /// <summary>
        /// Note
        /// </summary>
        public string? Note { get; set; } = string.Empty;

        /// <summary>
        /// Indicates if the IP is currently banned
        /// </summary>
        [JsonIgnore]
        public bool IsCurrentlyBanned => BanEndUtc.HasValue && BanEndUtc > DateTime.UtcNow;
    }
}
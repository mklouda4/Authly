using Authly.Models;
using Microsoft.AspNetCore.Identity;
using System.Security.Cryptography;

namespace Authly.Authorization
{
    /// <summary>
    /// Password hashing for local users (ASP.NET Core Identity V3 format: PBKDF2-HMAC-SHA512, 100 000 iterations)
    /// </summary>
    public static class PasswordHashing
    {
        private static readonly PasswordHasher<User> Hasher = new();

        /// <summary>
        /// Hashes a plaintext password
        /// </summary>
        public static string Hash(User user, string password) => Hasher.HashPassword(user, password);

        /// <summary>
        /// Verifies a plaintext password against the user's stored hash.
        /// Users without a stored hash (external accounts) never match.
        /// </summary>
        /// <param name="needsRehash">True when the hash should be upgraded to the current parameters</param>
        public static bool Verify(User user, string? password, out bool needsRehash)
        {
            needsRehash = false;
            if (string.IsNullOrEmpty(password) || !IsHashed(user.PasswordHash))
            {
                return false;
            }

            var result = Hasher.VerifyHashedPassword(user, user.PasswordHash!, password);
            needsRehash = result == PasswordVerificationResult.SuccessRehashNeeded;
            return result != PasswordVerificationResult.Failed;
        }

        /// <summary>
        /// Checks whether the value is an Identity password hash (V2 or V3 format) and not a plaintext password
        /// </summary>
        public static bool IsHashed(string? value)
        {
            if (string.IsNullOrEmpty(value))
            {
                return false;
            }

            var buffer = new byte[value.Length];
            if (!Convert.TryFromBase64String(value, buffer, out var length))
            {
                return false;
            }

            // V2: 0x00 + 16 B salt + 32 B subkey; V3: 0x01 + 12 B header + salt (>= 16 B) + subkey (>= 16 B)
            return (buffer[0] == 0x00 && length == 49) || (buffer[0] == 0x01 && length >= 13 + 32);
        }

        /// <summary>
        /// Generates a random password for bootstrap accounts
        /// </summary>
        public static string GenerateRandomPassword(int length = 24)
        {
            const string alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789";
            return RandomNumberGenerator.GetString(alphabet, length);
        }
    }
}

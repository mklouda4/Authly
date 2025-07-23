using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Xml.Serialization;

namespace Authly.Extension
{
    /// <summary>
    /// Extension methods for HttpContext
    /// </summary>
    public static class StringExtensions
    {
        /// <summary>
        /// Generates a deterministic string from a string input using MD5 hashing.
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        public static string GetDeterministicStringFromString(this string input)
        {
            var guid = input.GetDeterministicGuidFromString();
            return guid.ToString("N");
        }

        /// <summary>
        /// Generates a deterministic GUID from a string input using MD5 hashing.
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        public static Guid GetDeterministicGuidFromString(this string input)
        {
            if (string.IsNullOrEmpty(input))
                return Guid.Empty;

            var hash = System.Security.Cryptography.MD5.HashData(System.Text.Encoding.UTF8.GetBytes(input));
            return new Guid(hash);
        }
    }
}

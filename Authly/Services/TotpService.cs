using OtpNet;

namespace Authly.Services
{
    /// <summary>
    /// Interface for TOTP operations
    /// </summary>
    public interface ITotpService
    {
        /// <summary>
        /// Generates current TOTP code for given secret
        /// </summary>
        /// <param name="secret">Base32 encoded secret key</param>
        /// <returns>Current 6-digit TOTP code</returns>
        string GenerateCode(string secret);

        /// <summary>
        /// Gets remaining seconds until next code
        /// </summary>
        /// <returns>Seconds remaining (0-29)</returns>
        int GetRemainingSeconds();

        /// <summary>
        /// Validates TOTP code
        /// </summary>
        /// <param name="secret">Base32 encoded secret key</param>
        /// <param name="code">Code to validate</param>
        /// <returns>True if code is valid</returns>
        bool ValidateCode(string secret, string code);
    }

    /// <summary>
    /// Service for TOTP operations
    /// </summary>
    public class TotpService : ITotpService
    {
        private const int TimeStep = 30; // TOTP time step in seconds

        /// <summary>
        /// Generates current TOTP code for given secret
        /// </summary>
        /// <param name="secret">Base32 encoded secret key</param>
        /// <returns>Current 6-digit TOTP code</returns>
        public string GenerateCode(string secret)
        {
            try
            {
                var key = Base32Encoding.ToBytes(secret);
                var totp = new Totp(key);
                return totp.ComputeTotp();
            }
            catch
            {
                return "------";
            }
        }

        /// <summary>
        /// Gets remaining seconds until next code
        /// </summary>
        /// <returns>Seconds remaining (0-29)</returns>
        public int GetRemainingSeconds()
        {
            var unixTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var timeStepNumber = unixTime / TimeStep;
            var nextTimeStep = (timeStepNumber + 1) * TimeStep;
            return (int)(nextTimeStep - unixTime);
        }

        /// <summary>
        /// Validates TOTP code
        /// </summary>
        /// <param name="secret">Base32 encoded secret key</param>
        /// <param name="code">Code to validate</param>
        /// <returns>True if code is valid</returns>
        public bool ValidateCode(string secret, string code)
        {
            try
            {
                var key = Base32Encoding.ToBytes(secret);
                var totp = new Totp(key);
                return totp.VerifyTotp(code, out _, new VerificationWindow(2, 2));
            }
            catch
            {
                return false;
            }
        }
    }
}
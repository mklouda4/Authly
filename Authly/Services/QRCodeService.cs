using QRCoder;

namespace Authly.Services
{
    /// <summary>
    /// Interface for QR code generation service
    /// </summary>
    public interface IQRCodeService
    {
        /// <summary>
        /// Generates a QR code for TOTP setup
        /// </summary>
        /// <param name="email">User's email address</param>
        /// <param name="secret">TOTP secret key</param>
        /// <param name="applicationName">Application name</param>
        /// <returns>Base64 encoded PNG image of the QR code</returns>
        string GenerateTotpQRCode(string email, string secret, string applicationName);
    }

    /// <summary>
    /// Service for generating QR codes
    /// </summary>
    public class QRCodeService : IQRCodeService
    {
        /// <summary>
        /// Generates a QR code for TOTP setup compatible with Google Authenticator and Microsoft Authenticator
        /// </summary>
        /// <param name="email">User's email address</param>
        /// <param name="secret">TOTP secret key</param>
        /// <param name="applicationName">Application name</param>
        /// <returns>Base64 encoded PNG image of the QR code</returns>
        public string GenerateTotpQRCode(string email, string secret, string applicationName)
        {
            // Create the otpauth URI format for authenticator apps
            var otpauthUri = $"otpauth://totp/{Uri.EscapeDataString(applicationName)}:{Uri.EscapeDataString(email)}?secret={secret}&issuer={Uri.EscapeDataString(applicationName)}";

            // Generate QR code
            using var qrGenerator = new QRCodeGenerator();
            var qrCodeData = qrGenerator.CreateQrCode(otpauthUri, QRCodeGenerator.ECCLevel.Q);
            using var qrCode = new PngByteQRCode(qrCodeData);
            var qrCodeBytes = qrCode.GetGraphic(20);

            // Convert to base64 string
            return Convert.ToBase64String(qrCodeBytes);
        }
    }
}
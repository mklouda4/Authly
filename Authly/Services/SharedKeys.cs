using Authly.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;

namespace Authly.Services
{
    public interface ISharedKeys : IDisposable
    {
        RSA RSA { get; }
        SymmetricSecurityKey HMAC { get; }
        bool RSAIsAvailable { get; }
    }
    public class SharedKeys : ISharedKeys
    {
        private readonly OidcOptions _oidcOptions;
        private readonly IApplicationLogger _logger;
        private readonly IConfiguration _configuration;
        private RSA? _rsa;
        private SymmetricSecurityKey? _hmac;

        public SharedKeys(OidcOptions oidcOptions, IApplicationLogger logger, IConfiguration configuration)
        {
            _oidcOptions = oidcOptions;
            _logger = logger;
            _configuration = configuration;
            _ = RSA;
            _ = HMAC;
        }

        public bool RSAIsAvailable { get; private set; } = false;

        public RSA RSA
        {
            get
            {
                if (_rsa != null)
                {
                    return _rsa;
                }

                try
                {
                    var keyString = _oidcOptions.RsaPrivateKey;

                    if (!string.IsNullOrEmpty(keyString))
                    {
                        // Load RSA key from configuration (base64 encoded)
                        _rsa = RSA.Create();
                        _rsa.ImportRSAPrivateKey(Convert.FromBase64String(keyString), out _);
                        _logger.LogInfo(nameof(SharedKeys), "RSA private key loaded from configuration");
                        RSAIsAvailable = true;
                    }
                    else
                    {
                        // Generate new key (only for development!)
                        _rsa = RSA.Create(2048);
                        _logger.LogWarning(nameof(SharedKeys), "Generated new RSA key - use RsaPrivateKey in production!");

                        // For development - log the private key
                        var privateKeyBytes = _rsa.ExportRSAPrivateKey();
                        var privateKeyBase64 = Convert.ToBase64String(privateKeyBytes);
                        _logger.LogInfo(nameof(SharedKeys), $"Generated RSA Private Key (base64): {privateKeyBase64}");
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(nameof(SharedKeys), "Failed to load RSA key, generating new one", ex);
                    _rsa = RSA.Create(2048);
                }

                return _rsa;
            }
        }
        public SymmetricSecurityKey HMAC
        {
            get
            {
                if (_hmac != null)
                {
                    return _hmac;
                }

                var signingKeyString = _configuration["OAuth:SigningKey"] ?? Environment.GetEnvironmentVariable("OAUTH_SIGNING_KEY");
                if (string.IsNullOrEmpty(signingKeyString))
                {
                    var key = new byte[32];
                    using var rng = RandomNumberGenerator.Create();
                    rng.GetBytes(key);
                    signingKeyString = Convert.ToBase64String(key);
                    _logger.LogWarning("DatabaseOAuthAuthorizationService", "Generated new HMAC signing key. In production, persist this key!");
                }

                _hmac ??= new SymmetricSecurityKey(Convert.FromBase64String(signingKeyString))
                {
                    KeyId = "authly-hmac-key-1"
                };
                return _hmac;
            }
        }

        public void Dispose() 
            => _rsa?.Dispose();
    }
}
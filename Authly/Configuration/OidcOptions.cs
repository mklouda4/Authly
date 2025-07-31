namespace Authly.Configuration
{
    public class OidcOptions
    {
        public const string SectionName = "Oidc";

        public bool Enabled { get; set; } = true;
        public string? Issuer { get; set; } = "https://authly.local";
        public string? Audience { get; set; } = "authly";
        public string? SigningKey { get; set; } = "authly-rsa-key-1";
        public string? RsaPrivateKey { get; set; }
        public int IdTokenLifetimeMinutes { get; set; } = 30;
    }
}
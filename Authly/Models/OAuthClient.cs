using Authly.Controllers;
using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace Authly.Models
{
    /// <summary>
    /// OAuth Client application model for registered third-party applications
    /// </summary>
    public class OAuthClient
    {
        /// <summary>
        /// Unique client identifier
        /// </summary>
        public string ClientId { get; set; } = string.Empty;

        /// <summary>
        /// Client secret for confidential clients
        /// </summary>
        public string? ClientSecret { get; set; }

        /// <summary>
        /// Human-readable client name
        /// </summary>
        public string ClientName { get; set; } = string.Empty;

        /// <summary>
        /// Client description
        /// </summary>
        public string? Description { get; set; }

        /// <summary>
        /// Client type (public, confidential)
        /// </summary>
        public OAuthClientType ClientType { get; set; } = OAuthClientType.Confidential;

        /// <summary>
        /// Allowed redirect URIs (JSON array)
        /// </summary>
        public List<string> RedirectUris { get; set; } = new();

        /// <summary>
        /// Allowed grant types
        /// </summary>
        public List<OAuthGrantType> AllowedGrantTypes { get; set; } = new();

        /// <summary>
        /// Allowed scopes
        /// </summary>
        public List<string> AllowedScopes { get; set; } = new();

        /// <summary>
        /// Access token lifetime in seconds
        /// </summary>
        public int AccessTokenLifetime { get; set; } = 3600; // 1 hour

        /// <summary>
        /// Refresh token lifetime in seconds (null for no refresh tokens)
        /// </summary>
        public int? RefreshTokenLifetime { get; set; } = 86400; // 24 hours

        /// <summary>
        /// Whether the client requires PKCE
        /// </summary>
        public bool RequirePkce { get; set; } = true;

        /// <summary>
        /// Whether the client allows plain text PKCE (not recommended)
        /// </summary>
        public bool AllowPlainTextPkce { get; set; } = false;

        /// <summary>
        /// Client logo URL
        /// </summary>
        public string? LogoUri { get; set; }

        /// <summary>
        /// Client website URL
        /// </summary>
        public string? ClientUri { get; set; }

        /// <summary>
        /// Terms of service URL
        /// </summary>
        public string? TosUri { get; set; }

        /// <summary>
        /// Privacy policy URL
        /// </summary>
        public string? PolicyUri { get; set; }

        /// <summary>
        /// When the client was created
        /// </summary>
        public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// When the client was last modified
        /// </summary>
        public DateTime ModifiedUtc { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// Whether the client is enabled
        /// </summary>
        public bool Enabled { get; set; } = true;

        /// <summary>
        /// Who created this client
        /// </summary>
        public string? CreatedBy { get; set; }

        /// <summary>
        /// Additional custom properties
        /// </summary>
        public Dictionary<string, string> Properties { get; set; } = new();
    }

    /// <summary>
    /// OAuth client types
    /// </summary>
    public enum OAuthClientType
    {
        /// <summary>
        /// Confidential client (can securely store credentials)
        /// </summary>
        Confidential,
        
        /// <summary>
        /// Public client (cannot securely store credentials)
        /// </summary>
        Public
    }

    /// <summary>
    /// OAuth grant types
    /// </summary>
    public enum OAuthGrantType
    {
        /// <summary>
        /// Authorization Code Grant
        /// </summary>
        AuthorizationCode,
        
        /// <summary>
        /// Client Credentials Grant
        /// </summary>
        ClientCredentials,
        
        /// <summary>
        /// Refresh Token Grant
        /// </summary>
        RefreshToken,
        
        /// <summary>
        /// Device Code Grant
        /// </summary>
        DeviceCode
    }

    /// <summary>
    /// OAuth 2.0 Authorization Request (RFC 6749 Section 4.1.1)
    /// </summary>
    public class OAuthAuthorizationRequest
    {
        /// <summary>
        /// REQUIRED. The client identifier as described in Section 2.2.
        /// </summary>
        [JsonPropertyName("client_id")]
        [FromQuery(Name = "client_id")]
        public string ClientId { get; set; } = string.Empty;

        /// <summary>
        /// REQUIRED. The client redirection endpoint as described in Section 3.1.2.
        /// </summary>
        [JsonPropertyName("redirect_uri")]
        [FromQuery(Name = "redirect_uri")]
        public string RedirectUri { get; set; } = string.Empty;

        /// <summary>
        /// REQUIRED. Value MUST be set to "code" for authorization code flow.
        /// </summary>
        [JsonPropertyName("response_type")]
        [FromQuery(Name = "response_type")]
        public string ResponseType { get; set; } = "code";

        /// <summary>
        /// RECOMMENDED. An unguessable random string. Used to prevent CSRF attacks.
        /// </summary>
        [JsonPropertyName("state")]
        [FromQuery(Name = "state")]
        public string? State { get; set; }

        /// <summary>
        /// OPTIONAL. The scope of the access request as described by Section 3.3.
        /// </summary>
        [JsonPropertyName("scope")]
        [FromQuery(Name = "scope")]
        public string? Scope { get; set; }

        /// <summary>
        /// OPTIONAL. Code challenge for PKCE (RFC 7636).
        /// </summary>
        [JsonPropertyName("code_challenge")]
        [FromQuery(Name = "code_challenge")]
        public string? CodeChallenge { get; set; }

        /// <summary>
        /// OPTIONAL. Code challenge method for PKCE. MUST be "S256" or "plain".
        /// </summary>
        [JsonPropertyName("code_challenge_method")]
        [FromQuery(Name = "code_challenge_method")]
        public string? CodeChallengeMethod { get; set; }

        /// <summary>
        /// OPTIONAL. String value used to associate a Client session with an ID Token (OpenID Connect).
        /// </summary>
        [JsonPropertyName("nonce")]
        [FromQuery(Name = "nonce")]
        public string? Nonce { get; set; }

        /// <summary>
        /// OPTIONAL. Space delimited, case sensitive list of ASCII string values (OpenID Connect).
        /// </summary>
        [JsonPropertyName("response_mode")]
        [FromQuery(Name = "response_mode")]
        public string? ResponseMode { get; set; }

        /// <summary>
        /// OPTIONAL. Requested Authentication Context Class Reference values (OpenID Connect).
        /// </summary>
        [JsonPropertyName("acr_values")]
        [FromQuery(Name = "acr_values")]
        public string? AcrValues { get; set; }
    }

    /// <summary>
    /// OAuth 2.0 Token Request (RFC 6749 Section 4.1.3)
    /// </summary>
    public class OAuthTokenRequest
    {
        /// <summary>
        /// REQUIRED. Value MUST be set to "authorization_code", "refresh_token", "client_credentials", or "password".
        /// </summary>
        [JsonPropertyName("grant_type")]
        [FromForm(Name = "grant_type")]
        public string GrantType { get; set; } = string.Empty;

        /// <summary>
        /// REQUIRED. The client identifier as described in Section 2.2.
        /// </summary>
        [JsonPropertyName("client_id")]
        [FromForm(Name = "client_id")]
        public string ClientId { get; set; } = string.Empty;

        /// <summary>
        /// REQUIRED for confidential clients. The client secret.
        /// </summary>
        [JsonPropertyName("client_secret")]
        [FromForm(Name = "client_secret")]
        public string? ClientSecret { get; set; }

        /// <summary>
        /// REQUIRED for authorization_code grant. The authorization code received from the authorization server.
        /// </summary>
        [JsonPropertyName("code")]
        [FromForm(Name = "code")]
        public string? Code { get; set; }

        /// <summary>
        /// REQUIRED if redirect_uri was included in authorization request. Must be identical.
        /// </summary>
        [JsonPropertyName("redirect_uri")]
        [FromForm(Name = "redirect_uri")]
        public string? RedirectUri { get; set; }

        /// <summary>
        /// REQUIRED for PKCE. Code verifier for the PKCE request.
        /// </summary>
        [JsonPropertyName("code_verifier")]
        [FromForm(Name = "code_verifier")]
        public string? CodeVerifier { get; set; }

        /// <summary>
        /// REQUIRED for refresh_token grant. The refresh token issued to the client.
        /// </summary>
        [JsonPropertyName("refresh_token")]
        [FromForm(Name = "refresh_token")]
        public string? RefreshToken { get; set; }

        /// <summary>
        /// OPTIONAL. The scope of the access request as described by Section 3.3.
        /// </summary>
        [JsonPropertyName("scope")]
        [FromForm(Name = "scope")]
        public string? Scope { get; set; }

        /// <summary>
        /// REQUIRED for resource owner password credentials grant. The resource owner username.
        /// </summary>
        [JsonPropertyName("username")]
        [FromForm(Name = "username")]
        public string? Username { get; set; }

        /// <summary>
        /// REQUIRED for resource owner password credentials grant. The resource owner password.
        /// </summary>
        [JsonPropertyName("password")]
        [FromForm(Name = "password")]
        public string? Password { get; set; }
    }

    /// <summary>
    /// OAuth 2.0 Token Response (RFC 6749 Section 5.1)
    /// </summary>
    public class OAuthTokenResponse
    {
        /// <summary>
        /// REQUIRED. The access token issued by the authorization server.
        /// </summary>
        [JsonPropertyName("access_token")]
        public string AccessToken { get; set; } = string.Empty;

        /// <summary>
        /// REQUIRED. The type of the token issued. Value is case insensitive and typically "Bearer".
        /// </summary>
        [JsonPropertyName("token_type")]
        public string TokenType { get; set; } = "Bearer";

        /// <summary>
        /// RECOMMENDED. The lifetime in seconds of the access token.
        /// </summary>
        [JsonPropertyName("expires_in")]
        public int? ExpiresIn { get; set; }

        /// <summary>
        /// OPTIONAL. The refresh token, which can be used to obtain new access tokens.
        /// </summary>
        [JsonPropertyName("refresh_token")]
        public string? RefreshToken { get; set; }

        /// <summary>
        /// OPTIONAL. The scope of the access token as described by Section 3.3.
        /// </summary>
        [JsonPropertyName("scope")]
        public string? Scope { get; set; }

        /// <summary>
        /// OPTIONAL. The identifier of the resource owner (OpenID Connect).
        /// </summary>
        [JsonPropertyName("id_token")]
        public string? IdToken { get; set; }
    }
    public class OidcTokenResponse : OAuthTokenResponse
    {
        /// <summary>
        /// REQUIRED. The id token issued by the authorization server.
        /// </summary>
        [JsonPropertyName("id_token")]
        public string? IdToken { get; set; }
    }

    /// <summary>
    /// OAuth 2.0 Error Response (RFC 6749 Section 5.2)
    /// </summary>
    public class OAuthErrorResponse
    {
        /// <summary>
        /// REQUIRED. A single ASCII error code from the predefined list.
        /// </summary>
        [JsonPropertyName("error")]
        public string Error { get; set; } = string.Empty;

        /// <summary>
        /// OPTIONAL. Human-readable ASCII text providing additional information.
        /// </summary>
        [JsonPropertyName("error_description")]
        public string? ErrorDescription { get; set; }

        /// <summary>
        /// OPTIONAL. URI identifying a human-readable web page with information about the error.
        /// </summary>
        [JsonPropertyName("error_uri")]
        public string? ErrorUri { get; set; }

        /// <summary>
        /// REQUIRED if state was present in the client authorization request.
        /// </summary>
        [JsonPropertyName("state")]
        public string? State { get; set; }
    }

    /// <summary>
    /// OAuth authorization code
    /// </summary>
    public class OAuthAuthorizationCode
    {
        public string Code { get; set; } = string.Empty;
        public string ClientId { get; set; } = string.Empty;
        public string UserId { get; set; } = string.Empty;
        public string RedirectUri { get; set; } = string.Empty;
        public List<string> Scopes { get; set; } = new();
        public string? CodeChallenge { get; set; }
        public string? CodeChallengeMethod { get; set; }
        public string? Nonce { get; set; }
        public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
        public DateTime ExpiresUtc { get; set; } = DateTime.UtcNow.AddMinutes(10); // 10 minutes
        public bool IsExpired => DateTime.UtcNow > ExpiresUtc;
        public bool IsUsed { get; set; } = false;
    }

    /// <summary>
    /// OAuth access token
    /// </summary>
    public class OAuthAccessToken
    {
        public string TokenId { get; set; } = string.Empty;
        public string AccessToken { get; set; } = string.Empty;
        public string ClientId { get; set; } = string.Empty;
        public string UserId { get; set; } = string.Empty;
        public List<string> Scopes { get; set; } = new();
        public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
        public DateTime ExpiresUtc { get; set; }
        public bool IsExpired => DateTime.UtcNow > ExpiresUtc;
        public bool IsRevoked { get; set; } = false;
    }

    /// <summary>
    /// OAuth refresh token
    /// </summary>
    public class OAuthRefreshToken
    {
        public string TokenId { get; set; } = string.Empty;
        public string RefreshToken { get; set; } = string.Empty;
        public string AccessTokenId { get; set; } = string.Empty;
        public string ClientId { get; set; } = string.Empty;
        public string UserId { get; set; } = string.Empty;
        public List<string> Scopes { get; set; } = new();
        public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
        public DateTime ExpiresUtc { get; set; }
        public bool IsExpired => DateTime.UtcNow > ExpiresUtc;
        public bool IsRevoked { get; set; } = false;
    }

    /// <summary>
    /// Request model for creating OAuth client
    /// </summary>
    public class CreateOAuthClientRequest
    {
        [Required]
        [StringLength(100, MinimumLength = 1)]
        public string ClientName { get; set; } = string.Empty;

        [StringLength(500)]
        public string? Description { get; set; }

        [Required]
        public OAuthClientType ClientType { get; set; } = OAuthClientType.Confidential;

        [Required]
        [MinLength(1)]
        public List<string> RedirectUris { get; set; } = new();

        [Required]
        [MinLength(1)]
        public List<OAuthGrantType> AllowedGrantTypes { get; set; } = new();

        [Required]
        [MinLength(1)]
        public List<string> AllowedScopes { get; set; } = new();

        [Range(300, 86400)] // 5 minutes to 24 hours
        public int AccessTokenLifetime { get; set; } = 3600;

        [Range(300, 2592000)] // 5 minutes to 30 days
        public int? RefreshTokenLifetime { get; set; } = 86400;

        public bool RequirePkce { get; set; } = true;

        public bool AllowPlainTextPkce { get; set; } = false;

        [Url]
        public string? LogoUri { get; set; }

        [Url]
        public string? ClientUri { get; set; }

        [Url]
        public string? TosUri { get; set; }

        [Url]
        public string? PolicyUri { get; set; }
    }

    /// <summary>
    /// Request model for updating OAuth client
    /// </summary>
    public class UpdateOAuthClientRequest
    {
        [Required]
        public string ClientId { get; set; } = string.Empty;

        [Required]
        [StringLength(100, MinimumLength = 1)]
        public string ClientName { get; set; } = string.Empty;

        [StringLength(500)]
        public string? Description { get; set; }

        [Required]
        [MinLength(1)]
        public List<string> RedirectUris { get; set; } = new();

        [Required]
        [MinLength(1)]
        public List<string> AllowedScopes { get; set; } = new();

        [Range(300, 86400)] // 5 minutes to 24 hours
        public int AccessTokenLifetime { get; set; } = 3600;

        [Range(300, 2592000)] // 5 minutes to 30 days
        public int? RefreshTokenLifetime { get; set; } = 86400;

        public bool RequirePkce { get; set; } = true;

        public bool AllowPlainTextPkce { get; set; } = false;

        [Url]
        public string? LogoUri { get; set; }

        [Url]
        public string? ClientUri { get; set; }

        [Url]
        public string? TosUri { get; set; }

        [Url]
        public string? PolicyUri { get; set; }

        public bool Enabled { get; set; } = true;
    }

    /// <summary>
    /// OAuth scope definition
    /// </summary>
    public class OAuthScope
    {
        public string Name { get; set; } = string.Empty;
        public string DisplayName { get; set; } = string.Empty;
        public string? Description { get; set; }
        public bool Required { get; set; } = false;
        public bool Emphasize { get; set; } = false;
    }
}
using Authly.Models;
using Microsoft.AspNetCore.Mvc;
using System.Net;
using System.Text;

namespace Authly.Extension
{
    /// <summary>
    /// Client authentication method used on the token endpoint
    /// </summary>
    public enum ClientAuthenticationMethod
    {
        /// <summary>No client secret sent (public client)</summary>
        None,
        /// <summary>client_id + client_secret in the request body</summary>
        ClientSecretPost,
        /// <summary>client_id + client_secret in the Authorization: Basic header</summary>
        ClientSecretBasic
    }

    /// <summary>
    /// Client credentials extracted from an Authorization: Basic header.
    /// Raw values are the strings before form-url-decoding.
    /// </summary>
    public sealed record BasicClientCredentials(string ClientId, string ClientSecret, string RawClientId, string RawClientSecret);

    /// <summary>
    /// Result of token endpoint client authentication
    /// </summary>
    public sealed record ClientAuthenticationResult(ClientAuthenticationMethod Method, string? Error = null, string? ErrorDescription = null)
    {
        public bool Succeeded => Error == null;

        /// <summary>
        /// Method name as used in token_endpoint_auth_methods_supported
        /// </summary>
        public string MethodName => Method switch
        {
            ClientAuthenticationMethod.ClientSecretBasic => "client_secret_basic",
            ClientAuthenticationMethod.ClientSecretPost => "client_secret_post",
            _ => "none"
        };
    }

    /// <summary>
    /// Token endpoint client authentication (RFC 6749 §2.3.1)
    /// </summary>
    public static class ClientAuthenticationExtensions
    {
        private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

        /// <summary>
        /// Checks whether the Authorization header uses the Basic scheme (case-insensitive) and returns its parameter
        /// </summary>
        public static bool TryGetBasicParameter(string? authorizationHeader, out string parameter)
        {
            parameter = string.Empty;
            if (string.IsNullOrWhiteSpace(authorizationHeader))
            {
                return false;
            }

            var value = authorizationHeader.Trim();
            var separator = value.IndexOf(' ');
            var scheme = separator < 0 ? value : value[..separator];
            if (!scheme.Equals("Basic", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            parameter = separator < 0 ? string.Empty : value[(separator + 1)..].Trim();
            return true;
        }

        /// <summary>
        /// Decodes the Basic credentials: base64 (UTF-8) → split on first ':' → form-url-decode both parts
        /// </summary>
        public static bool TryDecodeBasicCredentials(string parameter, out BasicClientCredentials? credentials)
        {
            credentials = null;
            if (string.IsNullOrEmpty(parameter))
            {
                return false;
            }

            string decoded;
            try
            {
                decoded = StrictUtf8.GetString(Convert.FromBase64String(parameter));
            }
            catch (Exception ex) when (ex is FormatException or DecoderFallbackException)
            {
                return false;
            }

            var colon = decoded.IndexOf(':');
            if (colon <= 0)
            {
                return false;
            }

            var rawClientId = decoded[..colon];
            var rawClientSecret = decoded[(colon + 1)..];

            // application/x-www-form-urlencoded: '+' → space, %XX → byte
            credentials = new BasicClientCredentials(
                WebUtility.UrlDecode(rawClientId),
                WebUtility.UrlDecode(rawClientSecret),
                rawClientId,
                rawClientSecret);
            return true;
        }

        /// <summary>
        /// Resolves client credentials for a token request. When an Authorization: Basic header is present,
        /// the credentials are decoded, validated and copied into <paramref name="tokenRequest"/>.
        /// Without the header the request is left untouched (client_secret_post / none are validated later as before).
        /// </summary>
        public static async Task<ClientAuthenticationResult> AuthenticateClientAsync(
            this HttpRequest httpRequest,
            OAuthTokenRequest tokenRequest,
            Func<string, string?, Task<bool>> validateClientCredentials)
        {
            if (!TryGetBasicParameter(httpRequest.Headers.Authorization.FirstOrDefault(), out var parameter))
            {
                return new ClientAuthenticationResult(string.IsNullOrEmpty(tokenRequest.ClientSecret)
                    ? ClientAuthenticationMethod.None
                    : ClientAuthenticationMethod.ClientSecretPost);
            }

            const ClientAuthenticationMethod basic = ClientAuthenticationMethod.ClientSecretBasic;

            if (!TryDecodeBasicCredentials(parameter, out var credentials))
            {
                return new ClientAuthenticationResult(basic, "invalid_client", "Malformed Basic authorization header");
            }

            // RFC 6749 §2.3: the client MUST NOT use more than one authentication method in each request
            if (!string.IsNullOrEmpty(tokenRequest.ClientSecret))
            {
                return new ClientAuthenticationResult(basic, "invalid_request", "Client credentials must not be sent in both the Authorization header and the request body");
            }

            if (!string.IsNullOrEmpty(tokenRequest.ClientId)
                && tokenRequest.ClientId != credentials!.ClientId
                && tokenRequest.ClientId != credentials.RawClientId)
            {
                return new ClientAuthenticationResult(basic, "invalid_request", "client_id in the request body does not match the Authorization header");
            }

            // Spec-compliant (form-url-decoded) values first, then raw values for clients that skip the encoding
            var candidates = new List<(string ClientId, string ClientSecret)> { (credentials!.ClientId, credentials.ClientSecret) };
            if (credentials.RawClientId != credentials.ClientId || credentials.RawClientSecret != credentials.ClientSecret)
            {
                candidates.Add((credentials.RawClientId, credentials.RawClientSecret));
            }

            foreach (var (clientId, clientSecret) in candidates)
            {
                if (await validateClientCredentials(clientId, clientSecret))
                {
                    tokenRequest.ClientId = clientId;
                    tokenRequest.ClientSecret = clientSecret;
                    return new ClientAuthenticationResult(basic);
                }
            }

            tokenRequest.ClientId = credentials.ClientId;
            return new ClientAuthenticationResult(basic, "invalid_client", "Invalid client credentials");
        }

        /// <summary>
        /// Builds a token endpoint error response. Failed client authentication via the Authorization header
        /// returns 401 with WWW-Authenticate (RFC 6749 §5.2), everything else 400.
        /// </summary>
        public static IActionResult TokenError(this ControllerBase controller, string error, string? errorDescription, ClientAuthenticationMethod method)
        {
            var body = new OAuthErrorResponse
            {
                Error = error,
                ErrorDescription = errorDescription
            };

            if (error == "invalid_client" && method == ClientAuthenticationMethod.ClientSecretBasic)
            {
                controller.Response.Headers.WWWAuthenticate = "Basic realm=\"Authly\", charset=\"UTF-8\"";
                return controller.Unauthorized(body);
            }

            return controller.BadRequest(body);
        }
    }
}

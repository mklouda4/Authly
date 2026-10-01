using Authly.Extension;
using Authly.Models;
using Microsoft.AspNetCore.Http;
using System.Net;
using System.Text;
using Xunit;

namespace Authly.Tests
{
    public class ClientAuthenticationExtensionsTests
    {
        private const string ClientId = "VpQOe3BztKb9Eizs87BzKQ";

        private static string Encode(string clientId, string clientSecret) =>
            Convert.ToBase64String(Encoding.UTF8.GetBytes($"{clientId}:{clientSecret}"));

        // RFC 6749 §2.3.1 / Proxmox style: form-url-encode both parts before base64
        private static string EncodeFormUrl(string clientId, string clientSecret) =>
            Encode(WebUtility.UrlEncode(clientId), WebUtility.UrlEncode(clientSecret));

        private static HttpRequest RequestWithAuthorization(string? authorization)
        {
            var context = new DefaultHttpContext();
            if (authorization != null)
            {
                context.Request.Headers.Authorization = authorization;
            }
            return context.Request;
        }

        private static Func<string, string?, Task<bool>> Validator(string clientId, string clientSecret) =>
            (id, secret) => Task.FromResult(id == clientId && secret == clientSecret);

        [Theory]
        [InlineData("Basic abc", true, "abc")]
        [InlineData("basic abc", true, "abc")]
        [InlineData("BASIC abc", true, "abc")]
        [InlineData("bAsIc   abc  ", true, "abc")]
        [InlineData("Basic", true, "")]
        [InlineData("Bearer abc", false, "")]
        [InlineData("Basicabc", false, "")]
        [InlineData("", false, "")]
        [InlineData(null, false, "")]
        public void TryGetBasicParameter_DetectsSchemeCaseInsensitively(string? header, bool expected, string expectedParameter)
        {
            Assert.Equal(expected, ClientAuthenticationExtensions.TryGetBasicParameter(header, out var parameter));
            Assert.Equal(expectedParameter, parameter);
        }

        [Theory]
        [InlineData("abc/def=")]
        [InlineData("a+b+c")]
        [InlineData("100%sure")]
        [InlineData("with:colon:inside")]
        [InlineData("mix/+=%: ěšč")]
        [InlineData("plain")]
        public void TryDecodeBasicCredentials_FormUrlEncoded_RoundTrips(string secret)
        {
            Assert.True(ClientAuthenticationExtensions.TryDecodeBasicCredentials(EncodeFormUrl(ClientId, secret), out var credentials));
            Assert.Equal(ClientId, credentials!.ClientId);
            Assert.Equal(secret, credentials.ClientSecret);
        }

        [Fact]
        public void TryDecodeBasicCredentials_SplitsOnFirstColon()
        {
            Assert.True(ClientAuthenticationExtensions.TryDecodeBasicCredentials(Encode("client", "se:cr:et"), out var credentials));
            Assert.Equal("client", credentials!.ClientId);
            Assert.Equal("se:cr:et", credentials.ClientSecret);
        }

        [Fact]
        public void TryDecodeBasicCredentials_PlusDecodesToSpace()
        {
            Assert.True(ClientAuthenticationExtensions.TryDecodeBasicCredentials(Encode("client", "a+b"), out var credentials));
            Assert.Equal("a b", credentials!.ClientSecret);
            Assert.Equal("a+b", credentials.RawClientSecret);
        }

        [Theory]
        [InlineData("")]
        [InlineData("not base64!")]
        [InlineData("bm9jb2xvbg==")] // "nocolon"
        [InlineData("OnNlY3JldA==")] // ":secret" (empty client_id)
        [InlineData("/w==")]         // invalid UTF-8
        public void TryDecodeBasicCredentials_RejectsMalformed(string parameter)
        {
            Assert.False(ClientAuthenticationExtensions.TryDecodeBasicCredentials(parameter, out _));
        }

        [Theory]
        [InlineData("Basic")]
        [InlineData("basic")]
        [InlineData("BASIC")]
        public async Task AuthenticateClientAsync_BasicUrlEncoded_Succeeds(string scheme)
        {
            const string secret = "s3cr/t+key==";
            var request = new OAuthTokenRequest { GrantType = "authorization_code" };

            var result = await RequestWithAuthorization($"{scheme} {EncodeFormUrl(ClientId, secret)}")
                .AuthenticateClientAsync(request, Validator(ClientId, secret));

            Assert.True(result.Succeeded);
            Assert.Equal(ClientAuthenticationMethod.ClientSecretBasic, result.Method);
            Assert.Equal(ClientId, request.ClientId);
            Assert.Equal(secret, request.ClientSecret);
        }

        [Fact]
        public async Task AuthenticateClientAsync_BasicNotEncoded_FallsBackToRawValues()
        {
            const string secret = "s3cr/t+key==";
            var request = new OAuthTokenRequest { GrantType = "authorization_code" };

            var result = await RequestWithAuthorization($"Basic {Encode(ClientId, secret)}")
                .AuthenticateClientAsync(request, Validator(ClientId, secret));

            Assert.True(result.Succeeded);
            Assert.Equal(secret, request.ClientSecret);
        }

        [Fact]
        public async Task AuthenticateClientAsync_BasicWrongSecret_InvalidClient()
        {
            var request = new OAuthTokenRequest { GrantType = "authorization_code" };

            var result = await RequestWithAuthorization($"Basic {EncodeFormUrl(ClientId, "wrong")}")
                .AuthenticateClientAsync(request, Validator(ClientId, "right"));

            Assert.False(result.Succeeded);
            Assert.Equal("invalid_client", result.Error);
            Assert.Equal(ClientAuthenticationMethod.ClientSecretBasic, result.Method);
        }

        [Fact]
        public async Task AuthenticateClientAsync_BasicMalformed_InvalidClient()
        {
            var result = await RequestWithAuthorization("Basic not-base64!")
                .AuthenticateClientAsync(new OAuthTokenRequest(), Validator(ClientId, "x"));

            Assert.Equal("invalid_client", result.Error);
        }

        [Fact]
        public async Task AuthenticateClientAsync_BasicAndSecretInBody_InvalidRequest()
        {
            var request = new OAuthTokenRequest { ClientId = ClientId, ClientSecret = "secret" };

            var result = await RequestWithAuthorization($"Basic {EncodeFormUrl(ClientId, "secret")}")
                .AuthenticateClientAsync(request, Validator(ClientId, "secret"));

            Assert.Equal("invalid_request", result.Error);
        }

        [Fact]
        public async Task AuthenticateClientAsync_BasicWithMatchingBodyClientId_Succeeds()
        {
            var request = new OAuthTokenRequest { ClientId = ClientId };

            var result = await RequestWithAuthorization($"Basic {EncodeFormUrl(ClientId, "secret")}")
                .AuthenticateClientAsync(request, Validator(ClientId, "secret"));

            Assert.True(result.Succeeded);
        }

        [Fact]
        public async Task AuthenticateClientAsync_BasicWithDifferentBodyClientId_InvalidRequest()
        {
            var request = new OAuthTokenRequest { ClientId = "other" };

            var result = await RequestWithAuthorization($"Basic {EncodeFormUrl(ClientId, "secret")}")
                .AuthenticateClientAsync(request, Validator(ClientId, "secret"));

            Assert.Equal("invalid_request", result.Error);
        }

        [Fact]
        public async Task AuthenticateClientAsync_NoHeader_ClientSecretPost_LeavesRequestUntouched()
        {
            var request = new OAuthTokenRequest { ClientId = ClientId, ClientSecret = "secret" };
            var validatorCalled = false;

            var result = await RequestWithAuthorization(null)
                .AuthenticateClientAsync(request, (_, _) => { validatorCalled = true; return Task.FromResult(false); });

            Assert.True(result.Succeeded);
            Assert.Equal(ClientAuthenticationMethod.ClientSecretPost, result.Method);
            Assert.False(validatorCalled);
            Assert.Equal("secret", request.ClientSecret);
        }

        [Fact]
        public async Task AuthenticateClientAsync_NoSecret_None()
        {
            var result = await RequestWithAuthorization(null)
                .AuthenticateClientAsync(new OAuthTokenRequest { ClientId = ClientId }, Validator(ClientId, "x"));

            Assert.True(result.Succeeded);
            Assert.Equal(ClientAuthenticationMethod.None, result.Method);
        }

        [Fact]
        public async Task AuthenticateClientAsync_BearerHeader_IsIgnored()
        {
            var result = await RequestWithAuthorization("Bearer token")
                .AuthenticateClientAsync(new OAuthTokenRequest { ClientId = ClientId, ClientSecret = "s" }, Validator(ClientId, "x"));

            Assert.True(result.Succeeded);
            Assert.Equal(ClientAuthenticationMethod.ClientSecretPost, result.Method);
        }
    }
}

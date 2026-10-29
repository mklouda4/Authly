using System.Text.Json;
using Authly.Authorization.UserStorage;
using Authly.Models;
using Authly.Services;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Authly.Tests
{
    public class IdTokenRoleTests
    {
        private const string RedirectUri = "https://pulse.mjhome.cz/callback";
        private const string Nonce = "nonce-123";

        private sealed record IssuedTokens(User User, JsonElement IdToken, IDictionary<string, object> UserInfo);

        // Runs the real authorization code flow against an isolated app and returns the decoded ID token payload
        private static async Task<IssuedTokens> IssueTokensAsync(bool administrator, params string[] scopes)
        {
            using var factory = new AuthlyFactory();
            _ = factory.Server;
            using var scope = factory.Services.CreateScope();
            var services = scope.ServiceProvider;

            var user = new User
            {
                UserName = administrator ? "admin.test" : "user.test",
                Email = administrator ? "admin@mjhome.cz" : "user@mjhome.cz",
                FullName = administrator ? "Admin Test" : "User Test",
                EmailConfirmed = true,
                Administrator = administrator
            };
            Assert.True(await services.GetRequiredService<IUserStorage>().CreateUser(user));

            var client = await services.GetRequiredService<IOAuthClientService>().CreateClientAsync(new CreateOAuthClientRequest
            {
                ClientName = "Pulse",
                RedirectUris = [RedirectUri],
                AllowedGrantTypes = [OAuthGrantType.AuthorizationCode],
                AllowedScopes = ["openid", "profile", "email"],
                RequirePkce = false
            }, "tests");

            var authorization = services.GetRequiredService<IOAuthAuthorizationService>();
            var code = await authorization.CreateAuthorizationCodeAsync(client.ClientId, user.Id, RedirectUri, [.. scopes], null, null, Nonce);
            var (isValid, response, error, description) = await authorization.ExchangeAuthorizationCodeAsync(new OAuthTokenRequest
            {
                GrantType = "authorization_code",
                ClientId = client.ClientId,
                ClientSecret = client.ClientSecret,
                Code = code.Code,
                RedirectUri = RedirectUri
            });
            Assert.True(isValid, $"{error}: {description}");

            var idToken = Assert.IsType<OidcTokenResponse>(response).IdToken!;
            var payload = JsonDocument.Parse(Base64UrlEncoder.Decode(idToken.Split('.')[1])).RootElement.Clone();
            var userInfo = Assert.IsAssignableFrom<IDictionary<string, object>>(await authorization.GetUserInfoAsync(response.AccessToken));
            return new IssuedTokens(user, payload, userInfo);
        }

        private static string[] Strings(JsonElement array) => [.. array.EnumerateArray().Select(e => e.GetString()!)];

        [Fact]
        public async Task IdToken_Administrator_ContainsAdminAndUserRoles()
        {
            var tokens = await IssueTokensAsync(administrator: true, "openid", "profile", "email");

            Assert.Equal("admin", tokens.IdToken.GetProperty("role").GetString());
            Assert.Equal(JsonValueKind.Array, tokens.IdToken.GetProperty("roles").ValueKind);
            Assert.Equal(["admin", "user"], Strings(tokens.IdToken.GetProperty("roles")));
        }

        [Fact]
        public async Task IdToken_RegularUser_ContainsSingleUserRoleAsArray()
        {
            var tokens = await IssueTokensAsync(administrator: false, "openid", "profile", "email");

            Assert.Equal("user", tokens.IdToken.GetProperty("role").GetString());
            // A lone claim would be serialized as a plain string; clients mapping roles to groups expect an array
            Assert.Equal(JsonValueKind.Array, tokens.IdToken.GetProperty("roles").ValueKind);
            Assert.Equal(["user"], Strings(tokens.IdToken.GetProperty("roles")));
        }

        [Fact]
        public async Task IdToken_OpenIdScopeOnly_StillContainsRoles()
        {
            var tokens = await IssueTokensAsync(administrator: true, "openid");

            Assert.Equal("admin", tokens.IdToken.GetProperty("role").GetString());
            Assert.Equal(["admin", "user"], Strings(tokens.IdToken.GetProperty("roles")));
            Assert.False(tokens.IdToken.TryGetProperty("preferred_username", out _));
            Assert.False(tokens.IdToken.TryGetProperty("email", out _));
        }

        [Fact]
        public async Task IdToken_ExistingClaims_AreUnchanged()
        {
            var tokens = await IssueTokensAsync(administrator: false, "openid", "profile", "email");
            var payload = tokens.IdToken;

            Assert.Equal(
                ["aud", "auth_time", "email", "email_verified", "exp", "iat", "iss", "name", "nbf", "nonce", "preferred_username", "role", "roles", "sub"],
                payload.EnumerateObject().Select(p => p.Name).Order(StringComparer.Ordinal));
            Assert.Equal(tokens.User.Id, payload.GetProperty("sub").GetString());
            Assert.Equal(Nonce, payload.GetProperty("nonce").GetString());
            Assert.Equal(JsonValueKind.Number, payload.GetProperty("auth_time").ValueKind);
            Assert.Equal(JsonValueKind.True, payload.GetProperty("email_verified").ValueKind);
            Assert.Equal("User Test", payload.GetProperty("name").GetString());
            Assert.Equal("user.test", payload.GetProperty("preferred_username").GetString());
            Assert.Equal("user@mjhome.cz", payload.GetProperty("email").GetString());
        }

        [Theory]
        [InlineData(true, "admin", new[] { "admin", "user" })]
        [InlineData(false, "user", new[] { "user" })]
        public async Task UserInfo_IsUnchanged(bool administrator, string role, string[] roles)
        {
            var tokens = await IssueTokensAsync(administrator, "openid", "profile", "email");
            var user = tokens.User;

            Assert.Equal(
                ["email", "email_verified", "given_name", "name", "preferred_username", "role", "roles", "sub"],
                tokens.UserInfo.Keys.Order(StringComparer.Ordinal));
            Assert.Equal(user.Id, tokens.UserInfo["sub"]);
            Assert.Equal(user.FullName, tokens.UserInfo["name"]);
            Assert.Equal(user.UserName, tokens.UserInfo["preferred_username"]);
            Assert.Equal(user.FullName, tokens.UserInfo["given_name"]);
            Assert.Equal(user.Email, tokens.UserInfo["email"]);
            Assert.Equal(true, tokens.UserInfo["email_verified"]);
            Assert.Equal(role, tokens.UserInfo["role"]);
            Assert.Equal(roles, Assert.IsType<string[]>(tokens.UserInfo["roles"]));
        }
    }
}

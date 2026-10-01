using Authly.Extension;
using Microsoft.AspNetCore.Http;
using Xunit;

namespace Authly.Tests
{
    public class PublicBaseUrlTests
    {
        // Request as seen behind a TLS-terminating proxy whose X-Forwarded-Proto was not applied
        private static HttpRequest ProxiedRequest()
        {
            var context = new DefaultHttpContext();
            context.Request.Scheme = "http";
            context.Request.Host = new HostString("auth.mjhome.cz");
            return context.Request;
        }

        [Theory]
        [InlineData("https://auth.mjhome.cz/", null)]
        [InlineData("https://auth.mjhome.cz", "https://localhost:80")]
        [InlineData("https://auth.mjhome.cz/some/path", null)]
        public void IssuerWins_AndOnlyOriginIsUsed(string issuer, string? baseUrl)
        {
            Assert.Equal("https://auth.mjhome.cz", HttpContextExtensions.GetPublicBaseUrl(issuer, baseUrl, ProxiedRequest()));
        }

        [Fact]
        public void BaseUrl_UsedWhenIssuerMissing()
        {
            Assert.Equal("https://login.example.com", HttpContextExtensions.GetPublicBaseUrl(null, "https://login.example.com/", ProxiedRequest()));
        }

        [Theory]
        [InlineData(null, null)]
        [InlineData("", "localhost:80")]     // stack default AUTHLY_BASE_URL is not an absolute URL
        [InlineData("not a url", "ftp://x")]
        public void FallsBackToRequest_WhenNothingValidConfigured(string? issuer, string? baseUrl)
        {
            Assert.Equal("http://auth.mjhome.cz", HttpContextExtensions.GetPublicBaseUrl(issuer, baseUrl, ProxiedRequest()));
        }
    }
}

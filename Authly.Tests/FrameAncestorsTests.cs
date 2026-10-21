using Authly.Configuration;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Options;
using Xunit;

namespace Authly.Tests
{
    public class FrameAncestorsTests
    {
        [Theory]
        [InlineData("https://ha.mjhome.cz", "https://ha.mjhome.cz")]
        [InlineData("HTTPS://HA.MJHOME.CZ/", "https://ha.mjhome.cz")]
        [InlineData("https://ha.mjhome.cz:443", "https://ha.mjhome.cz")]
        [InlineData("https://ha.mjhome.cz:8123", "https://ha.mjhome.cz:8123")]
        [InlineData("https://*.mjhome.cz", "https://*.mjhome.cz")]
        [InlineData("http://localhost:8123", "http://localhost:8123")]
        [InlineData("http://127.0.0.1:8123", "http://127.0.0.1:8123")]
        public void TryNormalize_ValidOrigin_ReturnsSchemeHostPort(string entry, string expected)
        {
            Assert.True(FrameAncestorsOptions.TryNormalize(entry, out var origin, out var error), error);
            Assert.Equal(expected, origin);
        }

        [Theory]
        [InlineData("ftp://x")]
        [InlineData("https://a.cz/cesta")]
        [InlineData("https://a.cz?q=1")]
        [InlineData("https://a.cz#frag")]
        [InlineData("http://ha.mjhome.cz")]
        [InlineData("http://*.localhost")]
        [InlineData("https://user@ha.mjhome.cz")]
        [InlineData("ha.mjhome.cz")]
        [InlineData("'self'")]
        [InlineData("*")]
        public void TryNormalize_InvalidOrigin_Fails(string entry)
        {
            Assert.False(FrameAncestorsOptions.TryNormalize(entry, out _, out var error));
            Assert.Contains(entry, error);
        }

        [Fact]
        public async Task Login_DefaultConfiguration_AllowsOnlySameOrigin()
        {
            using var factory = new AuthlyFactory();
            var response = await factory.CreateClient().GetAsync("/login");

            Assert.True(response.IsSuccessStatusCode, $"GET /login returned {(int)response.StatusCode}");
            Assert.Equal("frame-ancestors 'self'", Assert.Single(response.Headers.GetValues("Content-Security-Policy")));
            Assert.Equal("SAMEORIGIN", Assert.Single(response.Headers.GetValues("X-Frame-Options")));
        }

        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public async Task Login_ConfiguredOrigins_AllowsThemAndDropsXFrameOptions(bool asEnvironmentList)
        {
            using var factory = asEnvironmentList
                ? new AuthlyFactory(("Security:FrameAncestors", "https://ha.mjhome.cz,https://haos.mjhome.cz"))
                : new AuthlyFactory(("Security:FrameAncestors:0", "https://ha.mjhome.cz"), ("Security:FrameAncestors:1", "https://haos.mjhome.cz/"));
            var response = await factory.CreateClient().GetAsync("/login");

            Assert.True(response.IsSuccessStatusCode, $"GET /login returned {(int)response.StatusCode}");
            Assert.Equal("frame-ancestors 'self' https://ha.mjhome.cz https://haos.mjhome.cz",
                Assert.Single(response.Headers.GetValues("Content-Security-Policy")));
            Assert.False(response.Headers.Contains("X-Frame-Options"));
        }

        [Fact]
        public async Task Login_AuthlyEnvironmentVariable_IsMappedToFrameAncestors()
        {
            // Tests in one class run sequentially and no other test class starts the app, so the process-wide variable cannot leak
            Environment.SetEnvironmentVariable("AUTHLY_FRAME_ANCESTORS", "https://ha.mjhome.cz https://haos.mjhome.cz");
            try
            {
                using var factory = new AuthlyFactory();
                var response = await factory.CreateClient().GetAsync("/login");

                Assert.Equal("frame-ancestors 'self' https://ha.mjhome.cz https://haos.mjhome.cz",
                    Assert.Single(response.Headers.GetValues("Content-Security-Policy")));
                Assert.False(response.Headers.Contains("X-Frame-Options"));
            }
            finally
            {
                Environment.SetEnvironmentVariable("AUTHLY_FRAME_ANCESTORS", null);
            }
        }

        [Theory]
        [InlineData("ftp://x")]
        [InlineData("https://a.cz/cesta")]
        public void Startup_InvalidOrigin_Fails(string entry)
        {
            using var factory = new AuthlyFactory(("Security:FrameAncestors", $"https://ha.mjhome.cz {entry}"));

            var exception = Assert.ThrowsAny<Exception>(() => factory.CreateClient());

            var validation = Unwrap(exception).OfType<OptionsValidationException>().FirstOrDefault();
            Assert.NotNull(validation);
            Assert.Contains(entry, validation.Message);
        }

        private static IEnumerable<Exception> Unwrap(Exception exception)
        {
            for (var current = exception; current != null; current = current.InnerException)
            {
                yield return current;
                if (current is AggregateException aggregate)
                {
                    foreach (var inner in aggregate.InnerExceptions.SelectMany(Unwrap))
                    {
                        yield return inner;
                    }
                }
            }
        }

        /// <summary>
        /// Runs the real app on an isolated web root so tests never touch the development database or keys
        /// </summary>
        private sealed class AuthlyFactory(params (string Key, string Value)[] settings) : WebApplicationFactory<Program>
        {
            private readonly string _webRoot = Directory.CreateTempSubdirectory("authly-tests-").FullName;

            protected override void ConfigureWebHost(IWebHostBuilder builder)
            {
                _ = builder.UseEnvironment("Testing");
                _ = builder.UseSetting(WebHostDefaults.WebRootKey, _webRoot);
                foreach (var (key, value) in settings)
                {
                    _ = builder.UseSetting(key, value);
                }
            }

            protected override void Dispose(bool disposing)
            {
                base.Dispose(disposing);
                try
                {
                    Directory.Delete(_webRoot, recursive: true);
                }
                catch (IOException)
                {
                    // SQLite may still hold the file briefly; the temp folder is cleaned up by the OS
                }
            }
        }
    }
}

using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;

namespace Authly.Tests
{
    /// <summary>
    /// Runs the real app on an isolated web root so tests never touch the development database or keys
    /// </summary>
    internal sealed class AuthlyFactory(params (string Key, string Value)[] settings) : WebApplicationFactory<Program>
    {
        private readonly string _webRoot = CreateWebRoot();

        // Startup migrations need the database folder to exist, as the mounted data volume does in production
        private static string CreateWebRoot()
        {
            var webRoot = Directory.CreateTempSubdirectory("authly-tests-").FullName;
            _ = Directory.CreateDirectory(Path.Combine(webRoot, "data"));
            return webRoot;
        }

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

using Microsoft.Extensions.Options;

namespace Authly.Configuration
{
    /// <summary>
    /// Origins that may embed the Authly UI in an iframe (CSP frame-ancestors)
    /// </summary>
    public class FrameAncestorsOptions
    {
        /// <summary>
        /// Configuration section name (array in appsettings, comma or space separated list in an environment variable)
        /// </summary>
        public const string SectionName = "Security:FrameAncestors";

        /// <summary>
        /// Configured origins as entered, validated by <see cref="FrameAncestorsOptionsValidator"/>
        /// </summary>
        public List<string> Origins { get; set; } = [];

        /// <summary>
        /// True when origins other than Authly itself may embed the UI
        /// </summary>
        public bool AllowsExternalOrigins => Origins.Count > 0;

        /// <summary>
        /// Value of the CSP frame-ancestors directive
        /// </summary>
        public string Policy => string.Join(' ', Origins
            .Select(o => TryNormalize(o, out var origin, out _) ? origin : null)
            .OfType<string>()
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Prepend("'self'"));

        /// <summary>
        /// Reads the section either as an array (appsettings) or as a single comma/space separated value (environment variable).
        /// A single value wins, so AUTHLY_FRAME_ANCESTORS (or Security__FrameAncestors) overrides an array from appsettings.json.
        /// </summary>
        public static List<string> ReadEntries(IConfigurationSection section)
        {
            // Some configuration sources report an array's parent key with an empty value, so only a non-empty value counts as a list
            var values = !string.IsNullOrWhiteSpace(section.Value)
                ? [section.Value]
                : section.GetChildren().Select(c => c.Value);

            return values
                .SelectMany(v => (v ?? string.Empty).Split([',', ';', ' ', '\t', '\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                .ToList();
        }

        /// <summary>
        /// Normalizes an origin to scheme://host[:port]; https only (http for localhost), no path, query or fragment.
        /// A leading "*." wildcard subdomain is allowed.
        /// </summary>
        public static bool TryNormalize(string entry, out string origin, out string? error)
        {
            origin = string.Empty;
            error = null;

            var schemeEnd = entry.IndexOf("://", StringComparison.Ordinal);
            var wildcard = schemeEnd > 0 && entry.AsSpan(schemeEnd + 3).StartsWith("*.");
            var parsable = wildcard ? entry.Remove(schemeEnd + 3, 2) : entry;

            if (!Uri.TryCreate(parsable, UriKind.Absolute, out var uri) || string.IsNullOrEmpty(uri.Host))
            {
                error = $"'{entry}' is not an absolute URL such as https://ha.example.com";
                return false;
            }

            var isLocalhost = uri.IsLoopback || uri.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase);
            if (uri.Scheme != Uri.UriSchemeHttps && !(uri.Scheme == Uri.UriSchemeHttp && isLocalhost && !wildcard))
            {
                error = $"'{entry}' must use https (http is allowed only for localhost)";
                return false;
            }

            if (!string.IsNullOrEmpty(uri.UserInfo) || uri.AbsolutePath != "/" || !string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment) || parsable.Contains('?') || parsable.Contains('#'))
            {
                error = $"'{entry}' must be an origin only (scheme://host[:port]) without user info, path, query or fragment";
                return false;
            }

            origin = $"{uri.Scheme}://{(wildcard ? "*." : string.Empty)}{uri.Authority}";
            return true;
        }
    }

    /// <summary>
    /// Fails startup with a readable message when a frame ancestor origin is invalid
    /// </summary>
    public class FrameAncestorsOptionsValidator : IValidateOptions<FrameAncestorsOptions>
    {
        public ValidateOptionsResult Validate(string? name, FrameAncestorsOptions options)
        {
            var errors = options.Origins
                .Select(o => FrameAncestorsOptions.TryNormalize(o, out _, out var error) ? null : error)
                .OfType<string>()
                .Select(e => $"{FrameAncestorsOptions.SectionName}: {e}")
                .ToList();

            return errors.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(errors);
        }
    }
}

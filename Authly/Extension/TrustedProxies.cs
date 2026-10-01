using System.Net;

namespace Authly.Extension
{
    /// <summary>
    /// Parsing of trusted reverse proxy networks for ForwardedHeadersOptions
    /// </summary>
    public static class TrustedProxies
    {
        /// <summary>
        /// Private and loopback ranges - used when nothing is configured (typical Docker / LAN reverse proxy setup)
        /// </summary>
        public static readonly string[] Defaults = ["127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"];

        /// <summary>
        /// Parses a comma/semicolon/space separated list of IP addresses or CIDR networks.
        /// Empty input returns <see cref="Defaults"/>; invalid entries throw so a typo cannot silently trust nobody or everybody.
        /// </summary>
        public static List<System.Net.IPNetwork> Parse(string? value)
        {
            var entries = string.IsNullOrWhiteSpace(value)
                ? Defaults
                : value.Split([',', ';', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

            var networks = new List<System.Net.IPNetwork>();
            foreach (var entry in entries)
            {
                if (System.Net.IPNetwork.TryParse(entry, out var network))
                {
                    networks.Add(network);
                }
                else if (IPAddress.TryParse(entry, out var address))
                {
                    networks.Add(new System.Net.IPNetwork(address, address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128));
                }
                else
                {
                    throw new FormatException($"Invalid trusted proxy entry '{entry}' (expected IP address or CIDR)");
                }
            }

            return networks;
        }
    }
}

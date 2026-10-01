using Authly.Extension;
using System.Net;
using Xunit;

namespace Authly.Tests
{
    public class TrustedProxiesTests
    {
        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        public void Parse_Empty_ReturnsPrivateDefaults(string? value)
        {
            var networks = TrustedProxies.Parse(value);

            Assert.Equal(TrustedProxies.Defaults.Length, networks.Count);
            Assert.Contains(networks, n => n.Contains(IPAddress.Parse("192.168.50.10")));
            Assert.Contains(networks, n => n.Contains(IPAddress.Parse("172.18.0.2")));
            Assert.DoesNotContain(networks, n => n.Contains(IPAddress.Parse("8.8.8.8")));
        }

        [Fact]
        public void Parse_MixedList_AcceptsCidrAndSingleAddresses()
        {
            var networks = TrustedProxies.Parse("192.168.50.0/24; 10.0.0.5, ::1");

            Assert.Equal(3, networks.Count);
            Assert.Contains(networks, n => n.Contains(IPAddress.Parse("192.168.50.99")));
            Assert.Contains(networks, n => n.Contains(IPAddress.Parse("10.0.0.5")));
            Assert.DoesNotContain(networks, n => n.Contains(IPAddress.Parse("10.0.0.6")));
            Assert.Contains(networks, n => n.Contains(IPAddress.IPv6Loopback));
        }

        [Theory]
        [InlineData("not-an-ip")]
        [InlineData("192.168.1.0/99")]
        public void Parse_InvalidEntry_Throws(string value)
        {
            Assert.Throws<FormatException>(() => TrustedProxies.Parse(value));
        }
    }
}

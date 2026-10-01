using Authly.Extension;
using Microsoft.AspNetCore.Http;
using System.Net;
using Xunit;

namespace Authly.Tests
{
    public class ClientIpAddressTests
    {
        [Fact]
        public void GetClientIpAddress_IgnoresClientSuppliedForwardingHeaders()
        {
            // Without a trusted proxy, ForwardedHeadersMiddleware leaves RemoteIpAddress untouched;
            // the raw headers must not be able to override it.
            var context = new DefaultHttpContext();
            context.Connection.RemoteIpAddress = IPAddress.Parse("203.0.113.7");
            context.Request.Headers["X-Forwarded-For"] = "1.2.3.4";
            context.Request.Headers["X-Real-IP"] = "5.6.7.8";

            Assert.Equal("203.0.113.7", context.GetClientIpAddress());
        }

        [Fact]
        public void GetClientIpAddress_NormalizesIpv4MappedAddresses()
        {
            var context = new DefaultHttpContext();
            context.Connection.RemoteIpAddress = IPAddress.Parse("::ffff:192.168.50.20");

            Assert.Equal("192.168.50.20", context.GetClientIpAddress());
        }

        [Fact]
        public void GetClientIpAddress_NoConnectionAddress_ReturnsUnknown()
        {
            Assert.Equal("unknown", new DefaultHttpContext().GetClientIpAddress());
        }
    }
}

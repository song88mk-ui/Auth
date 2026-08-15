using System.Linq;
using Auth.Shared.Utilities;

namespace Auth.Tests.Utilities
{
    public class JwtParserTests
    {
        [Fact]
        public void ParseClaimsFromJwt_WellFormedJwt_ReturnsExpectedClaims()
        {
            // header.payload.signature, payload = {"sub":"1","name":"Bob"}
            const string jwt = "header.eyJzdWIiOiIxIiwibmFtZSI6IkJvYiJ9.signature";

            var claims = JwtParser.ParseClaimsFromJwt(jwt).ToList();

            Assert.Contains(claims, c => c.Type == "sub" && c.Value == "1");
            Assert.Contains(claims, c => c.Type == "name" && c.Value == "Bob");
        }

        [Theory]
        // payload = {"sub":"123","name":"Alice"} -> base64url length % 4 == 2
        [InlineData("header.eyJzdWIiOiIxMjMiLCJuYW1lIjoiQWxpY2UifQ.signature", "sub", "123")]
        // payload = {"sub":"1","role":"admin"} -> base64url length % 4 == 3
        [InlineData("header.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0.signature", "role", "admin")]
        public void ParseClaimsFromJwt_PayloadRequiresPadding_ParsesWithoutThrowing(string jwt, string claimType, string expectedValue)
        {
            var claims = JwtParser.ParseClaimsFromJwt(jwt).ToList();

            Assert.Contains(claims, c => c.Type == claimType && c.Value == expectedValue);
        }
    }
}

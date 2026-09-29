//-----------------------------------------------------------------------------
// Filename: IceServerAuthChallengeUnitTest.cs
//
// Description: TURN server authentication and certificate policy. A 401 / 438
// challenge that comes back after credentials were sent must count towards
// IceServer.MAX_ERRORS, so a TURN server with wrong credentials fails instead
// of being retried for the life of the session; TURNS certificates are only
// validated for the listed domains.
//
// History:
// Sep 2026     iSpyConnect     Created.
//
// License:
// BSD 3-Clause "New" or "Revised" License, see included LICENSE.md file.
//-----------------------------------------------------------------------------

using System.Net;
using System.Text;
using Xunit;

namespace SIPSorcery.Net.UnitTests
{
    [Trait("Category", "unit")]
    public class IceServerAuthChallengeUnitTest
    {
        private static STUNMessage BuildChallenge(IceServer iceServer, STUNMessageTypesEnum messageType, int errorCode)
        {
            var response = new STUNMessage(messageType);
            response.Header.TransactionId = Encoding.ASCII.GetBytes(iceServer.TransactionID);
            response.Attributes.Add(new STUNErrorCodeAttribute(errorCode, "Unauthorized"));
            response.Attributes.Add(new STUNAttribute(STUNAttributeTypesEnum.Nonce, Encoding.ASCII.GetBytes("nonce")));
            response.Attributes.Add(new STUNAttribute(STUNAttributeTypesEnum.Realm, Encoding.ASCII.GetBytes("realm")));
            return response;
        }

        [Theory]
        [InlineData(STUNMessageTypesEnum.AllocateErrorResponse)]
        [InlineData(STUNMessageTypesEnum.BindingErrorResponse)]
        [InlineData(STUNMessageTypesEnum.RefreshErrorResponse)]
        public void RepeatedChallengeCountsTowardsMaxErrors(STUNMessageTypesEnum messageType)
        {
            Assert.True(STUNUri.TryParse("turn:127.0.0.1:3478", out var uri));
            var iceServer = new IceServer(uri, 0, "user", "wrong-password");
            var serverEndPoint = new IPEndPoint(IPAddress.Loopback, 3478);

            // The first challenge starts authentication and counts once; each later one (credentials were sent)
            // adds to the count until the server is failed.
            for (int i = 1; i <= IceServer.MAX_ERRORS; i++)
            {
                iceServer.GotStunResponse(BuildChallenge(iceServer, messageType, IceServer.STUN_UNAUTHORISED_ERROR_CODE), serverEndPoint);
                Assert.Equal(i, iceServer.ErrorResponseCount);
                Assert.NotNull(iceServer.Nonce);
            }
        }

        [Theory]
        [InlineData("coturn5.ispyconnect.com", true)]
        [InlineData("ispyconnect.com", true)]
        [InlineData("COTURN5.ISPYCONNECT.COM.", true)]
        [InlineData("evilispyconnect.com", false)]
        [InlineData("ispyconnect.com.example.net", false)]
        [InlineData("46.62.130.35", false)]
        [InlineData("", false)]
        public void TurnsCertificateValidatedOnlyForListedDomains(string host, bool validated)
        {
            Assert.Equal(validated, RtpIceChannel.IsTurnsValidatedHost(host));
        }

        [Fact]
        public void ErrorCodeAttributeKeepsItsClass()
        {
            var attribute = new STUNErrorCodeAttribute(438, "Stale Nonce");

            Assert.Equal(438, attribute.ErrorCode);
        }
    }
}

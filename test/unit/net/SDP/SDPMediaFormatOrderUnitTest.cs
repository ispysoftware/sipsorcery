//-----------------------------------------------------------------------------
// Filename: SDPMediaFormatOrderUnitTest.cs
//
// Description: Unit tests for the order of the media formats parsed from an
// SDP media announcement, which is the sender's order of preference.
//
// License:
// BSD 3-Clause "New" or "Revised" License, see included LICENSE.md file.
//-----------------------------------------------------------------------------

using System.Linq;
using Xunit;

namespace SIPSorcery.Net.UnitTests
{
    [Trait("Category", "unit")]
    public class SDPMediaFormatOrderUnitTest
    {
        private const string BrowserStyleOffer =
            "v=0\r\n" +
            "o=- 4611731400430051336 2 IN IP4 127.0.0.1\r\n" +
            "s=-\r\n" +
            "t=0 0\r\n" +
            "m=audio 9 UDP/TLS/RTP/SAVPF 111 63 9 0 8 13 110 126\r\n" +
            "c=IN IP4 0.0.0.0\r\n" +
            "a=mid:0\r\n" +
            "a=recvonly\r\n" +
            "a=rtpmap:111 opus/48000/2\r\n" +
            "a=fmtp:111 minptime=10;useinbandfec=1\r\n" +
            "a=rtpmap:63 red/48000/2\r\n" +
            "a=rtpmap:9 G722/8000\r\n" +
            "a=rtpmap:0 PCMU/8000\r\n" +
            "a=rtpmap:8 PCMA/8000\r\n" +
            "a=rtpmap:13 CN/8000\r\n" +
            "a=rtpmap:110 telephone-event/48000\r\n" +
            "a=rtpmap:126 telephone-event/8000\r\n";

        /// <summary>
        /// Dynamic payload types (defined by a=rtpmap lines) must keep their place in the m= line,
        /// ahead of well known static types listed after them.
        /// </summary>
        [Fact]
        public void MediaFormatsKeepTheOrderOfTheMediaLine()
        {
            SDP sdp = SDP.ParseSDPDescription(BrowserStyleOffer);

            var audio = sdp.Media.Single(x => x.Media == SDPMediaTypesEnum.audio);

            Assert.Equal(new[] { 111, 63, 9, 0, 8, 13, 110, 126 }, audio.MediaFormats.Keys.ToArray());
            Assert.Equal("opus/48000/2", audio.MediaFormats.Values.First().Rtpmap);
            Assert.Equal("minptime=10;useinbandfec=1", audio.MediaFormats[111].Fmtp);
        }

        /// <summary>
        /// The order survives the rtpmap lines arriving in a different order to the m= line, and a
        /// format with an rtpmap but no place in the m= line goes last.
        /// </summary>
        [Fact]
        public void MediaLineOrderWinsOverAttributeOrder()
        {
            string sdpText =
                "v=0\r\n" +
                "o=- 1 2 IN IP4 127.0.0.1\r\n" +
                "s=-\r\n" +
                "t=0 0\r\n" +
                "m=video 9 UDP/TLS/RTP/SAVPF 102 96 0\r\n" +
                "c=IN IP4 0.0.0.0\r\n" +
                "a=rtpmap:97 rtx/90000\r\n" +
                "a=rtpmap:96 VP8/90000\r\n" +
                "a=rtpmap:102 H264/90000\r\n";

            SDP sdp = SDP.ParseSDPDescription(sdpText);

            var video = sdp.Media.Single(x => x.Media == SDPMediaTypesEnum.video);

            Assert.Equal(new[] { 102, 96, 0, 97 }, video.MediaFormats.Keys.ToArray());
        }
    }
}

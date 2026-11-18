//-----------------------------------------------------------------------------
// Filename: RtpSendPathUnitTest.cs
//
// Description: Unit tests for the allocation-free pieces of the RTP send path:
// the fixed header writer, the H264 NAL finder, the TWCC send time tracker and
// the TWCC feedback parser.
//
// License:
// BSD 3-Clause "New" or "Revised" License, see included LICENSE.md file.
//-----------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Linq;
using Xunit;

namespace SIPSorcery.Net.UnitTests
{
    [Trait("Category", "unit")]
    public class RtpSendPathUnitTest
    {
        /// <summary>
        /// The fixed header writer must produce the same 12 bytes as an RTPHeader with the same fields.
        /// </summary>
        [Theory]
        [InlineData(0, 96, (ushort)0, 0u, 1u)]
        [InlineData(1, 111, (ushort)65535, 4294967295u, 3735928559u)]
        [InlineData(1, 127, (ushort)12345, 90000u, 42u)]
        public void FixedHeaderMatchesRtpHeader(int markerBit, int payloadType, ushort seq, uint timestamp, uint ssrc)
        {
            var header = new RTPHeader
            {
                MarkerBit = markerBit,
                PayloadType = payloadType,
                SequenceNumber = seq,
                Timestamp = timestamp,
                SyncSource = ssrc,
                HeaderExtensionFlag = 0
            };

            byte[] expected = new byte[RTPHeader.MIN_HEADER_LEN];
            header.WriteTo(expected);

            byte[] actual = new byte[RTPHeader.MIN_HEADER_LEN];
            int written = RTPHeader.WriteFixedHeader(actual, markerBit, payloadType, seq, timestamp, ssrc);

            Assert.Equal(RTPHeader.MIN_HEADER_LEN, written);
            Assert.Equal(expected, actual);
        }

        public static IEnumerable<object[]> AccessUnits()
        {
            // 4 byte start codes, as an encoder emits them.
            yield return new object[] { new byte[] { 0, 0, 0, 1, 0x67, 0x42, 0, 0, 0, 1, 0x68, 0xCE, 0, 0, 0, 1, 0x65, 0x88, 0x84 } };
            // 3 byte start codes.
            yield return new object[] { new byte[] { 0, 0, 1, 0x67, 0x42, 0, 0, 1, 0x65, 0x88 } };
            // Mixed, with 0x01 bytes and zero pairs inside the NALs that are not start codes.
            yield return new object[] { new byte[] { 0, 0, 0, 1, 0x41, 1, 1, 0, 1, 0, 0, 2, 0, 0, 1, 0x41, 0x9A, 0, 1 } };
            // No leading start code, and a start code with extra zeros in front of it.
            yield return new object[] { new byte[] { 0x65, 0x88, 0, 0, 0, 0, 0, 1, 0x41, 0x9A } };
            // A start code at the very end, and back to back start codes (empty NALs are skipped).
            yield return new object[] { new byte[] { 0, 0, 1, 0, 0, 1, 0x41, 0x9A, 0, 0, 1 } };
            // No start code at all: the whole buffer is one NAL.
            yield return new object[] { new byte[] { 0x41, 0x9A, 0x01, 0x02 } };
            // Empty.
            yield return new object[] { Array.Empty<byte>() };
        }

        /// <summary>
        /// The NAL finder the send path uses must return exactly what ParseNals returns.
        /// </summary>
        [Theory]
        [MemberData(nameof(AccessUnits))]
        public void TryNextNalMatchesParseNals(byte[] accessUnit)
        {
            var expected = H264Packetiser.ParseNals(accessUnit).Select(x => x.NAL.ToArray()).ToList();

            var actual = new List<byte[]>();
            int position = 0;
            while (H264Packetiser.TryNextNal(accessUnit, ref position, out int start, out int length))
            {
                actual.Add(accessUnit.AsSpan(start, length).ToArray());
            }

            Assert.Equal(expected.Count, actual.Count);
            for (int i = 0; i < expected.Count; i++)
            {
                Assert.Equal(expected[i], actual[i]);
            }
        }

        /// <summary>
        /// A send time can be read back for a recent seqnum, and a seqnum that has since been
        /// overwritten by a newer one in the same slot misses instead of returning the newer time.
        /// </summary>
        [Fact]
        public void TwccTrackerReturnsOnlyTheSeqnumItHolds()
        {
            var tracker = new TwccSentPacketTracker();

            Assert.False(tracker.TryGetSendTime(5, out _));

            tracker.RecordSend(5, 1000);
            tracker.RecordSend(65535, 2000);

            Assert.True(tracker.TryGetSendTime(5, out long ticks));
            Assert.Equal(1000, ticks);
            Assert.True(tracker.TryGetSendTime(65535, out ticks));
            Assert.Equal(2000, ticks);
            Assert.False(tracker.TryGetSendTime(6, out _));

            // 8192 seqnums later the slot is reused.
            tracker.RecordSend((ushort)(5 + 8192), 3000);

            Assert.False(tracker.TryGetSendTime(5, out _));
            Assert.True(tracker.TryGetSendTime((ushort)(5 + 8192), out ticks));
            Assert.Equal(3000, ticks);

            tracker.Reset();
            Assert.False(tracker.TryGetSendTime(65535, out _));
        }

        /// <summary>
        /// Each received packet gets its own receive delta when a packet in the middle of the
        /// feedback was not received (which carries no delta).
        /// </summary>
        [Fact]
        public void TwccFeedbackDeltasStayAlignedAcrossALostPacket()
        {
            byte[] packet =
            {
                0x8F, 0xCD, 0x00, 0x05,     // V=2, FMT=15 (TWCC), PT=205 (RTPFB), length 5 (24 bytes)
                0x00, 0x00, 0x00, 0x01,     // sender SSRC
                0x00, 0x00, 0x00, 0x02,     // media SSRC
                0x00, 0x64, 0x00, 0x03,     // base seqnum 100, 3 packet statuses
                0x00, 0x00, 0x01, 0x07,     // reference time 1, feedback count 7
                0xD1, 0x00,                 // 2-bit status vector: small delta, not received, small delta
                0x04, 0x08                  // deltas: 4 and 8 (x 250us)
            };

            var feedback = new RTCPTWCCFeedback(packet);

            Assert.Equal(1u, feedback.SenderSSRC);
            Assert.Equal(2u, feedback.MediaSSRC);
            Assert.Equal(100, feedback.BaseSequenceNumber);
            Assert.Equal(3, feedback.PacketStatusCount);
            Assert.Equal(1u, feedback.ReferenceTime);
            Assert.Equal(7, feedback.FeedbackPacketCount);
            Assert.Equal(3, feedback.PacketStatuses.Count);

            Assert.Equal(100, feedback.PacketStatuses[0].SequenceNumber);
            Assert.Equal(TWCCPacketStatusType.ReceivedSmallDelta, feedback.PacketStatuses[0].Status);
            Assert.Equal(1000, feedback.PacketStatuses[0].Delta);

            Assert.Equal(101, feedback.PacketStatuses[1].SequenceNumber);
            Assert.Equal(TWCCPacketStatusType.NotReceived, feedback.PacketStatuses[1].Status);
            Assert.Null(feedback.PacketStatuses[1].Delta);

            Assert.Equal(102, feedback.PacketStatuses[2].SequenceNumber);
            Assert.Equal(TWCCPacketStatusType.ReceivedSmallDelta, feedback.PacketStatuses[2].Status);
            Assert.Equal(2000, feedback.PacketStatuses[2].Delta);
        }

        /// <summary>
        /// A run length chunk and a large (signed, 2 byte) delta, followed by another RTCP packet in
        /// the same buffer that the parser must not read deltas from.
        /// </summary>
        [Fact]
        public void TwccFeedbackStopsAtItsOwnLength()
        {
            byte[] packet =
            {
                0x8F, 0xCD, 0x00, 0x05,     // length 5 (24 bytes)
                0x00, 0x00, 0x00, 0x01,
                0x00, 0x00, 0x00, 0x02,
                0xFF, 0xFF, 0x00, 0x03,     // base seqnum 65535, 3 packet statuses
                0x00, 0x00, 0x01, 0x00,
                0x40, 0x03,                 // run length chunk: large delta x 3
                0xFF, 0xFE,                 // one delta only (-2): the message is short by two
                // The next RTCP packet in the compound: must not be taken for deltas.
                0x81, 0xC9, 0x00, 0x01, 0x11, 0x22, 0x33, 0x44
            };

            var feedback = new RTCPTWCCFeedback(packet);

            Assert.Equal(3, feedback.PacketStatuses.Count);
            Assert.Equal(65535, feedback.PacketStatuses[0].SequenceNumber);
            Assert.Equal(0, feedback.PacketStatuses[1].SequenceNumber);
            Assert.Equal(1, feedback.PacketStatuses[2].SequenceNumber);
            Assert.All(feedback.PacketStatuses, x => Assert.Equal(TWCCPacketStatusType.ReceivedLargeDelta, x.Status));
            Assert.Equal(-500, feedback.PacketStatuses[0].Delta);
            Assert.Null(feedback.PacketStatuses[1].Delta);
            Assert.Null(feedback.PacketStatuses[2].Delta);
        }
    }
}

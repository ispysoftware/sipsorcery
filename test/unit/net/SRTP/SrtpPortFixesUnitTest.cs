//-----------------------------------------------------------------------------
// Filename: SrtpPortFixesUnitTest.cs
//
// Description: Tests for the fixes applied to SharpSRTP's SrtpContext when it
// was ported into this fork: 80-bit SRTCP tag for the *_HMAC_SHA1_32 profiles,
// 31-bit SRTCP index, and per-SSRC receive state only seeded by an
// authenticated packet.
//
// History:
// Sep 2026     iSpyConnect     Created.
//
// License:
// BSD 3-Clause "New" or "Revised" License, see included LICENSE.md file.
//-----------------------------------------------------------------------------

using System;
using System.Buffers.Binary;
using Org.BouncyCastle.Tls;
using SIPSorcery.Net.SharpSRTP.DTLSSRTP;
using SIPSorcery.Net.SharpSRTP.SRTP;
using Xunit;

namespace SIPSorcery.Net.UnitTests
{
    [Trait("Category", "unit")]
    public class SrtpPortFixesUnitTest
    {
        private static readonly byte[] MasterKey = { 0xE1, 0xF9, 0x7A, 0x0D, 0x3E, 0x01, 0x8B, 0xE0, 0xD6, 0x4F, 0xA3, 0x2C, 0x06, 0xDE, 0x41, 0x39 };
        private static readonly byte[] MasterSalt = { 0x0E, 0xC6, 0x75, 0xAD, 0x49, 0x8A, 0xFE, 0xEB, 0xB6, 0x96, 0x0B, 0x3A, 0xAB, 0xE6 };

        private static SrtpContext Create(SrtpContextType type, int profile)
        {
            return new SrtpContext(type, DtlsSrtpProtocol.DtlsProtectionProfiles[profile], MasterKey, MasterSalt);
        }

        private static byte[] BuildRtp(ushort seq, uint ssrc, out int length)
        {
            length = 12 + 50;
            var packet = new byte[length + RTPSession.SRTP_MAX_PREFIX_LENGTH];
            packet[0] = 0x80;
            packet[1] = 96;
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2), seq);
            BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(8), ssrc);
            for (int i = 12; i < length; i++)
            {
                packet[i] = (byte)i;
            }
            return packet;
        }

        private static byte[] BuildRtcp(uint ssrc, out int length)
        {
            length = 32;
            var packet = new byte[length + RTPSession.SRTP_MAX_PREFIX_LENGTH];
            packet[0] = 0x81;
            packet[1] = 201;
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2), (ushort)((length / 4) - 1));
            BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(4), ssrc);
            return packet;
        }

        /// <summary>
        /// RFC 5764 4.1.2: SRTP_AES128_CM_HMAC_SHA1_32 uses a 32-bit tag for SRTP but an 80-bit tag for SRTCP.
        /// </summary>
        [Fact]
        public void Sha1_32ProfileUses80BitSrtcpTag()
        {
            var sender = Create(SrtpContextType.RTCP, SrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_32);
            var receiver = Create(SrtpContextType.RTCP, SrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_32);

            var packet = BuildRtcp(0x1234, out int length);
            Assert.Equal(0, sender.ProtectRtcp(packet, length, out int protectedLength));
            Assert.Equal(length + 4 + 10, protectedLength);

            Assert.Equal(0, receiver.UnprotectRtcp(packet, protectedLength, out int plainLength));
            Assert.Equal(length, plainLength);

            // SRTP on the same profile keeps the 32-bit tag.
            var rtpSender = Create(SrtpContextType.RTP, SrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_32);
            var rtp = BuildRtp(1, 0x1234, out int rtpLength);
            Assert.Equal(0, rtpSender.ProtectRtp(rtp, rtpLength, out int rtpProtectedLength));
            Assert.Equal(rtpLength + 4, rtpProtectedLength);
        }

        /// <summary>
        /// A genuine first packet with sequence number 0 is accepted, and a replay of it is rejected.
        /// </summary>
        [Fact]
        public void FirstRtpPacketWithSeqZeroAccepted()
        {
            var sender = Create(SrtpContextType.RTP, SrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_80);
            var receiver = Create(SrtpContextType.RTP, SrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_80);

            var packet = BuildRtp(0, 0x5678, out int length);
            Assert.Equal(0, sender.ProtectRtp(packet, length, out int protectedLength));
            var replay = (byte[])packet.Clone();

            Assert.Equal(0, receiver.UnprotectRtp(packet, protectedLength, out int plainLength));
            Assert.Equal(length, plainLength);

            Assert.Equal(SrtpContext.ERROR_REPLAY_CHECK_FAILED, receiver.UnprotectRtp(replay, protectedLength, out _));
        }

        /// <summary>
        /// A forged first packet (bad tag, high sequence number) must not change the receiver's state, so the
        /// genuine stream that follows still decrypts.
        /// </summary>
        [Fact]
        public void ForgedFirstRtpPacketDoesNotBreakStream()
        {
            var sender = Create(SrtpContextType.RTP, SrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_80);
            var receiver = Create(SrtpContextType.RTP, SrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_80);

            var forged = BuildRtp(0xFFF0, 0x9ABC, out int forgedLength);
            Assert.NotEqual(0, receiver.UnprotectRtp(forged, forgedLength + 10, out _));

            for (ushort seq = 100; seq < 105; seq++)
            {
                var packet = BuildRtp(seq, 0x9ABC, out int length);
                Assert.Equal(0, sender.ProtectRtp(packet, length, out int protectedLength));
                Assert.Equal(0, receiver.UnprotectRtp(packet, protectedLength, out int plainLength));
                Assert.Equal(length, plainLength);
            }
        }

        /// <summary>
        /// Runt packets return an error code instead of throwing.
        /// </summary>
        [Fact]
        public void RuntPacketsReturnError()
        {
            var rtp = Create(SrtpContextType.RTP, SrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_80);
            var rtcp = Create(SrtpContextType.RTCP, SrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_80);
            var buffer = new byte[64];

            Assert.Equal(SrtpContext.ERROR_GENERIC, rtp.UnprotectRtp(buffer, 12, out _));
            Assert.Equal(SrtpContext.ERROR_GENERIC, rtcp.UnprotectRtcp(buffer, 12, out _));
        }
    }
}

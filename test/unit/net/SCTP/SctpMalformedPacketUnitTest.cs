//-----------------------------------------------------------------------------
// Filename: SctpMalformedPacketUnitTest.cs
//
// Description: Malformed SCTP packets from the remote peer must be rejected as
// a recoverable parse failure (ApplicationException, which the receive loops
// drop per packet). They used to read past the chunk (SACK counts,
// GHSA-jwjp-4649-v8jp) or spin the receive thread forever (zero-length chunks,
// GHSA-qmvg-569h-hqrh; zero-length ERROR causes).
//
// History:
// Sep 2026     iSpyConnect     Created.
//
// License:
// BSD 3-Clause "New" or "Revised" License, see included LICENSE.md file.
//-----------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using SIPSorcery.Sys;
using Xunit;

namespace SIPSorcery.Net.UnitTests
{
    [Trait("Category", "unit")]
    public class SctpMalformedPacketUnitTest
    {
        private static readonly TimeSpan HANG_TIMEOUT = TimeSpan.FromSeconds(2);

        #region SACK counts (GHSA-jwjp-4649-v8jp)

        [Theory]
        [InlineData(0xFFFF, 0x0000)]
        [InlineData(0x0000, 0xFFFF)]
        [InlineData(0xFFFF, 0xFFFF)]
        [InlineData(0x0001, 0x0000)]   // One entry past the chunk: the check left out the chunk header.
        [InlineData(0x0000, 0x0001)]
        public void SackViewWithCountsPastChunkIsRejected(int numGapAckBlocks, int numDuplicateTSNs)
        {
            var chunk = BuildSack(16, numGapAckBlocks, numDuplicateTSNs);

            Assert.Throws<ApplicationException>(() => ParseChunkView(chunk));
        }

        [Theory]
        [InlineData(1)]
        [InlineData(4)]
        [InlineData(12)]
        public void SackViewShorterThanFixedParametersIsRejected(int chunkLength)
        {
            var chunk = new byte[(chunkLength + 3) & ~3];
            chunk[0] = (byte)SctpChunkType.SACK;
            NetConvert.ToBuffer((ushort)chunkLength, chunk, 2);

            Assert.Throws<ApplicationException>(() => ParseChunkView(chunk));
        }

        [Fact]
        public void SackViewWithMatchingCountsParses()
        {
            var chunk = BuildMatchingSack();

            var view = new SctpChunkView(chunk);

            Assert.Equal(1000U, view.CumulativeTsnAck);
            Assert.Equal(262144U, view.ARwnd);
            Assert.Equal((ushort)2, view.NumGapAckBlocks);
            Assert.Equal((ushort)3, view.GetTsnGapBlock(0).Start);
            Assert.Equal((ushort)5, view.GetTsnGapBlock(0).End);
            Assert.Equal((ushort)8, view.GetTsnGapBlock(1).Start);
            Assert.Equal((ushort)9, view.GetTsnGapBlock(1).End);
            Assert.Equal((ushort)1, view.NumDuplicateTSNs);
            Assert.Equal(1234U, view.GetDuplicateTSN(0));
        }

        /// <summary>
        /// The receive path: the bad SACK has to be rejected when the packet is parsed, before
        /// SctpDataSender.GotSack has applied any of it.
        /// </summary>
        [Fact]
        public void PacketWithSackCountsPastChunkIsRejected()
        {
            var packet = BuildPacket(BuildSack(16, 1, 0));

            Assert.Throws<ApplicationException>(() => ParsePacketView(packet));
        }

        [Theory]
        [InlineData(0xFFFF, 0x0000)]
        [InlineData(0x0000, 0xFFFF)]
        [InlineData(0xFFFF, 0xFFFF)]
        [InlineData(0x0064, 0x0000)]   // In bounds of the buffer, but past the chunk: stale bytes parsed as gap blocks.
        [InlineData(0x0000, 0x0064)]
        public void SackChunkParseWithCountsPastChunkIsRejected(int numGapAckBlocks, int numDuplicateTSNs)
        {
            // Sized like RTCSctpTransport's receive buffer, so an unbounded read has room to run before it leaves the array.
            var buffer = new byte[(int)SctpAssociation.DEFAULT_ADVERTISED_RECEIVE_WINDOW];
            BuildSack(16, numGapAckBlocks, numDuplicateTSNs).CopyTo(buffer, 0);

            Assert.Throws<ApplicationException>(() => SctpSackChunk.ParseChunk(buffer, 0));
        }

        [Fact]
        public void SackChunkParseShorterThanFixedParametersIsRejected()
        {
            var buffer = new byte[64];
            buffer[0] = (byte)SctpChunkType.SACK;
            NetConvert.ToBuffer((ushort)4, buffer, 2);

            Assert.Throws<ApplicationException>(() => SctpSackChunk.ParseChunk(buffer, 0));
        }

        [Fact]
        public void SackChunkParseWithMatchingCountsSucceeds()
        {
            var sack = SctpSackChunk.ParseChunk(BuildMatchingSack(), 0);

            Assert.Equal(1000U, sack.CumulativeTsnAck);
            Assert.Equal(262144U, sack.ARwnd);
            Assert.Equal(2, sack.GapAckBlocks.Count);
            Assert.Equal((ushort)3, sack.GapAckBlocks[0].Start);
            Assert.Equal((ushort)5, sack.GapAckBlocks[0].End);
            Assert.Equal((ushort)8, sack.GapAckBlocks[1].Start);
            Assert.Equal((ushort)9, sack.GapAckBlocks[1].End);
            Assert.Equal(1234U, Assert.Single(sack.DuplicateTSN));
        }

        #endregion

        #region Zero-length chunks (GHSA-qmvg-569h-hqrh)

        [Theory]
        [InlineData(0x80)]   // Unrecognised, action Skip.
        [InlineData(0xC0)]   // Unrecognised, action Skip and report.
        [InlineData(0x0B)]   // COOKIE ACK.
        public async Task PacketViewWithZeroLengthChunkDoesNotHang(int chunkType)
        {
            var packet = BuildPacket(new byte[] { (byte)chunkType, 0x00, 0x00, 0x00 });

            await AssertRejectedWithoutHanging(() => ParsePacketView(packet));
        }

        [Theory]
        [InlineData(0x80)]
        [InlineData(0x0B)]
        public async Task PacketParseWithZeroLengthChunkDoesNotHang(int chunkType)
        {
            var packet = BuildPacket(new byte[] { (byte)chunkType, 0x00, 0x00, 0x00 });

            await AssertRejectedWithoutHanging(() => SctpPacket.Parse(packet));
        }

        #endregion

        #region Error causes

        [Fact]
        public async Task ErrorCauseWithZeroLengthDoesNotHang()
        {
            // ERROR chunk, length 8, holding one cause header that declares a length of 0.
            var chunk = new byte[] { (byte)SctpChunkType.ERROR, 0x00, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00 };

            await AssertRejectedWithoutHanging(() => EnumerateErrorCodes(chunk));
        }

        [Fact]
        public async Task ErrorCausesAreSteppedByPaddedLength()
        {
            // Protocol Violation with one byte of information (length 5, padded to 8), then Out of Resource (length 4).
            var chunk = new byte[]
            {
                (byte)SctpChunkType.ERROR, 0x00, 0x00, 0x10,
                0x00, 0x0D, 0x00, 0x05, 0x41, 0x00, 0x00, 0x00,
                0x00, 0x04, 0x00, 0x04
            };

            var enumerate = Task.Run(() => EnumerateErrorCodes(chunk));

            Assert.True(await Task.WhenAny(enumerate, Task.Delay(HANG_TIMEOUT)) == enumerate, "Enumerating the error causes did not return.");
            Assert.Equal(new[] { SctpErrorCauseCode.ProtocolViolation, SctpErrorCauseCode.OutOfResource }, await enumerate);
        }

        #endregion

        /// <summary>
        /// Runs the parse on a worker so a regression fails the test instead of hanging the run.
        /// </summary>
        private static async Task AssertRejectedWithoutHanging(Action parse)
        {
            var parseTask = Task.Run(parse);

            Assert.True(await Task.WhenAny(parseTask, Task.Delay(HANG_TIMEOUT)) == parseTask, "The parse did not return.");
            await Assert.ThrowsAsync<ApplicationException>(() => parseTask);
        }

        private static void ParseChunkView(byte[] chunk) => new SctpChunkView(chunk);

        private static void ParsePacketView(byte[] packet) => SctpPacketView.Parse(packet);

        private static List<SctpErrorCauseCode> EnumerateErrorCodes(byte[] chunk)
        {
            var codes = new List<SctpErrorCauseCode>();
            foreach (var code in new SctpChunkView(chunk).GetErrorCodes())
            {
                codes.Add(code);
            }
            return codes;
        }

        /// <summary>
        /// A SACK chunk declaring the given length and counts, with nothing after the fixed parameters.
        /// </summary>
        private static byte[] BuildSack(int chunkLength, int numGapAckBlocks, int numDuplicateTSNs)
        {
            var chunk = new byte[chunkLength];
            chunk[0] = (byte)SctpChunkType.SACK;
            NetConvert.ToBuffer((ushort)chunkLength, chunk, 2);
            NetConvert.ToBuffer(1000U, chunk, 4);                        // Cumulative TSN ack.
            NetConvert.ToBuffer(262144U, chunk, 8);                      // ARwnd.
            NetConvert.ToBuffer((ushort)numGapAckBlocks, chunk, 12);
            NetConvert.ToBuffer((ushort)numDuplicateTSNs, chunk, 14);
            return chunk;
        }

        /// <summary>
        /// Length 28: 16 fixed, 2 gap ack blocks (8) and 1 duplicate TSN (4).
        /// </summary>
        private static byte[] BuildMatchingSack()
        {
            var chunk = BuildSack(28, 2, 1);
            NetConvert.ToBuffer((ushort)3, chunk, 16);
            NetConvert.ToBuffer((ushort)5, chunk, 18);
            NetConvert.ToBuffer((ushort)8, chunk, 20);
            NetConvert.ToBuffer((ushort)9, chunk, 22);
            NetConvert.ToBuffer(1234U, chunk, 24);
            return chunk;
        }

        /// <summary>
        /// An SCTP common header (ports 5000, verification tag 1; the checksum isn't checked by the parsers) followed by the chunk.
        /// </summary>
        private static byte[] BuildPacket(byte[] chunk)
        {
            var packet = new byte[SctpHeader.SCTP_HEADER_LENGTH + chunk.Length];
            NetConvert.ToBuffer((ushort)5000, packet, 0);
            NetConvert.ToBuffer((ushort)5000, packet, 2);
            NetConvert.ToBuffer(1U, packet, 4);
            chunk.CopyTo(packet, SctpHeader.SCTP_HEADER_LENGTH);
            return packet;
        }
    }
}

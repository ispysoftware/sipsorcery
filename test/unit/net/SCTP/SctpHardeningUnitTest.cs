//-----------------------------------------------------------------------------
// Filename: SctpHardeningUnitTest.cs
//
// Description: Unit tests for the SCTP checksum calculation and for the limits
// on fragmented message reassembly.
//
// License:
// BSD 3-Clause "New" or "Revised" License, see included LICENSE.md file.
//-----------------------------------------------------------------------------

using System;
using System.Linq;
using Xunit;

namespace SIPSorcery.Net.UnitTests
{
    [Trait("Category", "unit")]
    public class SctpHardeningUnitTest
    {
        /// <summary>
        /// The span based checksum (which uses the CPU's CRC instruction where there is one) must
        /// agree with the table based one for every length around the 8 byte stride.
        /// </summary>
        [Fact]
        public void Crc32cSpanMatchesTable()
        {
            var random = new Random(12345);

            for (int length = 0; length <= 67; length++)
            {
                byte[] data = new byte[length];
                random.NextBytes(data);

                Assert.Equal(CRC32C.Calculate(data, 0, data.Length), CRC32C.Calculate(data.AsSpan()));
            }

            // The check value for CRC-32C of "123456789".
            Assert.Equal(0xE3069283u, CRC32C.Calculate("123456789"u8));
        }

        /// <summary>
        /// A checksum taken in pieces must equal the checksum of the whole.
        /// </summary>
        [Fact]
        public void Crc32cAppendInPiecesMatchesWhole()
        {
            byte[] data = new byte[200];
            new Random(54321).NextBytes(data);

            foreach (int split in new[] { 0, 1, 7, 8, 9, 12, 100, 199, 200 })
            {
                uint crc = CRC32C.Append(CRC32C.SEED, data.AsSpan(0, split));
                crc = CRC32C.Append(crc, data.AsSpan(split));

                Assert.Equal(CRC32C.Calculate(data.AsSpan()), CRC32C.Finish(crc));
            }
        }

        /// <summary>
        /// A serialised packet verifies, and stops verifying when any byte of it is changed.
        /// </summary>
        [Fact]
        public void VerifyChecksumAcceptsGoodAndRejectsCorruptPackets()
        {
            var packet = new SctpPacket(5000, 5000, 0xAABBCCDD);
            packet.AddChunk(new SctpDataChunk(false, true, true, 1, 0, 0, 0, Enumerable.Range(0, 100).Select(x => (byte)x).ToArray()));
            byte[] buffer = packet.GetBytes();

            Assert.True(SctpPacket.VerifyChecksum(buffer));

            foreach (int index in new[] { 0, 7, 8, 11, 12, buffer.Length - 1 })
            {
                byte[] corrupt = (byte[])buffer.Clone();
                corrupt[index] ^= 0x01;
                Assert.False(SctpPacket.VerifyChecksum(corrupt));
            }

            // Too short to hold a header at all.
            Assert.False(SctpPacket.VerifyChecksum(new byte[4]));
        }

        /// <summary>
        /// A fragmented message larger than the receiver will deliver is dropped without an
        /// exception, and messages on other streams are still delivered afterwards.
        /// </summary>
        [Fact]
        public void OversizeFragmentedMessageIsDropped()
        {
            const int fragmentSize = 1000;
            const int fragmentCount = 300; // 300KB, over the 256KB limit for one message.

            SctpDataReceiver receiver = new SctpDataReceiver(1_000_000, fragmentSize, 0);
            byte[] fragment = new byte[fragmentSize];

            uint tsn = 0;
            for (int i = 0; i < fragmentCount; i++)
            {
                bool isFirst = i == 0;
                bool isLast = i == fragmentCount - 1;
                var frames = receiver.OnDataChunk(new SctpDataChunk(false, isFirst, isLast, tsn++, 0, 0, 0, fragment));

                Assert.Empty(frames);
            }

            Assert.Equal(tsn - 1, receiver.CumulativeAckTSN);

            // A message on another stream still arrives.
            var next = receiver.OnDataChunk(new SctpDataChunk(false, true, true, tsn++, 1, 0, 0, new byte[] { 0x55 }));

            Assert.Single(next);
            Assert.Equal(new byte[] { 0x55 }, next.Single().UserData.ToArray());
        }

        /// <summary>
        /// Fragments of a message that never ends stop being accepted once the fragment store is
        /// full, rather than being held without limit. A rejected fragment is not acknowledged.
        /// </summary>
        [Fact]
        public void FragmentStoreIsBounded()
        {
            const int fragmentSize = 1000;

            SctpDataReceiver receiver = new SctpDataReceiver(4_000_000, fragmentSize, 0);
            byte[] fragment = new byte[fragmentSize];

            // A beginning and then middle fragments only: 600KB offered, the store holds 512KB.
            uint tsn = 0;
            for (int i = 0; i < 600; i++)
            {
                Assert.Empty(receiver.OnDataChunk(new SctpDataChunk(false, i == 0, false, tsn++, 0, 0, 0, fragment)));
            }

            // 524 fragments of 1000 bytes fit under 524,288 bytes; the rest were turned away unacknowledged.
            Assert.Equal(523u, receiver.CumulativeAckTSN);
        }
    }
}

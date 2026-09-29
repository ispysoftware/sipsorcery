//-----------------------------------------------------------------------------
// Filename: STUNMalformedPacketUnitTest.cs
//
// Description: Malformed/short STUN packets must be rejected without throwing:
// an exception in the RTP socket's receive path used to close the socket and
// kill the WebRTC session (one unauthenticated datagram was enough).
//
// History:
// Sep 2026     iSpyConnect     Created.
//
// License:
// BSD 3-Clause "New" or "Revised" License, see included LICENSE.md file.
//-----------------------------------------------------------------------------

using System;
using System.Buffers.Binary;
using Xunit;

namespace SIPSorcery.Net.UnitTests
{
    [Trait("Category", "unit")]
    public class STUNMalformedPacketUnitTest
    {
        [Theory]
        [InlineData(4)]
        [InlineData(12)]
        [InlineData(19)]
        public void ShortPacketParsesToNull(int length)
        {
            var packet = new byte[length];
            packet[1] = 0x01; // Binding request type prefix.

            Assert.Null(STUNMessage.ParseSTUNMessage(packet));
        }

        [Fact]
        public void ShortDataIndicationParsesToNull()
        {
            var packet = new byte[] { 0x00, 0x17, 0x00, 0x00 };

            Assert.Null(STUNMessage.ParseSTUNMessage(packet));
        }

        [Theory]
        [InlineData((ushort)0x0020, 0)]   // XOR-MAPPED-ADDRESS, empty value
        [InlineData((ushort)0x0020, 4)]   // XOR-MAPPED-ADDRESS, too short for IPv4
        [InlineData((ushort)0x0001, 4)]   // MAPPED-ADDRESS, too short
        [InlineData((ushort)0x0009, 0)]   // ERROR-CODE, empty value
        public void ShortTypedAttributeIsSkippedNotThrown(ushort attributeType, int valueLength)
        {
            int paddedValueLength = (valueLength + 3) & ~3;
            var packet = new byte[20 + 4 + paddedValueLength];
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(0), 0x0001); // Binding request.
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2), (ushort)(4 + paddedValueLength));
            BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(4), STUNHeader.MAGIC_COOKIE);
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(20), attributeType);
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(22), (ushort)valueLength);

            var message = STUNMessage.ParseSTUNMessage(packet);

            Assert.NotNull(message);
            Assert.Empty(message.Attributes);
        }

        [Fact]
        public void IPv6FamilyXorAddressWithIPv4LengthIsSkipped()
        {
            var packet = new byte[20 + 4 + 8];
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(0), 0x0101); // Binding success response.
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2), 12);
            BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(4), STUNHeader.MAGIC_COOKIE);
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(20), 0x0020); // XOR-MAPPED-ADDRESS
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(22), 8);
            packet[25] = 0x02; // IPv6 family with only an IPv4-sized value.

            var message = STUNMessage.ParseSTUNMessage(packet);

            Assert.NotNull(message);
            Assert.Empty(message.Attributes);
        }
    }
}

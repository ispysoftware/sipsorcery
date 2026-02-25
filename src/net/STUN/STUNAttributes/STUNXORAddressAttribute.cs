//-----------------------------------------------------------------------------
// Filename: STUNXORAddressAttribute.cs
//
// Description: Implements STUN XOR mapped address attribute as defined in RFC5389.
//
// Author(s):
// Aaron Clauson (aaron@sipsorcery.com)
//
// History:
// 15 Oct 2014	Aaron Clauson	Created, Hobart, Australia.
//
// License: 
// BSD 3-Clause "New" or "Revised" License, see included LICENSE.md file.
//-----------------------------------------------------------------------------

using System;
using System.Buffers.Binary;
using System.Linq;
using System.Net;
using SIPSorcery.Sys;

namespace SIPSorcery.Net
{
    /// <summary>
    /// This attribute is the same as the mapped address attribute except the address details are XOR'ed with the STUN magic cookie. 
    /// THe reason for this is to stop NAT application layer gateways from doing string replacements of private IP addresses and ports.
    /// </summary>
    public class STUNXORAddressAttribute : STUNAddressAttributeBase
    {
        /// <summary>
        /// Obsolete.
        /// <br/> For IPv6 support, please parse using
        /// <br/> <see cref="STUNXORAddressAttribute(STUNAttributeTypesEnum, byte[], byte[])"/>
        /// <br/> <br/>
        /// Parses an XOR-d (encoded) IPv4 Address attribute.
        /// </summary>
        [Obsolete("Provided for backward compatibility with RFC3489 clients.")]
        public STUNXORAddressAttribute(STUNAttributeTypesEnum attributeType, byte[] attributeValue)
            : this(attributeType, attributeValue, null)
        {
        }

        /// <summary>
        /// Parses an XOR-d (encoded) Address attribute with IPv4/IPv6 support.
        /// </summary>
        /// <param name="attributeType">of <see cref="STUNAttributeTypesEnum.XORMappedAddress"/>
        /// or <see cref="STUNAttributeTypesEnum.XORPeerAddress"/>
        /// or <see cref="STUNAttributeTypesEnum.XORRelayedAddress"/></param>
        /// <param name="attributeValue">the raw bytes</param>
        /// <param name="transactionId">the <see cref="STUNHeader.TransactionId"/></param>
        public STUNXORAddressAttribute(STUNAttributeTypesEnum attributeType, byte[] attributeValue, byte[] transactionId)
            : base(attributeType, attributeValue)
        {
            Family = attributeValue[1];
            AddressAttributeLength = Family == 1 ? ADDRESS_ATTRIBUTE_IPV4_LENGTH : ADDRESS_ATTRIBUTE_IPV6_LENGTH;
            TransactionId = transactionId;

            byte[] address;

            // Read Port (Big-Endian) and XOR with high 16 bits of Magic Cookie
            Port = (ushort)(BinaryPrimitives.ReadUInt16BigEndian(attributeValue.AsSpan(2)) ^ (ushort)(STUNHeader.MAGIC_COOKIE >> 16));

            // Read Address (Big-Endian), XOR with Magic Cookie, and write back to bytes
            address = new byte[4];
            uint xoredAddress = BinaryPrimitives.ReadUInt32BigEndian(attributeValue.AsSpan(4)) ^ STUNHeader.MAGIC_COOKIE;
            BinaryPrimitives.WriteUInt32BigEndian(address, xoredAddress);

            if (Family == STUNAttributeConstants.IPv6AddressFamily[0] && TransactionId != null)
            {
                address = new byte[12]; // Remaining 12 bytes of IPv6 (after the first 4)
                Span<byte> addrSpan = address;

                // XOR against the Transaction ID blocks (indices 0, 4, 8)
                BinaryPrimitives.WriteUInt32BigEndian(addrSpan.Slice(0, 4),
                    BinaryPrimitives.ReadUInt32BigEndian(attributeValue.AsSpan(8)) ^ BinaryPrimitives.ReadUInt32BigEndian(TransactionId.AsSpan(0)));

                BinaryPrimitives.WriteUInt32BigEndian(addrSpan.Slice(4, 4),
                    BinaryPrimitives.ReadUInt32BigEndian(attributeValue.AsSpan(12)) ^ BinaryPrimitives.ReadUInt32BigEndian(TransactionId.AsSpan(4)));

                BinaryPrimitives.WriteUInt32BigEndian(addrSpan.Slice(8, 4),
                    BinaryPrimitives.ReadUInt32BigEndian(attributeValue.AsSpan(16)) ^ BinaryPrimitives.ReadUInt32BigEndian(TransactionId.AsSpan(8)));
            }

            Address = new IPAddress(address);
        }

        /// <summary>
        /// Obsolete.
        /// <br/> For IPv6 support, please create using <see cref="STUNXORAddressAttribute(STUNAttributeTypesEnum, int, IPAddress, byte[])"/>
        /// <br/> <br/>
        /// Creates an XOR-d (encoded) IPv4 Address attribute.
        /// </summary>
        [Obsolete("Provided for backward compatibility with RFC3489 clients.")]
        public STUNXORAddressAttribute(STUNAttributeTypesEnum attributeType, int port, IPAddress address)
            : this(attributeType, port, address, null)
        {
        }

        /// <summary>
        /// Creates an XOR-d (encoded) Address attribute with IPv4/IPv6 support.
        /// </summary>
        /// <param name="attributeType">of <see cref="STUNAttributeTypesEnum.XORMappedAddress"/>
        /// or <see cref="STUNAttributeTypesEnum.XORPeerAddress"/>
        /// or <see cref="STUNAttributeTypesEnum.XORRelayedAddress"/></param>
        /// <param name="port">Allocated Port</param>
        /// <param name="address">Allocated IPAddress</param>
        /// <param name="transactionId">the <see cref="STUNHeader.TransactionId"/></param>
        public STUNXORAddressAttribute(STUNAttributeTypesEnum attributeType, int port, IPAddress address, byte[] transactionId)
            : base(attributeType, null)
        {
            Port = port;
            Address = address;
            Family = address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 1 : 2;
            AddressAttributeLength = Family == 1 ? ADDRESS_ATTRIBUTE_IPV4_LENGTH : ADDRESS_ATTRIBUTE_IPV6_LENGTH;
            TransactionId = transactionId;
        }

        public override int ToByteBuffer(byte[] buffer, int startIndex)
        {
            BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(startIndex), (ushort)base.AttributeType);
            BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(startIndex + 2), AddressAttributeLength);

            buffer[startIndex + 4] = 0x00;
            buffer[startIndex + 5] = (byte)Family;

            var address = Address.GetAddressBytes();

            ushort xorPort = (ushort)(Convert.ToUInt16(Port) ^ (ushort)(STUNHeader.MAGIC_COOKIE >> 16));
            uint xorAddress = BinaryPrimitives.ReadUInt32BigEndian(address) ^ STUNHeader.MAGIC_COOKIE;

            BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(startIndex + 6), xorPort);
            BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(startIndex + 8), xorAddress);

            if (Family == STUNAttributeConstants.IPv6AddressFamily[0] && TransactionId != null)
            {
                Span<byte> dest = buffer.AsSpan(startIndex + 12);

                // XOR the remaining 12 bytes of the IPv6 address against the Transaction ID in 4-byte chunks
                BinaryPrimitives.WriteUInt32BigEndian(dest.Slice(0, 4),
                    BinaryPrimitives.ReadUInt32BigEndian(address.AsSpan(4)) ^ BinaryPrimitives.ReadUInt32BigEndian(TransactionId.AsSpan(0)));

                BinaryPrimitives.WriteUInt32BigEndian(dest.Slice(4, 4),
                    BinaryPrimitives.ReadUInt32BigEndian(address.AsSpan(8)) ^ BinaryPrimitives.ReadUInt32BigEndian(TransactionId.AsSpan(4)));

                BinaryPrimitives.WriteUInt32BigEndian(dest.Slice(8, 4),
                    BinaryPrimitives.ReadUInt32BigEndian(address.AsSpan(12)) ^ BinaryPrimitives.ReadUInt32BigEndian(TransactionId.AsSpan(8)));
            }

            return STUNAttribute.STUNATTRIBUTE_HEADER_LENGTH + PaddedLength;
        }

        public override string ToString()
        {
            string attrDescrStr = "STUN XOR_MAPPED_ADDRESS Attribute: " + base.AttributeType + ", address=" + Address.ToString() + ", port=" + Port + ".";

            return attrDescrStr;
        }

        public IPEndPoint GetIPEndPoint()
        {
            if (Address != null)
            {
                return new IPEndPoint(Address, Port);
            }
            else
            {
                return null;
            }
        }
    }
}

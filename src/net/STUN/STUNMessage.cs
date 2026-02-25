//-----------------------------------------------------------------------------
// Filename: STUNMessage.cs
//
// Description: Implements STUN Message as defined in RFC5389.
//
// Author(s):
// Aaron Clauson (aaron@sipsorcery.com)
//
// History:
// 26 Nov 2010	Aaron Clauson	Created, Hobart, Australia.
//
// License: 
// BSD 3-Clause "New" or "Revised" License, see included LICENSE.md file.
//-----------------------------------------------------------------------------

using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;
using SIPSorcery.Sys;

namespace SIPSorcery.Net
{
    public class STUNMessage
    {
        private const int FINGERPRINT_XOR = 0x5354554e;
        private const int MESSAGE_INTEGRITY_ATTRIBUTE_HMAC_LENGTH = 20;
        private const int FINGERPRINT_ATTRIBUTE_CRC32_LENGTH = 4;

        private static ILogger logger = Log.Logger;

        /// <summary>
        /// For parsed STUN messages this indicates whether a valid fingerprint
        /// as attached to the message.
        /// </summary>
        public bool isFingerprintValid { get; private set; } = false;

        /// <summary>
        /// For received STUN messages this is the raw buffer.
        /// </summary>
        private byte[] _receivedBuffer;

        public STUNHeader Header = new STUNHeader();
        public List<STUNAttribute> Attributes = new List<STUNAttribute>();

        public ushort PaddedSize
        {
            get
            {
                return (ushort)(STUNHeader.STUN_HEADER_LENGTH + Header.MessageLength);
            }
        }

        public STUNMessage()
        { }

        public STUNMessage(STUNMessageTypesEnum stunMessageType)
        {
            Header = new STUNHeader(stunMessageType);
        }

        public void AddUsernameAttribute(string username)
        {
            byte[] usernameBytes = Encoding.UTF8.GetBytes(username);
            Attributes.Add(new STUNAttribute(STUNAttributeTypesEnum.Username, usernameBytes));
        }

        public void AddNonceAttribute(string nonce)
        {
            byte[] nonceBytes = Encoding.UTF8.GetBytes(nonce);
            Attributes.Add(new STUNAttribute(STUNAttributeTypesEnum.Nonce, nonceBytes));
        }

        public void AddXORMappedAddressAttribute(IPAddress remoteAddress, int remotePort)
        {
            AddXORAddressAttribute(STUNAttributeTypesEnum.XORMappedAddress, remoteAddress, remotePort);
        }

        public void AddXORPeerAddressAttribute(IPAddress remoteAddress, int remotePort)
        {
            AddXORAddressAttribute(STUNAttributeTypesEnum.XORPeerAddress, remoteAddress, remotePort);
        }

        public void AddXORAddressAttribute(STUNAttributeTypesEnum addressType, IPAddress remoteAddress, int remotePort)
        {
            STUNXORAddressAttribute xorAddressAttribute = new STUNXORAddressAttribute(addressType, remotePort, remoteAddress, Header.TransactionId);
            Attributes.Add(xorAddressAttribute);
        }

        public static STUNMessage ParseSTUNMessage(ReadOnlyMemory<byte> buffer)
        {
            // The IsEmpty check replaces the old, more complex check.
            if (buffer.IsEmpty)
            {
                return null;
            }

            // Get a Span for all synchronous processing within this method.
            ReadOnlySpan<byte> bufferSpan = buffer.Span;

            STUNMessage stunMessage = new STUNMessage();

            // This copy is still here for lifetime reasons, as discussed.
            stunMessage._receivedBuffer = buffer.ToArray();
            stunMessage.Header = STUNHeader.ParseSTUNHeader(bufferSpan);

            if (stunMessage.Header.MessageLength > 0)
            {
                // Use buffer.Length instead of the old bufferLength parameter.
                STUNAttribute.TryParseMessageAttributes(stunMessage.Attributes, bufferSpan,
                    STUNHeader.STUN_HEADER_LENGTH, buffer.Length, stunMessage.Header);
            }

            if (stunMessage.Attributes.Count > 0 && stunMessage.Attributes[stunMessage.Attributes.Count - 1].AttributeType == STUNAttributeTypesEnum.FingerPrint)
            {
                var fingerprintAttribute = stunMessage.Attributes[stunMessage.Attributes.Count - 1];

                var input = bufferSpan.Slice(0, buffer.Length - STUNAttribute.STUNATTRIBUTE_HEADER_LENGTH - FINGERPRINT_ATTRIBUTE_CRC32_LENGTH);

                uint crc = Crc32.Compute(input) ^ FINGERPRINT_XOR;
                Span<byte> calculatedFingerprint = stackalloc byte[4];
                System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(calculatedFingerprint, crc);

                if (fingerprintAttribute.Value.AsSpan().SequenceEqual(calculatedFingerprint))
                {
                    stunMessage.isFingerprintValid = true;
                }
            }

            return stunMessage;
        }

        public byte[] ToByteBufferStringKey(string messageIntegrityKey, bool addFingerprint)
        {
            return ToByteBuffer(messageIntegrityKey.NotNullOrBlank() ? System.Text.Encoding.UTF8.GetBytes(messageIntegrityKey) : null, addFingerprint);
        }

        public byte[] ToByteBuffer(byte[] messageIntegrityKey, bool addFingerprint)
        {
            UInt16 attributesLength = 0;
            foreach (STUNAttribute attribute in Attributes)
            {
                attributesLength += Convert.ToUInt16(STUNAttribute.STUNATTRIBUTE_HEADER_LENGTH + attribute.PaddedLength);
            }

            if (messageIntegrityKey != null)
            {
                attributesLength += STUNAttribute.STUNATTRIBUTE_HEADER_LENGTH + MESSAGE_INTEGRITY_ATTRIBUTE_HMAC_LENGTH;
            }

            int messageLength = STUNHeader.STUN_HEADER_LENGTH + attributesLength;

            byte[] buffer = new byte[messageLength];

            BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(0), (ushort)Header.MessageType);
            BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(2), attributesLength);
            BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(4), STUNHeader.MAGIC_COOKIE);

            Buffer.BlockCopy(Header.TransactionId, 0, buffer, 8, STUNHeader.TRANSACTION_ID_LENGTH);

            int attributeIndex = 20;
            foreach (STUNAttribute attr in Attributes)
            {
                attributeIndex += attr.ToByteBuffer(buffer, attributeIndex);
            }

            //logger.LogDebug($"Pre HMAC STUN message: {ByteBufferInfo.HexStr(buffer, attributeIndex)}");

            if (messageIntegrityKey != null)
            {
                var integrityAttibtue = new STUNAttribute(STUNAttributeTypesEnum.MessageIntegrity, new byte[MESSAGE_INTEGRITY_ATTRIBUTE_HMAC_LENGTH]);

                HMACSHA1 hmacSHA = new HMACSHA1(messageIntegrityKey);
                byte[] hmac = hmacSHA.ComputeHash(buffer, 0, attributeIndex);

                integrityAttibtue.Value = hmac;
                attributeIndex += integrityAttibtue.ToByteBuffer(buffer, attributeIndex);
            }

            if (addFingerprint)
            {
                // The fingerprint attribute length has not been included in the length in the STUN header so adjust it now.
                attributesLength += STUNAttribute.STUNATTRIBUTE_HEADER_LENGTH + FINGERPRINT_ATTRIBUTE_CRC32_LENGTH;
                messageLength += STUNAttribute.STUNATTRIBUTE_HEADER_LENGTH + FINGERPRINT_ATTRIBUTE_CRC32_LENGTH;

                BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(2), attributesLength);

                var fingerprintAttribute = new STUNAttribute(STUNAttributeTypesEnum.FingerPrint, new byte[FINGERPRINT_ATTRIBUTE_CRC32_LENGTH]);
                uint crc = Crc32.Compute(buffer) ^ FINGERPRINT_XOR;
                byte[] fingerPrint = new byte[4];
                BinaryPrimitives.WriteUInt32BigEndian(fingerPrint, crc);
                fingerprintAttribute.Value = fingerPrint;

                Array.Resize(ref buffer, messageLength);
                fingerprintAttribute.ToByteBuffer(buffer, attributeIndex);
            }

            return buffer;
        }

        public new string ToString()
        {
            string messageDescr = "STUN Message: " + Header.MessageType.ToString() + ", length=" + Header.MessageLength;

            foreach (STUNAttribute attribute in Attributes)
            {
                messageDescr += "\n " + attribute.ToString();
            }

            return messageDescr;
        }

        /// <summary>
        /// Check that the message integrity attribute is correct.
        /// </summary>
        /// <param name="messageIntegrityKey">The message integrity key that was used to generate
        /// the HMAC for the original message.</param>
        /// <returns>True if the fingerprint and HMAC of the STUN message are valid. False if not.</returns>
        public bool CheckIntegrity(byte[] messageIntegrityKey)
        {
            bool isHmacValid = false;

            if (isFingerprintValid)
            {
                if (Attributes.Count > 2 && Attributes[Attributes.Count - 2].AttributeType == STUNAttributeTypesEnum.MessageIntegrity)
                {
                    var messageIntegrityAttribute = Attributes[Attributes.Count - 2];

                    int preImageLength = _receivedBuffer.Length
                        - STUNAttribute.STUNATTRIBUTE_HEADER_LENGTH * 2
                        - MESSAGE_INTEGRITY_ATTRIBUTE_HMAC_LENGTH
                        - FINGERPRINT_ATTRIBUTE_CRC32_LENGTH;

                    // Need to adjust the STUN message length field for to remove the fingerprint.
                    ushort length = (ushort)(Header.MessageLength - STUNAttribute.STUNATTRIBUTE_HEADER_LENGTH - FINGERPRINT_ATTRIBUTE_CRC32_LENGTH);
                    BinaryPrimitives.WriteUInt16BigEndian(_receivedBuffer.AsSpan(2), length);

                    HMACSHA1 hmacSHA = new HMACSHA1(messageIntegrityKey);
                    byte[] calculatedHmac = hmacSHA.ComputeHash(_receivedBuffer, 0, preImageLength);

                    //logger.LogDebug($"Received Message integrity HMAC  : {messageIntegrityAttribute.Value.HexStr()}.");
                    //logger.LogDebug($"Calculated Message integrity HMAC: {calculatedHmac.HexStr()}.");

                    isHmacValid = messageIntegrityAttribute.Value.HexStr() == calculatedHmac.HexStr();
                }
            }

            return isHmacValid;
        }
    }
}

/*
 * File: TransportWideCCExtension.cs
 * 
 * Description:
 *   Implements the Transport Wide Congestion Control (TWCC) RTP header extension.
 *   This extension carries a 16-bit sequence number and adheres to the IETF draft:
 *   http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01
 *   It provides functionality to marshal and unmarshal the TWCC header extension.
 * 
 * Author:        Sean Tearney
 * Date:          2025-02-22
 * 
 * License:       BSD 3-Clause "New" or "Revised" License, see included LICENSE.md file.
 * 
 * Change Log:
 *   2025-02-20  Initial creation.
 */
using System;
using System.Buffers.Binary;

namespace SIPSorcery.Net
{
    /// <summary>
    /// TransportWideCCExtension implements the Transport Wide Congestion Control (TWCC)
    /// RTP header extension as defined in:
    /// http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01
    /// 
    /// This extension carries a 16-bit sequence number (2 bytes of payload).
    /// The one-byte header is constructed as (id &lt;&lt; 4) | (extensionSize - 1).
    /// </summary>
    public class TransportWideCCExtension : RTPHeaderExtension
    {
        public const string RTP_HEADER_EXTENSION_URI = "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01";
        
        public static readonly string[] SUPPORTED_URIS = 
        {
            RTP_HEADER_EXTENSION_URI,
            "urn:ietf:params:rtp-hdrext:transport-wide-cc",
            "http://www.webrtc.org/experiments/rtp-hdrext/transport-wide-cc-02"

        };

        internal const int RTP_HEADER_EXTENSION_SIZE = 2; // TWCC payload: 2 bytes for sequence number.

        /// <summary>
        /// The TWCC sequence number.
        /// </summary>
        public ushort SequenceNumber { get; private set; }

        /// <summary>
        /// Constructs a TWCC header extension with the negotiated extension id.
        /// </summary>
        /// <param name="id">The negotiated header extension id.</param>
        public TransportWideCCExtension(int id)
            : base(id, RTP_HEADER_EXTENSION_URI, SUPPORTED_URIS, RTP_HEADER_EXTENSION_SIZE, RTPHeaderExtensionType.OneByte)
        {
        }

        /// <summary>
        /// Generic setter override. Expects a ushort representing the sequence number.
        /// </summary>
        /// <param name="value">The TWCC sequence number as an object (ushort).</param>
        public override void Set(object value)
        {
            if (value is ushort seq)
            {
                SequenceNumber = seq;
            }
            else
            {
                throw new ArgumentException("Value must be a ushort representing the TWCC sequence number", nameof(value));
            }
        }

        /// <summary>
        /// Writes the 2-byte TWCC sequence number payload into the destination buffer.
        /// </summary>
        /// <param name="destination">The buffer to write the payload into.</param>
        /// <returns>The number of bytes written (always 2 for TWCC).</returns>
        public override int Marshal(Span<byte> destination)
        {
            if (destination.Length < RTP_HEADER_EXTENSION_SIZE)
            {
                throw new ArgumentException($"Destination buffer is too small for TWCC payload, requires {RTP_HEADER_EXTENSION_SIZE} bytes but got {destination.Length}.", nameof(destination));
            }

            BinaryPrimitives.WriteUInt16BigEndian(destination, SequenceNumber);

            return RTP_HEADER_EXTENSION_SIZE;
        }

        /// <summary>
        /// Parses the 2-byte TWCC sequence number from a buffer slice and sets the
        /// SequenceNumber property.
        /// </summary>
        /// <param name="data">The buffer slice containing the 2-byte extension payload.</param>
        public override void Unmarshal(ReadOnlySpan<byte> data)
        {
            if (data.Length != RTP_HEADER_EXTENSION_SIZE)
            {
                throw new ArgumentException($"Invalid TWCC extension payload size, expected {RTP_HEADER_EXTENSION_SIZE} but got {data.Length}.");
            }

            SequenceNumber = BinaryPrimitives.ReadUInt16BigEndian(data);
        }
    }
}

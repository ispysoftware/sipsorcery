using System;
using System.Buffers; // Required for ArrayPool

namespace SIPSorcery.Net
{
    public class RTPPacket
    {
        public RTPHeader Header { get; private set; }

        // The payload is now a single, unified property.
        public ReadOnlyMemory<byte> Payload { get; private set; }

        private int _srtpProtectionLength = 0;

        /// <summary>
        /// Creates an empty RTP packet.
        /// </summary>
        public RTPPacket()
        {
            Header = new RTPHeader();
            Payload = ReadOnlyMemory<byte>.Empty;
        }

        /// <summary>
        /// Creates an RTP packet by parsing a buffer. This is a "zero-copy" operation
        /// that does not allocate a new buffer for the payload.
        /// </summary>
        /// <param name="packetBuffer">The buffer containing the full RTP packet.</param>
        public RTPPacket(ReadOnlyMemory<byte> packetBuffer)
        {
            if (RTPHeader.TryParse(packetBuffer, out var header))
            {
                Header = header;
                // Store a slice of the original buffer, NO COPYING.
                Payload = packetBuffer.Slice(header.Length, header.PayloadSize);
            }
            else
            {
                throw new ApplicationException("Could not parse RTP packet from buffer.");
            }
        }

        /// <summary>
        /// Creates an RTP packet from a pre-parsed header and a payload.
        /// This is also a zero-copy operation.
        /// </summary>
        public RTPPacket(RTPHeader header, ReadOnlyMemory<byte> payload)
        {
            Header = header;
            Payload = payload;
        }

        /// <summary>
        /// The total length of the serialized packet in bytes.
        /// </summary>
        public int Length => Header.Length + Payload.Length + _srtpProtectionLength;

        /// <summary>
        /// Writes the complete RTP packet (header and payload) to a destination buffer.
        /// This method is allocation-free.
        /// </summary>
        /// <param name="destination">The buffer to write the packet to.</param>
        /// <returns>The number of bytes written.</returns>
        public int WriteTo(Span<byte> destination)
        {
            if (destination.Length < Length)
            {
                throw new ArgumentException("Destination buffer is too small to write the RTP packet.");
            }

            int headerLength = Header.WriteTo(destination);
            Payload.Span.CopyTo(destination.Slice(headerLength));

            // Logic for writing SRTP protection bytes would go here if needed.

            return Length;
        }

        /// <summary>
        /// Gets a new byte array containing the full packet.
        /// NOTE: This method allocates a new array and is less efficient than WriteTo.
        /// </summary>
        public byte[] GetBytes()
        {
            byte[] buffer = new byte[Length];
            WriteTo(buffer);
            return buffer;
        }

        /// <summary>
        /// Tries to parse an RTP packet from a buffer in a zero-copy manner.
        /// </summary>
        public static bool TryParse(ReadOnlyMemory<byte> buffer, out RTPPacket packet)
        {
            if (RTPHeader.TryParse(buffer, out _))
            {
                packet = new RTPPacket(buffer);
                return true;
            }

            packet = null;
            return false;
        }

    }
}

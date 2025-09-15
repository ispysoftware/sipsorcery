using System;
using System.Buffers.Binary;

namespace SIPSorcery.Net
{
    public class AbsSendTimeExtension : RTPHeaderExtension
    {
        public const string RTP_HEADER_EXTENSION_URI = "http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time";
        internal const int RTP_HEADER_EXTENSION_SIZE = 3; // The payload is 3 bytes (24 bits).

        private static readonly DateTimeOffset UnixEpoch = new DateTimeOffset(1970, 1, 1, 0, 0, 0, TimeSpan.Zero);
        public static readonly string[] SUPPORTED_URIS =
        {
            RTP_HEADER_EXTENSION_URI,
            "urn:ietf:params:rtp-hdrext:sdes:abs-send-time"
        };
        /// <summary>
        /// The parsed 24-bit absolute send time value.
        /// </summary>
        public uint Timestamp { get; private set; }

        public AbsSendTimeExtension(int id) : base(id, RTP_HEADER_EXTENSION_URI,
            SUPPORTED_URIS,
            RTP_HEADER_EXTENSION_SIZE, RTPHeaderExtensionType.OneByte)
        { }

        public override void Set(Object value)
        {
            if (value is uint timestamp)
            {
                Timestamp = timestamp;
            }
        }

        // --- START OF REFACTORED METHODS ---

        /// <summary>
        /// Calculates the current absolute send time and writes the 3-byte payload
        /// into the destination buffer.
        /// </summary>
        public override int Marshal(Span<byte> destination)
        {
            if (destination.Length < RTP_HEADER_EXTENSION_SIZE)
            {
                throw new ArgumentException($"Destination buffer is too small for AbsSendTime payload, requires {RTP_HEADER_EXTENSION_SIZE} bytes.", nameof(destination));
            }

            // Calculate the 64-bit NTP timestamp.
            ulong unixNanoseconds = (ulong)((DateTimeOffset.UtcNow - UnixEpoch).Ticks * 100L);
            var seconds = unixNanoseconds / 1_000_000_000UL;
            seconds += 0x83AA7E80UL; // NTP epoch offset.
            var fractions = (unixNanoseconds % 1_000_000_000UL) << 32;
            fractions /= 1_000_000_000UL;
            var ntpTimestamp = (seconds << 32) | fractions;

            // The absolute send time is the middle 24 bits of the NTP timestamp.
            uint absSendTime24bit = (uint)((ntpTimestamp >> 14) & 0xFFFFFF);

            // Write the 24-bit value directly into the buffer in Big Endian format.
            destination[0] = (byte)(absSendTime24bit >> 16);
            destination[1] = (byte)(absSendTime24bit >> 8);
            destination[2] = (byte)absSendTime24bit;

            return RTP_HEADER_EXTENSION_SIZE;
        }

        /// <summary>
        /// Parses the 3-byte absolute send time payload from a buffer and sets the
        /// Timestamp property.
        /// </summary>
        public override void Unmarshal(ReadOnlySpan<byte> data)
        {
            if (data.Length != RTP_HEADER_EXTENSION_SIZE)
            {
                throw new ArgumentException($"Invalid AbsSendTime extension payload size, expected {RTP_HEADER_EXTENSION_SIZE} but got {data.Length}.");
            }

            Timestamp = (uint)(data[0] << 16 | data[1] << 8 | data[2]);
        }
    }
}

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
            // The payload size for AbsSendTime is 3 bytes.
            const int RTP_HEADER_EXTENSION_PAYLOAD_SIZE = 3;
            // The total size is the 1-byte extension header plus the 3-byte payload.
            const int TOTAL_EXTENSION_SIZE = 1 + RTP_HEADER_EXTENSION_PAYLOAD_SIZE;

            if (destination.Length < TOTAL_EXTENSION_SIZE)
            {
                throw new ArgumentException($"Destination buffer is too small for AbsSendTime payload, requires {TOTAL_EXTENSION_SIZE} bytes.", nameof(destination));
            }

            // --- The Critical Fix ---
            // First, construct and write the one-byte header containing the ID and the payload length.
            // Replicating the original logic: (id << 4) | (payload_size - 1)
            byte headerByte = (byte)((Id << 4) | (RTP_HEADER_EXTENSION_PAYLOAD_SIZE - 1));
            destination[0] = headerByte;

            // --- NTP Timestamp Calculation ---
            // Calculate the 64-bit NTP timestamp.
            ulong unixNanoseconds = (ulong)((DateTimeOffset.UtcNow - UnixEpoch).Ticks * 100L);
            var seconds = unixNanoseconds / 1_000_000_000UL;
            seconds += 0x83AA7E80UL; // NTP epoch offset (seconds between 1900 and 1970).
            var fractions = (unixNanoseconds % 1_000_000_000UL) << 32;
            fractions /= 1_000_000_000UL;
            var ntpTimestamp = (seconds << 32) | fractions;

            // The absolute send time is the middle 24 bits of the NTP timestamp.
            uint absSendTime24bit = (uint)((ntpTimestamp >> 14) & 0xFFFFFF);

            // Write the 24-bit (3-byte) value into the buffer after the header.
            var payloadDestination = destination.Slice(1);
            payloadDestination[0] = (byte)(absSendTime24bit >> 16);
            payloadDestination[1] = (byte)(absSendTime24bit >> 8);
            payloadDestination[2] = (byte)absSendTime24bit;

            return TOTAL_EXTENSION_SIZE;
        }

        /// <summary>
        /// Parses the 3-byte absolute send time payload from a buffer and sets the
        /// Timestamp property.
        /// </summary>
        public override object Unmarshal(RTPHeader header, ReadOnlySpan<byte> data)
        {
            const int RTP_HEADER_EXTENSION_PAYLOAD_SIZE = 3;
            if (data.Length != RTP_HEADER_EXTENSION_PAYLOAD_SIZE)
            {
                throw new ArgumentException($"Invalid AbsSendTime extension payload size, expected {RTP_HEADER_EXTENSION_PAYLOAD_SIZE} but got {data.Length}.");
            }

            uint absSendTime24bit = (uint)(data[0] << 16 | data[1] << 8 | data[2]);

            ulong unixNanoseconds = (ulong)((DateTimeOffset.UtcNow - UnixEpoch).Ticks * 100L);
            var seconds = unixNanoseconds / 1_000_000_000UL;
            seconds += 0x83AA7E80UL;
            var fractions = (unixNanoseconds % 1_000_000_000UL) << 32;
            fractions /= 1_000_000_000UL;
            var ntpNow = (seconds << 32) | fractions;

            ulong reconstructedNtp = (ntpNow & 0xFFFFFFFFFF000000) | (ulong)absSendTime24bit;

            return new TimestampPair { NtpTimestamp = reconstructedNtp, RtpTimestamp = header.Timestamp };
        }
    }
}

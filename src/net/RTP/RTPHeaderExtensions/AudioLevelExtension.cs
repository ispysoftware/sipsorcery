using System;
using System.Buffers.Binary;
using SIPSorcery.Net;

namespace SIPSorcery.Net
{
    public class AudioLevelExtension : RTPHeaderExtension
    {
        /// <summary>
        /// A class to represent the audio level information.
        /// </summary>
        public class AudioLevel
        {
            public bool Voice;
            public ushort Level; // Level is 0-127, but ushort is used in original.

            public AudioLevel(bool voice, ushort level)
            {
                Voice = voice;
                Level = level;
            }
        }

        public const string RTP_HEADER_EXTENSION_URI = "urn:ietf:params:rtp-hdrext:ssrc-audio-level";

        public static readonly string[] SUPPORTED_URIS =
        {
            RTP_HEADER_EXTENSION_URI
        };
        internal const int RTP_HEADER_EXTENSION_SIZE = 1; // The payload is 1 byte.

        private AudioLevel _audioLevel;

        // Constructor and other methods remain the same...
        public AudioLevelExtension(int id) : base(id, RTP_HEADER_EXTENSION_URI, SUPPORTED_URIS, RTP_HEADER_EXTENSION_SIZE, RTPHeaderExtensionType.OneByte, Net.SDPMediaTypesEnum.audio)
        {
            _audioLevel = new AudioLevel(false, 0);
        }

        public override void Set(Object value)
        {
            if (value is AudioLevel audioLevel)
            {
                _audioLevel = audioLevel;
            }
        }

        // --- START OF REFACTORED METHODS ---

        /// <summary>
        /// Writes the 1-byte audio level payload into the destination buffer.
        /// </summary>
        public override int Marshal(Span<byte> destination)
        {
            if (destination.Length < RTP_HEADER_EXTENSION_SIZE)
            {
                throw new ArgumentException("Destination buffer is too small for the Audio Level payload.", nameof(destination));
            }

            // Combine the voice bit (0x80) and the level (0-127) into a single byte.
            byte payloadByte = (byte)((_audioLevel.Voice ? 0x80 : 0x00) | _audioLevel.Level);
            destination[0] = payloadByte;

            return RTP_HEADER_EXTENSION_SIZE;
        }

        /// <summary>
        /// Parses the 1-byte audio level payload from a buffer and updates the
        /// internal audio level state.
        /// </summary>
        public override void Unmarshal(ReadOnlySpan<byte> data)
        {
            if (data.Length != RTP_HEADER_EXTENSION_SIZE)
            {
                throw new ArgumentException($"Invalid Audio Level extension payload size, expected {RTP_HEADER_EXTENSION_SIZE} but got {data.Length}.");
            }

            byte payloadByte = data[0];

            // The voice flag is the most significant bit (MSB).
            bool voice = (payloadByte & 0x80) == 0x80;

            // The level is the lower 7 bits.
            ushort level = (ushort)(payloadByte & 0x7F);

            // Update the internal state with the parsed values.
            _audioLevel = new AudioLevel(voice, level);
        }
    }
}

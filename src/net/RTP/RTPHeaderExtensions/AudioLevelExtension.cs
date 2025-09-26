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
            public Boolean Voice;
            public ushort Level;

            public AudioLevel()
            {
                Voice = false;
                Level = 0;
            }

            public AudioLevel(ReadOnlySpan<byte> data)
            {
                if (data.IsEmpty || (data.Length != AudioLevelExtension.RTP_HEADER_EXTENSION_SIZE))
                {
                    throw new ArgumentException(nameof(data));
                }

                Voice = (data[0] & 0x80) != 0;
                Level = (ushort)(data[0] & 0x7F);
            }
        };

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
            _audioLevel = new AudioLevel()
            {
                Voice = false,
                Level = 0
            };
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
        /// Marshals the Audio Level header and payload into the destination buffer.
        /// </summary>
        public override int Marshal(Span<byte> destination)
        {
            const int RTP_HEADER_EXTENSION_PAYLOAD_SIZE = 1; // 1-byte payload.
            const int TOTAL_EXTENSION_SIZE = 1 + RTP_HEADER_EXTENSION_PAYLOAD_SIZE;

            if (destination.Length < TOTAL_EXTENSION_SIZE)
            {
                throw new ArgumentException($"Destination buffer is too small for Audio Level payload, requires {TOTAL_EXTENSION_SIZE} bytes.", nameof(destination));
            }

            // Per RFC, for a 1-byte payload, length (L) is 0.
            // The formula is (id << 4) | L. So, (Id << 4) | 0.
            byte headerByte = (byte)(Id << 4);
            destination[0] = headerByte;

            // Construct the payload byte from the current audio level state.
            byte voice = _audioLevel.Voice ? (byte)0x80 : (byte)0;
            destination[1] = (byte)(voice | _audioLevel.Level);

            return TOTAL_EXTENSION_SIZE;
        }

        /// <summary>
        /// Unmarshals the Audio Level data from the provided buffer, updates the
        /// internal state, and returns the parsed AudioLevel object.
        /// </summary>
        /// <returns>An AudioLevel object representing the voice activity and level.</returns>
        public override object Unmarshal(RTPHeader header, ReadOnlySpan<byte> data)
        {
            const int RTP_HEADER_EXTENSION_PAYLOAD_SIZE = 1;
            if (!data.IsEmpty && data.Length == RTP_HEADER_EXTENSION_PAYLOAD_SIZE)
            {
                // Update the internal state with the new audio level from the packet.
                _audioLevel = new AudioLevel(data);
            }

            // Return the current state, whether it was just updated or is the previous value.
            return _audioLevel;
        }
    }
}

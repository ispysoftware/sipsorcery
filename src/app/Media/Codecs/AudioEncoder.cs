//-----------------------------------------------------------------------------
// Filename: AudioEncoder.cs
//
// Description: Audio codecs for the simpler codecs.
//
// Author(s):
// Aaron Clauson (aaron@sipsorcery.com)
//
// History:
// 04 Sep 2020	Aaron Clauson	Created, Dublin, Ireland.
//
// License: 
// BSD 3-Clause "New" or "Revised" License, see included LICENSE.md file.
//-----------------------------------------------------------------------------

using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;
using SIPSorcery.Sys;
using SIPSorceryMedia.Abstractions;

namespace SIPSorcery.Media
{
    public class AudioEncoder : IAudioEncoder, IDisposable
    {
        private const int G722_BIT_RATE = 64000;              // G722 sampling rate is 16KHz with bits per sample of 16.

        // Opus is not handled here. It was, through Concentus (a managed port of libopus), which
        // allocates about 52KB for every 20ms frame it encodes. That dependency has been removed:
        // an application that offers Opus supplies its own encoder (Agent DVR uses FFmpeg's
        // libopus), and asking this class to encode or decode Opus throws like any other format
        // it does not know.

        private static ILogger logger = Log.Logger;

        private bool _disposedValue = false;

        private G722Codec _g722Codec;
        private G722CodecState _g722CodecState;
        private G722Codec _g722Decoder;
        private G722CodecState _g722DecoderState;

        private G729Encoder _g729Encoder;
        private G729Decoder _g729Decoder;

        private List<AudioFormat> _linearFormats = new List<AudioFormat>
        {
            new AudioFormat(AudioCodecsEnum.L16, 117, 16000),
            new AudioFormat(AudioCodecsEnum.L16, 118, 8000),

            // Not recommended due to very, very crude up-sampling in AudioEncoder class. PR's welcome :).
            //new AudioFormat(121, "L16", "L16/48000", null),
        };

        private List<AudioFormat> _supportedFormats = new List<AudioFormat>
        {
            new AudioFormat(SDPWellKnownMediaFormatsEnum.PCMU),
            new AudioFormat(SDPWellKnownMediaFormatsEnum.PCMA),
            new AudioFormat(SDPWellKnownMediaFormatsEnum.G722),
            new AudioFormat(SDPWellKnownMediaFormatsEnum.G729),
        };

        public List<AudioFormat> SupportedFormats
        {
            get => _supportedFormats;
        }

        /// <summary>
        /// Creates a new audio encoder instance.
        /// </summary>
        /// <param name="includeLinearFormats">If set to true the linear audio formats will be added
        /// to the list of supported formats. The reason they are only included if explicitly requested
        /// is they are not very popular for other VoIP systems and therefore needlessly pollute the SDP.</param>
        public AudioEncoder(bool includeLinearFormats = false)
        {
            if (includeLinearFormats)
            {
                _supportedFormats.AddRange(_linearFormats);
            }
        }

        public AudioEncoder(params AudioFormat[] supportedFormats)
        {
            _supportedFormats = supportedFormats.ToList();
        }

        /// <summary>
        /// Encodes PCM audio samples into a destination buffer.
        /// </summary>
        /// <param name="pcm">The input PCM audio samples.</param>
        /// <param name="destination">The buffer to write the encoded audio into.</param>
        /// <param name="format">The audio format and codec to use for encoding.</param>
        /// <returns>The number of bytes written to the destination buffer, or 0 if the buffer was too small.</returns>
        public int EncodeAudio(ReadOnlySpan<short> pcm, Span<byte> destination, AudioFormat format)
        {
            if (format.Codec == AudioCodecsEnum.G722)
            {
                if (_g722Codec == null)
                {
                    _g722Codec = new G722Codec();
                    _g722CodecState = new G722CodecState(G722_BIT_RATE, G722Flags.None);
                }

                int requiredBytes = pcm.Length / 2;
                if (destination.Length < requiredBytes) return 0;

                // Assuming the G722Codec library can write to a Span or array segment.
                // You may need to create a temporary array if it only takes `byte[]`.
                var encodedLength = _g722Codec.Encode(_g722CodecState, destination, pcm);
                return encodedLength;
            }
            else if (format.Codec == AudioCodecsEnum.G729)
            {
                // This codec likely returns a new byte[], so we copy it.
                // This is an exception to the zero-allocation goal due to the library's design.
                if (_g729Encoder == null)
                {
                    _g729Encoder = new G729Encoder();
                }
                ReadOnlySpan<byte> pcmBytes = MemoryMarshal.AsBytes(pcm);
                byte[] encoded = _g729Encoder.Process(pcmBytes.ToArray());

                if (destination.Length < encoded.Length) return 0;

                encoded.AsSpan().CopyTo(destination);
                return encoded.Length;
            }
            else if (format.Codec == AudioCodecsEnum.PCMA)
            {
                if (destination.Length < pcm.Length) return 0;

                for (int i = 0; i < pcm.Length; i++)
                {
                    destination[i] = ALawEncoder.LinearToALawSample(pcm[i]);
                }
                return pcm.Length;
            }
            else if (format.Codec == AudioCodecsEnum.PCMU)
            {
                if (destination.Length < pcm.Length) return 0;

                for (int i = 0; i < pcm.Length; i++)
                {
                    destination[i] = MuLawEncoder.LinearToMuLawSample(pcm[i]);
                }
                return pcm.Length;
            }
            else if (format.Codec == AudioCodecsEnum.L16)
            {
                int requiredBytes = pcm.Length * 2;
                if (destination.Length < requiredBytes) return 0;

                for (int i = 0; i < pcm.Length; i++)
                {
                    BinaryPrimitives.WriteInt16BigEndian(destination.Slice(i * 2), pcm[i]);
                }
                return requiredBytes;
            }
            else if (format.Codec == AudioCodecsEnum.PCM_S16LE)
            {
                var pcmBytes = MemoryMarshal.AsBytes(pcm);
                if (destination.Length < pcmBytes.Length) return 0;

                pcmBytes.CopyTo(destination);
                return pcmBytes.Length;
            }
            else
            {
                throw new ApplicationException($"Audio format {format.Codec} cannot be encoded.");
            }
        }

        /// <summary>
        /// Event handler for receiving RTP packets from the remote party.
        /// </summary>
        /// <param name="encodedSample">Data received from an RTP socket.</param>
        /// <param name="format">The audio format of the encoded packets.</param>
        public short[] DecodeAudio(byte[] encodedSample, AudioFormat format)
        {
            if (format.Codec == AudioCodecsEnum.G722)
            {
                if (_g722Decoder == null)
                {
                    _g722Decoder = new G722Codec();
                    _g722DecoderState = new G722CodecState(G722_BIT_RATE, G722Flags.None);
                }

                short[] decodedPcm = new short[encodedSample.Length * 2];
                int decodedSampleCount = _g722Decoder.Decode(_g722DecoderState, decodedPcm, encodedSample, encodedSample.Length);

                return decodedPcm.Take(decodedSampleCount).ToArray();
            }
            if (format.Codec == AudioCodecsEnum.G729)
            {
                if (_g729Decoder == null)
                {
                    _g729Decoder = new G729Decoder();
                }

                byte[] decodedBytes = _g729Decoder.Process(encodedSample);
                short[] decodedPcm = new short[decodedBytes.Length / sizeof(short)];
                Buffer.BlockCopy(decodedBytes, 0, decodedPcm, 0, decodedBytes.Length);
                return decodedPcm;
            }
            else if (format.Codec == AudioCodecsEnum.PCMA)
            {
                return encodedSample.Select(x => ALawDecoder.ALawToLinearSample(x)).ToArray();
            }
            else if (format.Codec == AudioCodecsEnum.PCMU)
            {
                return encodedSample.Select(x => MuLawDecoder.MuLawToLinearSample(x)).ToArray();
            }
            else if (format.Codec == AudioCodecsEnum.L16)
            {
                // Samples are on the wire as big endian.
                return encodedSample.Where((x, i) => i % 2 == 0).Select((y, i) => (short)(encodedSample[i * 2] << 8 | encodedSample[i * 2 + 1])).ToArray();
            }
            else if (format.Codec == AudioCodecsEnum.PCM_S16LE)
            {
                // Samples are on the wire as little endian (well unlikely to be on the wire in this case but when they 
                // arrive from somewhere like the SkypeBot SDK they will be in little endian format).
                return encodedSample.Where((x, i) => i % 2 == 0).Select((y, i) => (short)(encodedSample[i * 2 + 1] << 8 | encodedSample[i * 2])).ToArray();
            }
            else
            {
                throw new ApplicationException($"Audio format {format.Codec} cannot be decoded.");
            }
        }

        [Obsolete("No longer used. Use SIPSorcery.Media.PcmResampler.Resample instead.")]
        public short[] Resample(short[] pcm, int inRate, int outRate)
        {
            return PcmResampler.Resample(pcm, inRate, outRate);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!_disposedValue)
            {
                if (disposing)
                {
                    (_g729Encoder as IDisposable)?.Dispose();
                    (_g729Decoder as IDisposable)?.Dispose();
                }

                _disposedValue = true;
            }
        }

        public void Dispose()
        {
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }
    }
}

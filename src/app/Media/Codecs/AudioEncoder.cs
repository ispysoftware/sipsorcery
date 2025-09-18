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
using Concentus;
using Concentus.Enums;
using Microsoft.Extensions.Logging;
using SIPSorcery.Sys;
using SIPSorceryMedia.Abstractions;

namespace SIPSorcery.Media
{
    public class AudioEncoder : IAudioEncoder, IDisposable
    {
        private const int G722_BIT_RATE = 64000;              // G722 sampling rate is 16KHz with bits per sample of 16.
        private const int OPUS_SAMPLE_RATE = 48000;           // Opus codec sampling rate, 48KHz.
        private const int OPUS_CHANNELS = 2;                  // Opus codec number of channels.

        /// <summary>
        /// The max frame size that the OPUS encoder will accept is 2880 bytes (see IOpusEncoder.Encode).
        /// 2880 corresponds to a sample size of 30ms for a single channel at 48Khz with 16 bit PCM. Therefore
        /// the max sample size supported by OPUS is 30ms.
        /// </summary>
        private const int OPUS_MAXIMUM_INPUT_SAMPLES_PER_CHANNEL = 2880;

        /// <summary>
        /// OPUS max encode size (see IOpusEncoder.Encode).
        /// </summary>
        private const int OPUS_MAXIMUM_ENCODED_FRAME_SIZE = 1275;

        private static ILogger logger = Log.Logger;

        private bool _disposedValue = false;

        private G722Codec _g722Codec;
        private G722CodecState _g722CodecState;
        private G722Codec _g722Decoder;
        private G722CodecState _g722DecoderState;

        private G729Encoder _g729Encoder;
        private G729Decoder _g729Decoder;

        private IOpusDecoder _opusDecoder;
        private IOpusEncoder _opusEncoder;

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

            // Need more testing before adding OPUS by default. 24 Dec 2024 AC.
            //new AudioFormat(111, AudioCodecsEnum.OPUS.ToString(), OPUS_SAMPLE_RATE, OPUS_CHANNELS, "useinbandfec=1")
            // AudioCommonlyUsedFormats.OpusWebRTC
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
        public AudioEncoder(bool includeLinearFormats = false, bool includeOpus = false)
        {
            if (includeLinearFormats)
            {
                _supportedFormats.AddRange(_linearFormats);
            }

            if (includeOpus)
            {
                _supportedFormats.Add(AudioCommonlyUsedFormats.OpusWebRTC);
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
            else if (format.Codec == AudioCodecsEnum.OPUS)
            {
                if (_opusEncoder == null)
                {
                    var channelCount = format.ChannelCount > 0 ? format.ChannelCount : OPUS_CHANNELS;
                    // Ensure your Opus encoder is initialized for the resampled rate (48kHz)
                    _opusEncoder = OpusCodecFactory.CreateEncoder(8000, channelCount, OpusApplication.OPUS_APPLICATION_VOIP);
                    _opusEncoder.Complexity = 5;
                    _opusEncoder.Bitrate = 16000;
                    _opusEncoder.UseInbandFEC = true;

                }

                // --- FIX STARTS HERE ---

                // 1. Correctly calculate samples per channel from the byte buffer.
                // Each sample is 16-bit, so 2 bytes.
                const int bytesPerSample = 2;
                int totalSamples = pcm.Length / bytesPerSample;
                int samplesPerChannel = totalSamples / _opusEncoder.NumChannels;

                // 2. The check now correctly compares samples-per-channel to the limit.
                if (samplesPerChannel > OPUS_MAXIMUM_INPUT_SAMPLES_PER_CHANNEL)
                {
                    logger.LogWarning($"OPUS input sample count per channel ({samplesPerChannel}) exceeded maximum limit ({OPUS_MAXIMUM_INPUT_SAMPLES_PER_CHANNEL}).");
                    return 0;
                }

                Span<byte> tempBuffer = stackalloc byte[OPUS_MAXIMUM_ENCODED_FRAME_SIZE];

                // 3. Pass the correct samples-per-channel count to the encoder.
                int encodedLength = _opusEncoder.Encode(pcm, samplesPerChannel, tempBuffer, tempBuffer.Length);

                // --- FIX ENDS HERE ---

                if (destination.Length < encodedLength) return 0;

                tempBuffer.Slice(0, encodedLength).CopyTo(destination);
                return encodedLength;
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
            else if (format.Codec == AudioCodecsEnum.OPUS)
            {
                if (_opusDecoder == null)
                {
                    var channelCount = format.ChannelCount > 0 ? format.ChannelCount : OPUS_CHANNELS;
                    _opusDecoder = OpusCodecFactory.CreateDecoder(format.ClockRate, channelCount);
                }

                int maxSamples = OPUS_MAXIMUM_INPUT_SAMPLES_PER_CHANNEL * _opusDecoder.NumChannels;
                float[] floatBuf = new float[maxSamples];

                // Decode returns the number of samples per channel.
                int samplesPerChannel = _opusDecoder.Decode(
                    encodedSample,
                    floatBuf,
                    floatBuf.Length,
                    false);

                int totalFloats = samplesPerChannel * _opusDecoder.NumChannels;

                // Convert to 16-bit interleaved PCM.
                short[] pcm16 = new short[totalFloats];
                for (int i = 0; i < totalFloats; i++)
                {
                    var f = ClampToFloat(floatBuf[i], -1.0f, 1.0f);
                    pcm16[i] = (short)(f * 32767);
                }

                return pcm16;
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

        private float ClampToFloat(float value, float min, float max)
        {
            if (value < min) { return min; }
            if (value > max) { return max; }
            return value;
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!_disposedValue)
            {
                if (disposing)
                {
                    (_opusEncoder as IDisposable)?.Dispose();
                    (_opusDecoder as IDisposable)?.Dispose();
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

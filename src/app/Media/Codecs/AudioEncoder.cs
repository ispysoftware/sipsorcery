﻿//-----------------------------------------------------------------------------
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

using Concentus;
using System;
using System.Collections.Generic;
using System.Linq;
using SIPSorceryMedia.Abstractions;
using Concentus.Enums;

namespace SIPSorcery.Media
{
    public class AudioEncoder : IAudioEncoder
    {
        private const int G722_BIT_RATE = 64000;              // G722 sampling rate is 16KHz with bits per sample of 16.
        private const int OPUS_SAMPLE_RATE = 48000;           // Opus codec sampling rate, 48KHz.
        private const int OPUS_CHANNELS = 1;                  // Opus codec number of channels.
        private const int OPUS_MAXIMUM_DECODE_BUFFER_LENGTH = 5760;

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

            // Need more testing befoer adding OPUS by default. 24 Dec 2024 AC.
            //new AudioFormat(111, "OPUS", OPUS_SAMPLE_RATE, OPUS_CHANNELS, "useinbandfec=1")
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
        /// is they are not very popular for other VoIP systems and thereofre needlessly pollute the SDP.</param>
        public AudioEncoder(bool includeLinearFormats = false, bool includeOpus = false)
        {
            if (includeLinearFormats)
            {
                _supportedFormats.AddRange(_linearFormats);
            }

            if(includeOpus)
            {
                _supportedFormats.Add(new AudioFormat(111, "OPUS", OPUS_SAMPLE_RATE, OPUS_CHANNELS, "useinbandfec=1"));
            }
        }

        public byte[] EncodeAudio(short[] pcm, AudioFormat format)
        {
            if (format.Codec == AudioCodecsEnum.G722)
            {
                if (_g722Codec == null)
                {
                    _g722Codec = new G722Codec();
                    _g722CodecState = new G722CodecState(G722_BIT_RATE, G722Flags.None);
                }

                int outputBufferSize = pcm.Length / 2;
                byte[] encodedSample = new byte[outputBufferSize];
                int res = _g722Codec.Encode(_g722CodecState, encodedSample, pcm, pcm.Length);

                return encodedSample;
            }
            else if (format.Codec == AudioCodecsEnum.G729)
            {
                if (_g729Encoder == null)
                {
                    _g729Encoder = new G729Encoder();
                }

                byte[] pcmBytes = new byte[pcm.Length * sizeof(short)];
                Buffer.BlockCopy(pcm, 0, pcmBytes, 0, pcmBytes.Length);
                return _g729Encoder.Process(pcmBytes);
            }
            else if (format.Codec == AudioCodecsEnum.PCMA)
            {
                return pcm.Select(x => ALawEncoder.LinearToALawSample(x)).ToArray();
            }
            else if (format.Codec == AudioCodecsEnum.PCMU)
            {
                return pcm.Select(x => MuLawEncoder.LinearToMuLawSample(x)).ToArray();
            }
            else if (format.Codec == AudioCodecsEnum.L16)
            {
                // When netstandard2.1 can be used.
                //return MemoryMarshal.Cast<short, byte>(pcm)

                // Put on the wire in network byte order (big endian).
                return pcm.SelectMany(x => new byte[] { (byte)(x >> 8), (byte)(x) }).ToArray();
            }
            else if (format.Codec == AudioCodecsEnum.PCM_S16LE)
            {
                // Put on the wire as little endian.
                return pcm.SelectMany(x => new byte[] { (byte)(x), (byte)(x >> 8) }).ToArray();
            }
            else if (format.Codec == AudioCodecsEnum.OPUS)
            {
                if (_opusEncoder == null)
                {
                    _opusEncoder = OpusCodecFactory.CreateEncoder(OPUS_SAMPLE_RATE, OPUS_CHANNELS, OpusApplication.OPUS_APPLICATION_VOIP);
                }

                // Opus expects PCM data in float format [-1.0, 1.0].
                float[] pcmFloat = new float[pcm.Length];
                for (int i = 0; i < pcm.Length; i++)
                {
                    pcmFloat[i] = pcm[i] / 32768f; // Convert to float range [-1.0, 1.0]
                }

                byte[] encodedSample = new byte[pcm.Length];
                int encodedLength = _opusEncoder.Encode(pcmFloat, pcmFloat.Length / OPUS_CHANNELS, encodedSample, encodedSample.Length);
                return encodedSample.Take(encodedLength).ToArray();
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
                    _opusDecoder = OpusCodecFactory.CreateDecoder(OPUS_SAMPLE_RATE, OPUS_CHANNELS);
                }

                float[] decodedPcmFloat = new float[OPUS_MAXIMUM_DECODE_BUFFER_LENGTH];
                int decodedLength = _opusDecoder.Decode(encodedSample, decodedPcmFloat, decodedPcmFloat.Length, false);

                // Convert float PCM to short PCM
                short[] decodedPcm = new short[decodedLength];
                for (int i = 0; i < decodedLength; i++)
                {
                    // Clamp the value to the valid range of -32768 to 32767
                    decodedPcm[i] = ClampToShort(decodedPcmFloat[i] * 32767);
                }

                return decodedPcm;
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

        private short ClampToShort(float value)
        {
            if (value > short.MaxValue)
            {
                return short.MaxValue;
            }
            if (value < short.MinValue)
            {
                return short.MinValue;
            }
            return (short)value;
        }
    }
}

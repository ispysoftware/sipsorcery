//-----------------------------------------------------------------------------
// Filename: AudioStream.cs
//
// Description: Define an Audio media stream (which inherits MediaStream) to focus an Audio specific treatment
// The goal is to simplify RTPSession class
//
// Author(s):
// Christophe Irles
//
// History:
// 05 Apr 2022	Christophe Irles        Created (based on existing code from previous RTPSession class)
//
// License: 
// BSD 3-Clause "New" or "Revised" License, see included LICENSE.md file.
//-----------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SIPSorcery.Sys;
using SIPSorceryMedia.Abstractions;
using SIPSorcery.net.RTP;

namespace SIPSorcery.Net
{
    public class AudioStream : MediaStream
    {
        private const uint DEFAULT_AUDIO_SAMPLE_DURATION_MILLISECONDS = 20;

        protected static ILogger logger = Log.Logger;
        protected bool rtpEventInProgress = false;

        private bool sendingFormatFound = false;

        private bool _rtpPreviousTimestampSet = false;

        /// <summary>
        /// The RTP timestamp for the previously received RTP packet. Used to calculate the
        /// duration of the RTP packet in RTP timestamp units.
        /// </summary>
        private uint _rtpPreviousTimestamp = 0;

        /// <summary>
        /// The audio format negotiated for the audio stream by the SDP offer/answer exchange.
        /// </summary>
        public SDPAudioVideoMediaFormat NegotiatedFormat { get; private set; }

        /// <summary>
        /// Gets fired when the remote SDP is received and the set of common audio formats is set.
        /// </summary>
        public event Action<int, List<AudioFormat>> OnAudioFormatsNegotiatedByIndex;

        public event Action<EncodedAudioFrame> OnAudioFrameReceived;

        /// <summary>
        /// Indicates whether this session is using audio.
        /// </summary>
        public bool HasAudio
        {
            get
            {
                return (LocalTrack != null && LocalTrack.StreamStatus != MediaStreamStatusEnum.Inactive)
                  || (RemoteTrack != null && RemoteTrack.StreamStatus != MediaStreamStatusEnum.Inactive);
            }
        }

        public AudioStream(RtpSessionConfig config, int index) : base(config, index)
        {
            MediaType = SDPMediaTypesEnum.audio;
        }

        /// <summary>
        /// Sends an audio sample to the remote peer.
        /// </summary>
        /// <param name="durationRtpUnits">The duration in RTP timestamp units of the audio sample. This
        /// value is added to the previous RTP timestamp when building the RTP header.</param>
        /// <param name="sample">The audio sample to set as the RTP packet payload.</param>
        public async Task SendAudioAsync(uint durationRtpUnits, ReadOnlyMemory<byte> sample)
        {
            if (!sendingFormatFound)
            {
                NegotiatedFormat = GetSendingFormat();
                sendingFormatFound = true;
            }
            await SendAudioFrameAsync(durationRtpUnits, NegotiatedFormat.ID, sample);
        }

        /// <summary>
        /// Sends an audio sample to the remote peer.
        /// </summary>
        /// <param name="durationRtpUnits">The duration in RTP timestamp units of the audio sample. This
        /// value is added to the previous RTP timestamp when building the RTP header.</param>
        /// <param name="sample">The audio sample to set as the RTP packet payload.</param>
        public async Task SendAudio(uint durationRtpUnits, byte[] sample)
        {
            await SendAudioAsync(durationRtpUnits, new ArraySegment<byte>(sample));
        }

        /// <summary>
        /// Sends an audio packet to the remote party.
        /// </summary>
        /// <param name="duration">The duration of the audio payload in timestamp units. This value
        /// gets added onto the timestamp being set in the RTP header.</param>
        /// <param name="payloadTypeID">The payload ID to set in the RTP header.</param>
        /// <param name="bufferSegment">The audio payload to send.</param>
        public async Task SendAudioFrameAsync(uint duration, int payloadTypeID, ReadOnlyMemory<byte> buffer)
        {
            if (CheckIfCanSendRtpRaw())
            {
                if (rtpEventInProgress)
                {
                    //logger.LogWarning(nameof(SendAudioFrame) + " an RTPEvent is in progress.");
                    return;
                }

                try
                {
                    // Comments about splitting audio frames remain relevant...

                    int maxPayload = RTPSession.RTP_MAX_PAYLOAD;
                    // Use .Length instead of .Count
                    int totalPackets = (buffer.Length + maxPayload - 1) / maxPayload;

                    uint totalIncrement = 0;

                    for (int index = 0; index < totalPackets; index++)
                    {
                        int offset = index * maxPayload;
                        int payloadLength = Math.Min(maxPayload, buffer.Length - offset);

                        double fraction = (double)payloadLength / buffer.Length;
                        uint packetDuration = (uint)Math.Round(fraction * duration);

                        int markerBit = 0;

                        // The slicing logic is now much simpler and cleaner, no #if needed.
                        ReadOnlyMemory<byte> packetPayload = buffer.Slice(offset, payloadLength);

                        // Assuming SendRtpRaw is also updated to take a ReadOnlySpan<byte>
                        await SendRtpRawAsync(packetPayload, LocalTrack.Timestamp, markerBit, payloadTypeID, true);

                        LocalTrack.Timestamp += packetDuration;
                        totalIncrement += packetDuration;
                    }

                    if (totalIncrement != duration)
                    {
                        LocalTrack.Timestamp += (duration - totalIncrement);
                    }
                }
                catch (SocketException sockExcp)
                {
                    logger.LogError(sockExcp, "SocketException SendAudioFrame. {ErrorMessage}", sockExcp.Message);
                }
            }
        }

        /// <summary>
        /// Sends an audio packet to the remote party.
        /// </summary>
        /// <param name="duration">The duration of the audio payload in timestamp units. This value
        /// gets added onto the timestamp being set in the RTP header.</param>
        /// <param name="payloadTypeID">The payload ID to set in the RTP header.</param>
        /// <param name="buffer">The audio payload to send.</param>
        public async Task SendAudioFrameAsync(uint duration, int payloadTypeID, byte[] buffer)
        {
            await SendAudioFrameAsync(duration, payloadTypeID, new ArraySegment<byte>(buffer));
        }

        /// <summary>
        /// Sends an RTP event for a DTMF tone as per RFC2833. Sending the event requires multiple packets to be sent.
        /// This method will hold onto the socket until all the packets required for the event have been sent. The send
        /// can be cancelled using the cancellation token.
        /// </summary>
        /// <param name="rtpEvent">The RTP event to send.</param>
        /// <param name="cancellationToken">CancellationToken to allow the operation to be cancelled prematurely.</param>
        /// <param name="clockRate">To send an RTP event the clock rate of the underlying stream needs to be known.</param>
        /// <param name="samplePeriod">The sample period in milliseconds being used for the media stream that the event 
        /// is being inserted into. Should be set to 50ms if main media stream is dynamic or sample period is unknown.</param>
        public async Task SendDtmfEvent(RTPEvent rtpEvent, CancellationToken cancellationToken, int clockRate = RTPSession.DEFAULT_AUDIO_CLOCK_RATE, int samplePeriod = RTPSession.RTP_EVENT_DEFAULT_SAMPLE_PERIOD_MS)
        {
            if (CheckIfCanSendRtpRaw())
            {
                if (rtpEventInProgress)
                {
                    logger.LogWarning(nameof(SendDtmfEvent) + " an RTPEvent is already in progress.");
                    return;
                }

                try
                {
                    rtpEventInProgress = true;
                    // The RTP timestamp step corresponding to the sampling period. This can change depending
                    // on the codec being used. For example using PCMU with a sampling frequency of 8000Hz and a sample period of 50ms
                    // the timestamp step is 400 (8000 / (1000 / 50)). For a sample period of 20ms it's 160 (8000 / (1000 / 20)).
                    ushort rtpTimestampStep = (ushort)(clockRate * samplePeriod / 1000);

                    // If only the minimum number of packets are being sent then they are both the start and end of the event.
                    rtpEvent.EndOfEvent = (rtpEvent.TotalDuration <= rtpTimestampStep);
                    // The DTMF tone is generally multiple RTP events. Each event has a duration of the RTP timestamp step.
                    rtpEvent.Duration = rtpTimestampStep;

                    // Send the start of event packets.
                    for (int i = 0; i < RTPEvent.DUPLICATE_COUNT && !cancellationToken.IsCancellationRequested; i++)
                    {
                        byte[] buffer = rtpEvent.GetEventPayload();

                        int markerBit = (i == 0) ? 1 : 0;  // Set marker bit for the first packet in the event.

                        await SendRtpRawAsync(buffer, LocalTrack.Timestamp, markerBit, rtpEvent.PayloadTypeID, true);
                    }

                    await Task.Delay(samplePeriod, cancellationToken).ConfigureAwait(false);

                    if (!rtpEvent.EndOfEvent)
                    {
                        // Send the progressive event packets 
                        while ((rtpEvent.Duration + rtpTimestampStep) < rtpEvent.TotalDuration && !cancellationToken.IsCancellationRequested)
                        {
                            rtpEvent.Duration += rtpTimestampStep;
                            byte[] buffer = rtpEvent.GetEventPayload();

                            await SendRtpRawAsync(buffer, LocalTrack.Timestamp, 0, rtpEvent.PayloadTypeID, true);

                            await Task.Delay(samplePeriod, cancellationToken).ConfigureAwait(false);
                        }

                        // Send the end of event packets.
                        for (int j = 0; j < RTPEvent.DUPLICATE_COUNT && !cancellationToken.IsCancellationRequested; j++)
                        {
                            rtpEvent.EndOfEvent = true;
                            rtpEvent.Duration = rtpEvent.TotalDuration;
                            byte[] buffer = rtpEvent.GetEventPayload();

                            await SendRtpRawAsync(buffer, LocalTrack.Timestamp, 0, rtpEvent.PayloadTypeID, true);
                        }
                    }
                    LocalTrack.Timestamp += rtpEvent.TotalDuration;
                }
                catch (SocketException sockExcp)
                {
                    logger.LogError(sockExcp, "SocketException SendDtmfEvent. {ErrorMessage}", sockExcp.Message);
                }
                catch (TaskCanceledException)
                {
                    logger.LogWarning("SendDtmfEvent was cancelled by caller.");
                }
                finally
                {
                    rtpEventInProgress = false;
                }
            }
        }

        /// <summary>
        /// Sends a DTMF tone as an RTP event to the remote party.
        /// </summary>
        /// <param name="key">The DTMF tone to send.</param>
        /// <param name="ct">RTP events can span multiple RTP packets. This token can
        /// be used to cancel the send.</param>
        public virtual Task SendDtmf(byte key, CancellationToken ct)
        {
            var dtmfEvent = new RTPEvent(key, false, RTPEvent.DEFAULT_VOLUME, RTPSession.DTMF_EVENT_DURATION, NegotiatedRtpEventPayloadID);
            return SendDtmfEvent(dtmfEvent, ct);
        }

        public void CheckAudioFormatsNegotiation()
        {
            if (LocalTrack != null &&
                        LocalTrack.Capabilities.Where(x => x.Name().ToLower() != SDP.TELEPHONE_EVENT_ATTRIBUTE).Count() > 0)
            {
                OnAudioFormatsNegotiatedByIndex?.Invoke(
                            Index,
                            LocalTrack.Capabilities
                            .Where(x => x.Name().ToLower() != SDP.TELEPHONE_EVENT_ATTRIBUTE)
                            .Select(x => x.ToAudioFormat()).ToList());
            }
        }

        protected override void ProcessRtpPacket(IPEndPoint remoteEndPoint, RTPPacket rtpPacket, SDPAudioVideoMediaFormat format)
        {
            var audioFormat = format.ToAudioFormat();

            if (!audioFormat.IsEmpty())
            {
                uint durationMilliseconds = _rtpPreviousTimestampSet switch
                {
                    true => RtpTimestampExtensions.ToDurationMillisecondsInt(rtpPacket.Header.GetTimestampDelta(_rtpPreviousTimestamp), audioFormat.RtpClockRate),
                    false => DEFAULT_AUDIO_SAMPLE_DURATION_MILLISECONDS
                };

                OnAudioFrameReceived?.Invoke(new EncodedAudioFrame(Index, format.ToAudioFormat(), durationMilliseconds, rtpPacket.Payload));
            }

            RaiseOnRtpPacketReceivedByIndex(remoteEndPoint, rtpPacket);

            _rtpPreviousTimestamp = rtpPacket.Header.Timestamp;

            if (!_rtpPreviousTimestampSet)
            {
                _rtpPreviousTimestampSet = true;
            }
        }
    }
}

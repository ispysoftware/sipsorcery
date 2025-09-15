//-----------------------------------------------------------------------------
// Filename: VideoStream.cs
//
// Description: Define a Video media stream (which inherits MediaStream) to focus an Video specific treatment
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
using Microsoft.Extensions.Logging;
using SIPSorcery.net.RTP;
using SIPSorcery.net.RTP.Packetisation;
using SIPSorcery.Sys;
using SIPSorceryMedia.Abstractions;

namespace SIPSorcery.Net
{
    public class VideoStream : MediaStream
    {
        protected static ILogger logger = Log.Logger;
        protected RtpVideoFramer RtpVideoFramer;

        private VideoFormat sendingFormat;
        private bool sendingFormatFound = false;

        /// <summary>
        /// Gets fired when the remote SDP is received and the set of common video formats is set.
        /// </summary>
        public event Action<int, List<VideoFormat>> OnVideoFormatsNegotiatedByIndex;

        /// <summary>
        /// Gets fired when a full video frame is reconstructed from one or more RTP packets
        /// received from the remote party.
        /// </summary>
        /// <remarks>
        ///  - Received from end point,
        ///  - The frame timestamp,
        ///  - The encoded video frame payload.
        ///  - The video format of the encoded frame.
        /// </remarks>
        public event Action<int, IPEndPoint, uint, byte[], VideoFormat> OnVideoFrameReceivedByIndex;

        /// <summary>
        /// Indicates whether this session is using video.
        /// </summary>
        public bool HasVideo
        {
            get
            {
                return (LocalTrack != null && LocalTrack.StreamStatus != MediaStreamStatusEnum.Inactive)
                  || (RemoteTrack != null && RemoteTrack.StreamStatus != MediaStreamStatusEnum.Inactive);
            }
        }

        /// <summary>
        /// Indicates the maximum frame size that can be reconstructed from RTP packets during the depacketisation
        /// process.
        /// </summary>
        public int MaxReconstructedVideoFrameSize { get; set; } = 1048576;

        public VideoStream(RtpSessionConfig config, int index) : base(config, index)
        {
            MediaType = SDPMediaTypesEnum.video;
            NegotiatedRtpEventPayloadID = 0;
        }

        /// <summary>
        /// Helper method to send a low quality JPEG image over RTP. This method supports a very abbreviated version of RFC 2435 "RTP Payload Format for JPEG-compressed Video".
        /// It's intended as a quick convenient way to send something like a test pattern image over an RTSP connection. More than likely it won't be suitable when a high
        /// quality image is required since the header used in this method does not support quantization tables.
        /// </summary>
        /// <param name="duration">The duration in timestamp units of the payload (e.g. 3000 for 30fps).</param>
        /// <param name="jpegBytes">The raw encoded bytes of the JPEG image to transmit.</param>
        /// <param name="jpegQuality">The encoder quality of the JPEG image.</param>
        /// <param name="jpegWidth">The width of the JPEG image.</param>
        /// <param name="jpegHeight">The height of the JPEG image.</param>
        public void SendJpegFrame(uint duration, int payloadTypeID, byte[] jpegBytes, int jpegQuality, int jpegWidth, int jpegHeight)
        {
            if (CheckIfCanSendRtpRaw())
            {
                try
                {
                    for (int index = 0; index * RTPSession.RTP_MAX_PAYLOAD < jpegBytes.Length; index++)
                    {
                        uint offset = Convert.ToUInt32(index * RTPSession.RTP_MAX_PAYLOAD);
                        int payloadLength = ((index + 1) * RTPSession.RTP_MAX_PAYLOAD < jpegBytes.Length) ? RTPSession.RTP_MAX_PAYLOAD : jpegBytes.Length - index * RTPSession.RTP_MAX_PAYLOAD;
                        byte[] jpegHeader = RtpVideoFramer.CreateLowQualityRtpJpegHeader(offset, jpegQuality, jpegWidth, jpegHeight);

                        List<byte> packetPayload = new List<byte>();
                        packetPayload.AddRange(jpegHeader);
                        packetPayload.AddRange(jpegBytes.Skip(index * RTPSession.RTP_MAX_PAYLOAD).Take(payloadLength));

                        int markerBit = ((index + 1) * RTPSession.RTP_MAX_PAYLOAD < jpegBytes.Length) ? 0 : 1;

                        SendRtpRaw(packetPayload.ToArray(), LocalTrack.Timestamp, markerBit, payloadTypeID, true);
                    }

                    LocalTrack.Timestamp += duration;
                }
                catch (SocketException sockExcp)
                {
                    logger.LogError(sockExcp, "SocketException SendJpegFrame. {ErrorMessage}", sockExcp.Message);
                }
            }
        }

        /// <summary>
        /// Sends an H.264 frame, represented by an Access Unit, to the remote party.
        /// </summary>
        public void SendH264Frame(uint duration, int payloadTypeID, ReadOnlyMemory<byte> accessUnit)
        {
            if (CheckIfCanSendRtpRaw())
            {
                // This assumes H264Packetiser.ParseNals is updated to accept a ReadOnlySpan
                // and yield a struct/tuple containing a ReadOnlyMemory<byte> for the NAL.
                foreach (var nalInfo in H264Packetiser.ParseNals(accessUnit))
                {
                    // .Span is used to get the ReadOnlySpan<byte> from the ReadOnlyMemory<byte>
                    SendH26XNal(duration, payloadTypeID, nalInfo.NAL.Span, nalInfo.IsLast);
                }
            }
        }

        /// <summary>
        /// Sends a single H.264 or H.265 NAL to the remote party.
        /// </summary>
        private void SendH26XNal(uint duration, int payloadTypeID, ReadOnlySpan<byte> nal, bool isLastNal, bool is265 = false)
        {
            if (nal.IsEmpty)
            {
                return;
            }

            var naluHeaderSize = is265 ? 2 : 1;

            // A NAL fits into a single RTP packet (formerly STAP-A, now just a single NAL unit packet).
            if (nal.Length <= RTPSession.RTP_MAX_PAYLOAD)
            {
                // Send the NAL as a single NAL unit packet.
                // .ToArray() creates the necessary byte[] for the payload.
                byte[] payload = nal.ToArray();
                int markerBit = isLastNal ? 1 : 0;

                SetRtpHeaderExtensionValue(TransportWideCCExtension.RTP_HEADER_EXTENSION_URI, null);
                SendRtpRaw(payload, LocalTrack.Timestamp, markerBit, payloadTypeID, true);
            }
            // The NAL must be fragmented across multiple RTP packets.
            else
            {
                // Get the original NALU header. For H.264, it's the first byte. For H.265, the first two.
                ReadOnlySpan<byte> naluHeader = nal.Slice(0, naluHeaderSize);
                // The rest of the NAL is the payload to be fragmented. This slice is allocation-free.
                var nalPayloadToFragment = nal.Slice(naluHeaderSize);

                bool isFirstPacket = true;

                while (!nalPayloadToFragment.IsEmpty)
                {
                    int payloadLength = Math.Min(nalPayloadToFragment.Length, RTPSession.RTP_MAX_PAYLOAD);
                    var currentSlice = nalPayloadToFragment.Slice(0, payloadLength);
                    nalPayloadToFragment = nalPayloadToFragment.Slice(payloadLength);

                    bool isFinalPacket = nalPayloadToFragment.IsEmpty;
                    int markerBit = (isLastNal && isFinalPacket) ? 1 : 0;

                    // Generate the FU (Fragmentation Unit) header.
                    byte[] rtpHdr = is265 ?
                        H265Packetiser.GetH265RtpHeader(naluHeader.ToArray(), isFirstPacket, isFinalPacket) :
                        H264Packetiser.GetH264RtpHeader(naluHeader[0], isFirstPacket, isFinalPacket);

                    // Create the final payload: [FU Header][NAL Payload Slice]
                    byte[] payload = new byte[payloadLength + rtpHdr.Length];
                    rtpHdr.CopyTo(payload, 0);
                    currentSlice.CopyTo(payload.AsSpan(rtpHdr.Length));

                    isFirstPacket = false;

                    SetRtpHeaderExtensionValue(TransportWideCCExtension.RTP_HEADER_EXTENSION_URI, null);
                    SendRtpRaw(payload, LocalTrack.Timestamp, markerBit, payloadTypeID, true);
                }
            }

            if (isLastNal)
            {
                LocalTrack.Timestamp += duration;
            }
        }

        public void SendH265Frame(uint durationRtpUnits, int payloadID, byte[] sample)
        {
            if (CheckIfCanSendRtpRaw())
            {
                var nals = H265Packetiser.ParseNals(sample);

                // aggregation is only on 2 or more small nals
                if (nals.Where(x => x.NAL.Length < RTPSession.RTP_MAX_PAYLOAD).Count() > 1)
                {
                    //logger.LogTrace("(ou) Trying aggregating {nals} nals", nals.Count());
                    nals = H265Packetiser.CreateAggregated(nals, RTPSession.RTP_MAX_PAYLOAD);
                }

                //var i = 1;
                foreach (var nal in nals)
                {
                    //logger.LogTrace("(out) SEND {bits}({of}/{all})", nal.NAL.Length, i++, nals.Count());
                    SendH26XNal(durationRtpUnits, payloadID, nal.NAL, nal.IsLast, true);
                }
            }
        }

        /// <summary>
        /// Sends a VP8 frame as one or more RTP packets using a memory-efficient span.
        /// </summary>
        /// <param name="duration">The duration in timestamp units of the payload, based on a 90Khz clock.</param>
        /// <param name="payloadTypeID">The payload ID to place in the RTP header.</param>
        /// <param name="buffer">The VP8 encoded payload as a ReadOnlySpan.</param>
        public void SendVp8Frame(uint duration, int payloadTypeID, ReadOnlySpan<byte> buffer)
        {
            if (!CheckIfCanSendRtpRaw())
            {
                return;
            }

            try
            {
                var remainingBuffer = buffer;
                bool isFirstPacket = true;

                while (!remainingBuffer.IsEmpty)
                {
                    // Determine the size of the current packet's payload
                    int payloadLength = Math.Min(remainingBuffer.Length, RTPSession.RTP_MAX_PAYLOAD);
                    var currentSlice = remainingBuffer.Slice(0, payloadLength);

                    // Advance the view of the buffer for the next iteration
                    remainingBuffer = remainingBuffer.Slice(payloadLength);

                    // The VP8 payload descriptor is 1 byte. The 'S' bit (0x10) is set for the first packet.
                    byte vp8HeaderByte = isFirstPacket ? (byte)0x10 : (byte)0x00;
                    isFirstPacket = false;

                    // Create the final RTP payload: [VP8 Header (1 byte)][VP8 Frame Slice]
                    // Note: This still requires an allocation. For ultra-low latency, consider using ArrayPool<byte>.
                    byte[] payload = new byte[payloadLength + 1];
                    payload[0] = vp8HeaderByte;
                    currentSlice.CopyTo(payload.AsSpan(1));

                    // Set the marker bit only for the very last packet of the frame.
                    int markerBit = remainingBuffer.IsEmpty ? 1 : 0;

                    SetRtpHeaderExtensionValue(TransportWideCCExtension.RTP_HEADER_EXTENSION_URI, null);
                    SendRtpRaw(payload, LocalTrack.Timestamp, markerBit, payloadTypeID, true);
                }

                LocalTrack.Timestamp += duration;
            }
            catch (SocketException sockExcp)
            {
                logger.LogError(sockExcp, "SocketException in SendVp8Frame with Span.");
            }
        }

        /// <summary>
        /// Sends a JPEG frame as one or more RTP packets.
        /// </summary>
        /// <param name="durationRtpUnits"> The duration in timestamp units of the payload.</param>
        /// <param name="payloadID">The payload ID to place in the RTP header.</param>
        /// <param name="sample">The JPEG encoded payload.</param>
        public void SendMJPEGFrame(uint durationRtpUnits, int payloadID, byte[] sample)
        {
            if (CheckIfCanSendRtpRaw())
            {
                try
                {
                    var frameData = MJPEGPacketiser.GetFrameData(sample, out var customData);

                    var rtpHeader = MJPEGPacketiser.GetMJPEGRTPHeader(customData, 0);
                    if (rtpHeader.Length + frameData.Data.Length <= RTPSession.RTP_MAX_PAYLOAD)
                    {
                        var payload = rtpHeader.Concat(frameData.Data).ToArray();
                        SendRtpRaw(payload, LocalTrack.Timestamp, 1, payloadID, true);
                    }
                    else
                    {
                        var restBytes = frameData.Data;
                        var offset = 0;
                        while (restBytes.Length > 0)
                        {
                            var dataSize = RTPSession.RTP_MAX_PAYLOAD - rtpHeader.Length;
                            var isLast = dataSize >= restBytes.Length;
                            var data = isLast ? restBytes : restBytes.Take(dataSize).ToArray();
                            var markerBit = isLast ? 0 : 1;
                            var payload = rtpHeader.Concat(data).ToArray();
                            SendRtpRaw(payload, LocalTrack.Timestamp, markerBit, payloadID, true);

                            offset += RTPSession.RTP_MAX_PAYLOAD;
                            rtpHeader = MJPEGPacketiser.GetMJPEGRTPHeader(customData, offset);
                            restBytes = restBytes.Skip(data.Length).ToArray();
                        }
                    }
                }
                catch (SocketException sockExcp)
                {
                    logger.LogError("SocketException SendMJEPGFrame. " + sockExcp.Message);
                }
            }
        }

        /// <summary>
        /// Sends a video sample to the remote peer.
        /// </summary>
        /// <param name="durationRtpUnits">The duration in RTP timestamp units of the video sample. This
        /// value is added to the previous RTP timestamp when building the RTP header.</param>
        /// <param name="sample">The video sample to set as the RTP packet payload.</param>
        public void SendVideo(uint durationRtpUnits, ReadOnlyMemory<byte> sample)
        {
            if (!sendingFormatFound)
            {
                sendingFormat = GetSendingFormat().ToVideoFormat();
                sendingFormatFound = true;
            }

            int payloadID = sendingFormat.FormatID;

            switch (sendingFormat.Codec)
            {
                case VideoCodecsEnum.VP8:
                    SendVp8Frame(durationRtpUnits, payloadID, sample.Span); //to-do : avoid ToArray copy
                    break;
                case VideoCodecsEnum.H264:
                    SendH264Frame(durationRtpUnits, payloadID, sample);
                    break;
                //case VideoCodecsEnum.H265:
                //    SendH265Frame(durationRtpUnits, payloadID, sample);
                //    break;
                //case VideoCodecsEnum.JPEG:
                //    SendMJPEGFrame(durationRtpUnits, payloadID, sample);
                //    break;
                default:
                    throw new ApplicationException($"Unsupported video format selected {sendingFormat.FormatName}.");
            }
        }

        protected override void ProcessRtpPacket(IPEndPoint remoteEndPoint, RTPPacket rtpPacket, SDPAudioVideoMediaFormat format)
        {
            ProcessVideoRtpFrame(remoteEndPoint, rtpPacket, format);
            RaiseOnRtpPacketReceivedByIndex(remoteEndPoint, rtpPacket);
        }

        public void ProcessVideoRtpFrame(IPEndPoint endpoint, RTPPacket packet, SDPAudioVideoMediaFormat format)
        {
            if (OnVideoFrameReceivedByIndex == null)
            {
                return;
            }

            if (RtpVideoFramer != null)
            {
                var frame = RtpVideoFramer.GotRtpPacket(packet);
                if (frame != null)
                {
                    OnVideoFrameReceivedByIndex?.Invoke(Index, endpoint, packet.Header.Timestamp, frame, format.ToVideoFormat());
                }
            }
            else
            {
                if (format.ToVideoFormat().Codec == VideoCodecsEnum.VP8 ||
                    format.ToVideoFormat().Codec == VideoCodecsEnum.H264 ||
                    format.ToVideoFormat().Codec == VideoCodecsEnum.H265 ||
                    format.ToVideoFormat().Codec == VideoCodecsEnum.JPEG)
                {
                    logger.LogDebug("Video depacketisation codec set to {Codec} for SSRC {SSRC}.", format.ToVideoFormat().Codec, packet.Header.SyncSource);

                    RtpVideoFramer = new RtpVideoFramer(format.ToVideoFormat().Codec, MaxReconstructedVideoFrameSize);

                    var frame = RtpVideoFramer.GotRtpPacket(packet);
                    if (frame != null)
                    {
                        OnVideoFrameReceivedByIndex?.Invoke(Index, endpoint, packet.Header.Timestamp, frame, format.ToVideoFormat());
                    }
                }
                else
                {
                    logger.LogWarning("Video depacketisation logic for codec {CodecName} has not been implemented, PR's welcome!", format.Name());
                }
            }
        }

        public void CheckVideoFormatsNegotiation()
        {
            if (LocalTrack != null && LocalTrack.Capabilities?.Count() > 0)
            {
                OnVideoFormatsNegotiatedByIndex?.Invoke(
                            Index,
                            LocalTrack.Capabilities
                            .Select(x => x.ToVideoFormat()).ToList());
            }
        }
    }
}

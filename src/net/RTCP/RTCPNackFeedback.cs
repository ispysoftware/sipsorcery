/*
 * Filename: RTCPNackFeedback.cs
 *
 * Description:
 *   Full parser for the RTCP Generic NACK transport-layer feedback message
 *   (RFC 4585 §6.2.1, PT=RTPFB, FMT=1). The FCI field contains ONE OR MORE
 *   (PID, BLP) pairs; each pair names a lost packet plus a 16-bit bitmask of
 *   up to 16 further losses immediately following it. The pre-existing
 *   RTCPFeedback class only reads the first pair, which both under-reports
 *   the requested seqnums and (because its serialised length is fixed) breaks
 *   compound-packet offset accounting for multi-FCI NACKs.
 *
 * Author:        Sean Tearney
 * Date:          2026-07-18
 *
 * License:       BSD 3-Clause "New" or "Revised" License, see included LICENSE.md file.
 */

using System;
using System.Buffers.Binary;
using System.Collections.Generic;

namespace SIPSorcery.Net
{
    /// <summary>
    /// A parsed RTCP Generic NACK feedback message with every FCI entry.
    /// </summary>
    public class RTCPNackFeedback
    {
        public RTCPHeader Header { get; }
        public uint SenderSSRC { get; }

        /// <summary>
        /// The SSRC of the media source the NACK applies to — i.e. OUR local
        /// track SSRC when we are the sender being asked for retransmissions.
        /// </summary>
        public uint MediaSSRC { get; }

        /// <summary>
        /// The raw (PID, BLP) pairs from the FCI field, in wire order.
        /// </summary>
        public List<(ushort Pid, ushort Blp)> FciEntries { get; } = new List<(ushort, ushort)>();

        /// <summary>
        /// Creates a parsed NACK from a serialised RTCP feedback packet. The buffer
        /// must start at the RTCP header of the RTPFB message.
        /// </summary>
        public RTCPNackFeedback(ReadOnlySpan<byte> packet)
        {
            Header = new RTCPHeader(packet);

            int payloadIndex = RTCPHeader.HEADER_BYTES_LENGTH;
            SenderSSRC = BinaryPrimitives.ReadUInt32BigEndian(packet.Slice(payloadIndex));
            MediaSSRC = BinaryPrimitives.ReadUInt32BigEndian(packet.Slice(payloadIndex + 4));

            // Header.Length is in 32-bit words minus one, including the header.
            // FCI entries start after header (8 bytes) + two SSRCs (8 bytes).
            int packetLength = (Header.Length + 1) * 4;
            int fciIndex = payloadIndex + 8;

            while (fciIndex + 4 <= packetLength && fciIndex + 4 <= packet.Length)
            {
                ushort pid = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(fciIndex));
                ushort blp = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(fciIndex + 2));
                FciEntries.Add((pid, blp));
                fciIndex += 4;
            }
        }

        /// <summary>
        /// Enumerates every RTP sequence number requested by this NACK: each PID,
        /// plus PID+i (mod 2^16) for every set bit i (1-16) in the corresponding BLP.
        /// </summary>
        public IEnumerable<ushort> GetSequenceNumbers()
        {
            foreach (var (pid, blp) in FciEntries)
            {
                yield return pid;
                for (int bit = 0; bit < 16; bit++)
                {
                    if ((blp & (1 << bit)) != 0)
                    {
                        yield return (ushort)(pid + bit + 1);
                    }
                }
            }
        }
    }
}

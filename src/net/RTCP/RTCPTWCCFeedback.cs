/*
* Filename: RTCPTWCCFeedback.cs
*
* Description:
* Transport Wide Congestion Control (TWCC) Feedback Packet
*         0                   1                   2                   3
*         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
*        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
* header |V=2|P| FMT=15  |    PT=205     |             length            |
*        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*        |                     SSRC of packet sender                     |
*        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*        |                     SSRC of media source                      |
*        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
* TWCC   |           Base Sequence Number         | Packet Status Count  |
* header +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*        |                  Reference Time (24 bits)   | Fbk pkt cnt (8 bits)|
*        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*        |                                                               |
*        |             Packet Status Chunks (variable)                 |
*        |                                                               |
*        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*        |                                                               |
*        |               Receive Delta(s) (variable)                     |
*        |                                                               |
*        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*
*
* Author:        Sean Tearney
* Date:          2025 - 02 - 22
*
* License:       BSD 3-Clause "New" or "Revised" License, see included LICENSE.md file.
* 
* Change Log:
*   2025-02-20  Initial creation.
*/
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using SIPSorcery.Sys;

namespace SIPSorcery.Net
{
    public enum TWCCPacketStatusType
    {
        NotReceived = 0,
        ReceivedSmallDelta = 1,
        ReceivedLargeDelta = 2,
        Reserved = 3
    }

    /// <summary>
    /// Represents the status of a single RTP packet in a TWCC feedback message.
    /// </summary>
    /// <remarks>
    /// A struct: a feedback message reports every packet sent since the last one, and messages
    /// arrive 10-20 times a second per viewer, so as a class this was an allocation for every
    /// RTP packet sent.
    /// </remarks>
    public struct TWCCPacketStatus
    {
        /// <summary>
        /// The RTP sequence number for this packet.
        /// </summary>
        public ushort SequenceNumber { get; set; }
        /// <summary>
        /// The reception status.
        /// </summary>
        public TWCCPacketStatusType Status { get; set; }
        /// <summary>
        /// The receive time delta in (raw) units (typically 250 µs per unit). Null if not received.
        /// </summary>
        public int? Delta { get; set; }
    }

    /// <summary>
    /// Parser and serializer for RTCP TWCC feedback messages as per
    /// draft-holmer-rmcat-transport-wide-cc-extensions-01.
    /// 
    /// Format:
    /// 
    ///   0                   1                   2                   3
    ///   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    ///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///  |V=2|P|   FMT=15  |       PT=205      |          length             |
    ///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///  |                      SSRC of packet sender                    |
    ///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///  |                      SSRC of media source                     |
    ///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///  |      Base Sequence Number     |    Packet Status Count        |
    ///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///  |                      Reference Time                           |
    ///  |                 (24 bits)       | FB Packet Count (8 bits)      |
    ///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///  |                                                               |
    ///  |             Packet Status Chunks (variable length)            |
    ///  |                                                               |
    ///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///  |                                                               |
    ///  |                Receive Delta Values (variable length)         |
    ///  |                                                               |
    ///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// 
    /// Packet Status Chunks are 16-bit fields and come in two flavors:
    /// 
    /// 1. **Run Length Chunk** (when the two MSB are 00):
    ///    - Bits 15–14: Type (00)
    ///    - Bits 13–12: Packet Status Symbol (0–3)
    ///    - Bits 11–0 : Run Length (number of consecutive packets with that symbol)
    /// 
    /// 2. **Status Vector Chunk** (when the two MSB are 10 or 11):
    ///    - Bits 15–14: Type (10 for two-bit symbols, 11 for one-bit symbols)
    ///    - Bits 13–0 : For two-bit mode: seven 2-bit symbols; for one-bit mode: fourteen 1-bit symbols.
    ///      In one-bit mode, a bit value of 0 means packet not received; a value of 1 means received (assumed small delta).
    /// 
    /// For every packet marked as received (i.e. status of ReceivedSmallDelta or ReceivedLargeDelta),
    /// a delta field is present in the delta section. For small delta the field is 1 byte (signed),
    /// for large delta it is 2 bytes (signed, network order).
    /// </summary>
    public class RTCPTWCCFeedback
    {
        public RTCPHeader Header { get; private set; }
        public uint SenderSSRC { get; private set; }
        public uint MediaSSRC { get; private set; }

        /// <summary>
        /// The first (base) sequence number covered by this feedback.
        /// </summary>
        public ushort BaseSequenceNumber { get; private set; }

        /// <summary>
        /// Total number of packet statuses described.
        /// </summary>
        public ushort PacketStatusCount { get; private set; }

        /// <summary>
        /// 24-bit reference time, in multiples of 64 ms, from the top 24 bits of this 32-bit word.
        /// Per the spec this is semantically signed; it is stored as the raw 24-bit field because
        /// this class only round-trips it and never derives an absolute time from it.
        /// </summary>
        public uint ReferenceTime { get; private set; }

        /// <summary>
        /// Feedback packet count (the lower 8 bits of the 32-bit word containing ReferenceTime).
        /// </summary>
        public byte FeedbackPacketCount { get; private set; }

        /// <summary>
        /// The list of per-packet statuses (in order from BaseSequenceNumber).
        /// </summary>
        public List<TWCCPacketStatus> PacketStatuses { get; private set; }

        /// <summary>
        /// The resolution multiplier for delta values (e.g. 250 µs per unit).
        /// </summary>
        public int DeltaScale { get; set; } = 250;

        /// <summary>
        /// Maps a 2-bit packet status symbol to its <see cref="TWCCPacketStatusType"/>.
        /// A switch expression avoids the allocation and lookup cost of a dictionary.
        /// </summary>
        private static TWCCPacketStatusType BitsToStatus(ushort statusBits) => statusBits switch
        {
            0 => TWCCPacketStatusType.NotReceived,
            1 => TWCCPacketStatusType.ReceivedSmallDelta,
            2 => TWCCPacketStatusType.ReceivedLargeDelta,
            3 => TWCCPacketStatusType.Reserved,
            _ => throw new ArgumentException($"Invalid status bits: {statusBits}")
        };

        /// <summary>
        /// Maps a <see cref="TWCCPacketStatusType"/> to its 2-bit packet status symbol.
        /// </summary>
        private static ushort StatusToBits(TWCCPacketStatusType status) => status switch
        {
            TWCCPacketStatusType.NotReceived => 0,
            TWCCPacketStatusType.ReceivedSmallDelta => 1,
            TWCCPacketStatusType.ReceivedLargeDelta => 2,
            TWCCPacketStatusType.Reserved => 3,
            _ => throw new ArgumentException($"Invalid status: {status}")
        };


        /// <summary>
        /// Constructs a TWCC feedback message from the raw RTCP packet.
        /// </summary>
        /// <param name="packet">The RTCP TWCC feedback packet. Anything after it in the buffer
        /// (the rest of a compound packet) is ignored.</param>
        public RTCPTWCCFeedback(ReadOnlySpan<byte> packet)
        {
            // Parsed straight from the span into one list of status structs. This runs 10-20 times
            // a second for every viewer, and used to copy the buffer, build a list of status symbols
            // and a list of deltas, then allocate an object per reported packet.
            if (packet.Length < (RTCPHeader.HEADER_BYTES_LENGTH + 16))
            {
                throw new ArgumentException("Packet too short to be a valid TWCC feedback message.");
            }

            Header = new RTCPHeader(packet);

            // The caller passes the rest of the compound packet. Stop at the end of this message, so
            // a message that claims more deltas than it carries can't take them from the next one.
            int messageLength = (Header.Length + 1) * 4;
            if (messageLength >= RTCPHeader.HEADER_BYTES_LENGTH + 16 && messageLength < packet.Length)
            {
                packet = packet.Slice(0, messageLength);
            }

            int offset = RTCPHeader.HEADER_BYTES_LENGTH;

            SenderSSRC = BinaryPrimitives.ReadUInt32BigEndian(packet.Slice(offset));
            MediaSSRC = BinaryPrimitives.ReadUInt32BigEndian(packet.Slice(offset + 4));
            BaseSequenceNumber = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(offset + 8));
            PacketStatusCount = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(offset + 10));
            ReferenceTime = (uint)((packet[offset + 12] << 16) | (packet[offset + 13] << 8) | packet[offset + 14]);
            FeedbackPacketCount = packet[offset + 15];
            offset += 16;

            int statusCount = PacketStatusCount;
            var statuses = new List<TWCCPacketStatus>(statusCount);
            CollectionsMarshal.SetCount(statuses, statusCount);
            Span<TWCCPacketStatus> entries = CollectionsMarshal.AsSpan(statuses);

            // Packet status chunks: one status per packet from BaseSequenceNumber on.
            int filled = 0;
            ushort seq = BaseSequenceNumber;

            while (filled < statusCount)
            {
                if (offset + 2 > packet.Length)
                {
                    throw new ArgumentException($"Packet truncated during status chunk parsing. Expected {statusCount - filled} more statuses.");
                }

                ushort chunk = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(offset));
                offset += 2;

                int remaining = statusCount - filled;

                // Per draft-holmer-rmcat-transport-wide-cc-extensions:
                //   bit 15 (T)  = 0 → Run Length Chunk (status in bits 14-13, run in bits 12-0)
                //                = 1 → Status Vector Chunk; bit 14 (S) chooses symbol width:
                //                        S=0 → 1-bit symbols (14 symbols, bits 13-0)
                //                        S=1 → 2-bit symbols (7 symbols, bits 13-0)
                // Dispatch on T directly: a run length chunk can carry any of the 4 statuses, so its
                // status' high bit must not be mistaken for the chunk type.
                if ((chunk & 0x8000) == 0)
                {
                    var status = (TWCCPacketStatusType)((chunk >> 13) & 0x3);
                    int runLength = Math.Min(chunk & 0x1FFF, remaining);
                    for (int i = 0; i < runLength; i++)
                    {
                        entries[filled++] = new TWCCPacketStatus { SequenceNumber = seq++, Status = status };
                    }
                }
                else if ((chunk & 0x4000) == 0)
                {
                    // 1-bit symbols: 0 = not received, 1 = received with a small delta.
                    int symbols = Math.Min(14, remaining);
                    for (int i = 0; i < symbols; i++)
                    {
                        var status = ((chunk >> (13 - i)) & 0x1) == 0 ? TWCCPacketStatusType.NotReceived : TWCCPacketStatusType.ReceivedSmallDelta;
                        entries[filled++] = new TWCCPacketStatus { SequenceNumber = seq++, Status = status };
                    }
                }
                else
                {
                    int symbols = Math.Min(7, remaining);
                    for (int i = 0; i < symbols; i++)
                    {
                        var status = (TWCCPacketStatusType)((chunk >> (12 - (2 * i))) & 0x3);
                        entries[filled++] = new TWCCPacketStatus { SequenceNumber = seq++, Status = status };
                    }
                }
            }

            // Receive deltas: one for each packet reported received, in the same order, and none for
            // the others. (The deltas used to be collected into a list with a placeholder for every
            // packet NOT received, then read back with an index that only counted received packets.
            // The two fell out of step at the first lost packet in a message: every received packet
            // after it was given another packet's delta, or none at all, and a consumer that counts a
            // packet as received only when it has a delta undercounted them.)
            for (int i = 0; i < entries.Length; i++)
            {
                var status = entries[i].Status;

                if (status == TWCCPacketStatusType.ReceivedSmallDelta)
                {
                    if (offset + 1 > packet.Length)
                    {
                        break; // Truncated: this packet and the rest are left without a delta.
                    }

                    // Small delta is an UNSIGNED 8-bit value (spec §3.1.5): range [0, 63.75] ms in
                    // 250µs units. A signed cast here would corrupt any delta above 31.75 ms.
                    entries[i].Delta = packet[offset] * DeltaScale;
                    offset += 1;
                }
                else if (status == TWCCPacketStatusType.ReceivedLargeDelta)
                {
                    if (offset + 2 > packet.Length)
                    {
                        break;
                    }

                    entries[i].Delta = BinaryPrimitives.ReadInt16BigEndian(packet.Slice(offset)) * DeltaScale;
                    offset += 2;
                }
            }

            PacketStatuses = statuses;
        }

        /// <summary>
        /// Determines whether the 14 statuses starting at <paramref name="start"/> can be
        /// encoded as a one-bit status vector (all NotReceived or ReceivedSmallDelta).
        /// Avoids the allocation and delegate invocation of a LINQ Skip/Take/All.
        /// </summary>
        private bool CanUseOneBitVector(int start)
        {
            for (int j = 0; j < 14; j++)
            {
                var status = PacketStatuses[start + j].Status;
                if (status != TWCCPacketStatusType.NotReceived && status != TWCCPacketStatusType.ReceivedSmallDelta)
                {
                    return false;
                }
            }
            return true;
        }

        /// <summary>
        /// Serializes this TWCC feedback message to a byte array.
        /// Note: The serialization logic rebuilds the packet status chunks from the PacketStatuses list.
        /// This implements the run-length chunk when possible and defaults to two-bit
        /// status vector chunks if a run-length encoding isn’t efficient.
        /// </summary>
        /// <returns>The serialized RTCP TWCC feedback packet.</returns>
        public byte[] GetBytes()
        {
            int symbolCount = PacketStatuses.Count;

            // Worst-case chunk count is all 2-bit vector chunks (7 symbols per chunk),
            // and compute the exact delta byte count in the same pass to avoid regrowth.
            int chunkCapacity = (symbolCount + 6) / 7;
            int deltaBytesCapacity = 0;
            foreach (var ps in PacketStatuses)
            {
                if (ps.Status == TWCCPacketStatusType.ReceivedSmallDelta)
                {
                    deltaBytesCapacity += 1;
                }
                else if (ps.Status == TWCCPacketStatusType.ReceivedLargeDelta)
                {
                    deltaBytesCapacity += 2;
                }
            }

            List<ushort> chunks = new List<ushort>(chunkCapacity);
            List<byte> deltaBytes = new List<byte>(deltaBytesCapacity);
            int i = 0;
            while (i < PacketStatuses.Count)
            {
                var current = PacketStatuses[i].Status;
                int runLength = 1;
                while (i + runLength < PacketStatuses.Count && PacketStatuses[i + runLength].Status == current && runLength < 0x1FFF)
                {
                    runLength++;
                }

                // Check for a long run of the same status. Run Length Chunk layout
                // (draft-holmer §3.1.3): T(1)=0 | S(2)=status bits 14-13 | run length (13 bits 12-0).
                if (runLength >= 2)
                {
                    ushort statusBits = StatusToBits(current);
                    ushort chunk = (ushort)(statusBits << 13);
                    chunk |= (ushort)(runLength & 0x1FFF);
                    chunks.Add(chunk);
                    i += runLength;
                }
                // Try to use a one-bit status vector for efficiency.
                // Vector chunk (§3.1.4): T(1)=1 | S(1). S=0 → one-bit symbols, so marker is 10 = 0x8000.
                else if (i + 14 <= PacketStatuses.Count && CanUseOneBitVector(i))
                {
                    ushort chunk = 0x8000; // T=1, S=0 → one-bit symbol vector (14 symbols).
                    for (int j = 0; j < 14; j++)
                    {
                        if (PacketStatuses[i + j].Status == TWCCPacketStatusType.ReceivedSmallDelta)
                        {
                            chunk |= (ushort)(1 << (13 - j));
                        }
                    }
                    chunks.Add(chunk);
                    i += 14;
                }
                // Default to a two-bit status vector
                else
                {
                    int count = Math.Min(7, PacketStatuses.Count - i);
                    ushort chunk = 0xC000; // T=1, S=1 → two-bit symbol vector (7 symbols).
                    for (int j = 0; j < count; j++)
                    {
                        ushort statusBits = StatusToBits(PacketStatuses[i + j].Status);
                        chunk |= (ushort)(statusBits << (12 - 2 * j));
                    }
                    chunks.Add(chunk);
                    i += count;
                }
            }

            foreach (var ps in PacketStatuses)
            {
                if (ps.Status == TWCCPacketStatusType.ReceivedSmallDelta)
                {
                    // Small delta is unsigned: clamp to [0, 255] units (250µs each -> [0, 63.75] ms).
                    int units = ps.Delta.HasValue ? ps.Delta.Value / DeltaScale : 0;
                    deltaBytes.Add((byte)Math.Min(Math.Max(units, 0), 255));
                }
                else if (ps.Status == TWCCPacketStatusType.ReceivedLargeDelta)
                {
                    short delta = (short)(ps.Delta.HasValue ? ps.Delta.Value / DeltaScale : 0);
                    deltaBytes.Add((byte)(delta >> 8));
                    deltaBytes.Add((byte)(delta & 0xFF));
                }
            }

            int chunksPart = chunks.Count * 2;
            int deltasPart = deltaBytes.Count;

            // Fixed fields after the 4-byte RTCP common header total 16 bytes:
            // SenderSSRC(4) + MediaSSRC(4) + BaseSeq(2) + PacketStatusCount(2) + RefTime/FbCount(4).
            int unpaddedLength = RTCPHeader.HEADER_BYTES_LENGTH + 16 + chunksPart + deltasPart;

            // RTCP packets must be 32-bit aligned. The recv-delta section can be an odd number of
            // bytes, so zero-pad the tail up to a 4-byte boundary and include it in the length word.
            // (Matches libwebrtc/browser behaviour: alignment zeros only, no RTCP pad-count byte; the
            // parser stops after one delta per received status and ignores the trailing padding.)
            int padBytes = (4 - (unpaddedLength % 4)) % 4;
            int totalLength = unpaddedLength + padBytes;

            byte[] buffer = new byte[totalLength];
            int offset = RTCPHeader.HEADER_BYTES_LENGTH;

            WriteUInt32(buffer, ref offset, SenderSSRC);
            WriteUInt32(buffer, ref offset, MediaSSRC);
            WriteUInt16(buffer, ref offset, BaseSequenceNumber);
            WriteUInt16(buffer, ref offset, (ushort)PacketStatuses.Count);

            uint refTimeAndCount = (ReferenceTime << 8) | FeedbackPacketCount;
            WriteUInt32(buffer, ref offset, refTimeAndCount);

            foreach (ushort chunk in chunks)
            {
                WriteUInt16(buffer, ref offset, chunk);
            }

            foreach (byte b in deltaBytes)
            {
                buffer[offset++] = b;
            }

            // Trailing pad bytes (if any) are already zero from allocation.
            Header.SetLength((ushort)(totalLength / 4 - 1));
            Buffer.BlockCopy(Header.GetBytes(), 0, buffer, 0, RTCPHeader.HEADER_BYTES_LENGTH);

            return buffer;
        }

        public override string ToString()
        {
            var packetStatusInfo = string.Join(", ", PacketStatuses.Select(ps =>
                $"Seq:{ps.SequenceNumber}({ps.Status}{(ps.Delta.HasValue ? $",Δ:{ps.Delta.Value}" : "")})"));

            return $"TWCC Feedback: SenderSSRC={SenderSSRC}, MediaSSRC={MediaSSRC}, BaseSeq={BaseSequenceNumber}, " +
                   $"StatusCount={PacketStatusCount}, RefTime={ReferenceTime} (64ms units), " +
                   $"FbkPktCount={FeedbackPacketCount}, PacketStatuses=[{packetStatusInfo}]";
        }

        #region Helper Methods

        private uint ReadUInt32(byte[] buffer, ref int offset)
        {
            uint value = BinaryPrimitives.ReadUInt32BigEndian(buffer.AsSpan(offset));
            offset += 4;
            return value;
        }

        private ushort ReadUInt16(byte[] buffer, ref int offset)
        {
            ushort value = BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(offset));
            offset += 2;
            return value;
        }

        private void WriteUInt32(byte[] buffer, ref int offset, uint value)
        {
            BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(offset), value);
            offset += 4;
        }

        private void WriteUInt16(byte[] buffer, ref int offset, ushort value)
        {
            BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(offset), value);
            offset += 2;
        }

        #endregion
    }
}

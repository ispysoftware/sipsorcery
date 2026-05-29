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
    public class TWCCPacketStatus
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
    /// Parser and serializer for RTCP TWCC feedback messages as per RFC 8888.
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
        /// 24-bit reference time (in 1/64 seconds) from the top 24 bits of this 32-bit word.
        /// </summary>
        public uint ReferenceTime { get; private set; }

        /// <summary>
        /// Feedback packet count (the lower 8 bits of the 32-bit word containing ReferenceTime).
        /// </summary>
        public byte FeedbackPacketCount { get; private set; }

        /// <summary>
        /// The list of per-packet statuses (in order from BaseSequenceNumber).
        /// </summary>
        public List<TWCCPacketStatus> PacketStatuses { get; private set; } = new List<TWCCPacketStatus>();

        /// <summary>
        /// The resolution multiplier for delta values (e.g. 250 µs per unit).
        /// </summary>
        public int DeltaScale { get; set; } = 250;

        private static readonly Dictionary<TWCCPacketStatusType, ushort> StatusToBits = new Dictionary<TWCCPacketStatusType, ushort>
        {
            { TWCCPacketStatusType.NotReceived, 0 },
            { TWCCPacketStatusType.ReceivedSmallDelta, 1 },
            { TWCCPacketStatusType.ReceivedLargeDelta, 2 },
            { TWCCPacketStatusType.Reserved, 3 }
        };

        private static readonly Dictionary<ushort, TWCCPacketStatusType> BitsToStatus = StatusToBits.ToDictionary(kvp => kvp.Value, kvp => kvp.Key);


        /// <summary>
        /// Constructs a TWCC feedback message from the raw RTCP packet.
        /// </summary>
        /// <param name="packetspan">The complete RTCP TWCC feedback packet.</param>
        /// <summary>
        /// Parses a TWCC feedback packet from the given byte array.
        /// </summary>
        public RTCPTWCCFeedback(ReadOnlySpan<byte> packetspan)
        {
            byte[] packet = packetspan.ToArray();
            ValidatePacket(packet);

            Header = new RTCPHeader(packet);
            int offset = RTCPHeader.HEADER_BYTES_LENGTH;

            SenderSSRC = ReadUInt32(packet, ref offset);
            MediaSSRC = ReadUInt32(packet, ref offset);

            BaseSequenceNumber = ReadUInt16(packet, ref offset);
            PacketStatusCount = ReadUInt16(packet, ref offset);

            ReferenceTime = ParseReferenceTime(packet, ref offset, out byte fbCount);
            FeedbackPacketCount = fbCount;

            var statusSymbols = ParseStatusChunks(packet, ref offset);
            var (deltaValues, lastOffset) = ParseDeltaValues(packet, offset, statusSymbols);

            BuildPacketStatusList(statusSymbols, deltaValues);
        }

        private void ParseRunLengthChunk(ushort chunk, List<TWCCPacketStatusType> statusSymbols, ref int remainingStatuses)
        {
            // Per draft-holmer-rmcat-transport-wide-cc-extensions section 3.1.3, the
            // Run Length Chunk layout is:
            //
            //   bit:  15  14 13  12 11 10  9  8  7  6  5  4  3  2  1  0
            //         [T] [S(2)] [           Run Length (13 bits)           ]
            //          =0   └ status ┘  └─────── 13-bit run ────────────────┘
            //
            // PREVIOUSLY this used `(chunk >> 12) & 0x3` for status (off by one — it
            // read bits 13..12 instead of 14..13) and `chunk & 0x0FFF` for run length
            // (one bit too narrow). The status bug made every Run Length status decode
            // as LargeDelta on localhost, which then caused the delta-value parser to
            // read 2 bytes instead of 1 and produced bogus ±8s arrival times.
            ushort statusBits = (ushort)((chunk >> 13) & 0x3);
            if (!BitsToStatus.TryGetValue(statusBits, out TWCCPacketStatusType symbol))
            {
                throw new ArgumentException($"Invalid status bits in run length chunk: {statusBits}");
            }

            ushort runLength = (ushort)(chunk & 0x1FFF);
            runLength = (ushort)Math.Min(runLength, remainingStatuses);

            for (int i = 0; i < runLength; i++)
            {
                statusSymbols.Add(symbol);
            }
            remainingStatuses -= runLength;
        }


        private void ValidatePacket(byte[] packet)
        {
            if (packet == null)
            {
                throw new ArgumentNullException(nameof(packet));
            }
            if (packet.Length < (RTCPHeader.HEADER_BYTES_LENGTH + 12))
            {
                throw new ArgumentException("Packet too short to be a valid TWCC feedback message.");
            }
        }

        private uint ParseReferenceTime(byte[] packet, ref int offset, out byte fbCount)
        {
            if (offset + 4 > packet.Length)
            {
                throw new ArgumentException("Packet truncated at reference time.");
            }
            byte b1 = packet[offset++];
            byte b2 = packet[offset++];
            byte b3 = packet[offset++];
            fbCount = packet[offset++];
            return (uint)((b1 << 16) | (b2 << 8) | b3);
        }

        private List<TWCCPacketStatusType> ParseStatusChunks(byte[] packet, ref int offset)
        {
            var statusSymbols = new List<TWCCPacketStatusType>();
            int remainingStatuses = PacketStatusCount;

            while (remainingStatuses > 0)
            {
                if (offset + 2 > packet.Length)
                {
                    throw new ArgumentException($"Packet truncated during status chunk parsing. Expected {remainingStatuses} more statuses.");
                }

                ushort chunk = ReadUInt16(packet, ref offset);

                // Per draft-holmer-rmcat-transport-wide-cc-extensions:
                //   bit 15 (T)  = 0 → Run Length Chunk (status in bits 14-13, run in bits 12-0)
                //                = 1 → Status Vector Chunk; bit 14 (S) chooses symbol width:
                //                        S=0 → 1-bit symbols (14 symbols, bits 13-0)
                //                        S=1 → 2-bit symbols (7 symbols, bits 13-0)
                //
                // BEFORE this dispatch had two bugs:
                //   1. Cases 2 and 3 were wired to the wrong vector parsers.
                //   2. Case 1 (run-length with LargeDelta or Reserved status, i.e. S high
                //      bit set) had no handler at all — those chunks were silently dropped.
                // Both meant feedback decoded as garbage. Dispatch on T directly so case 1
                // can't go missing.
                if ((chunk & 0x8000) == 0)
                {
                    // T = 0 → Run Length Chunk. Status (any of the 4 values) is in bits 14-13.
                    ParseRunLengthChunk(chunk, statusSymbols, ref remainingStatuses);
                }
                else if ((chunk & 0x4000) == 0)
                {
                    // T = 1, S = 0 → 1-bit symbol vector (14 symbols).
                    ParseOneBitStatusVector(chunk, statusSymbols, ref remainingStatuses);
                }
                else
                {
                    // T = 1, S = 1 → 2-bit symbol vector (7 symbols).
                    ParseTwoBitStatusVector(chunk, statusSymbols, ref remainingStatuses);
                }
            }
            return statusSymbols;
        }

        private void ParseTwoBitStatusVector(ushort chunk, List<TWCCPacketStatusType> statusSymbols, ref int remainingStatuses)
        {
            int symbolsToRead = Math.Min(7, remainingStatuses);
            for (int i = 0; i < symbolsToRead; i++)
            {
                int shift = 12 - (2 * i);
                ushort symVal = (ushort)((chunk >> shift) & 0x3);
                if (!BitsToStatus.TryGetValue(symVal, out TWCCPacketStatusType symbol))
                {
                    throw new ArgumentException($"Invalid status bits in two-bit vector: {symVal}");
                }
                statusSymbols.Add(symbol);
            }
            remainingStatuses -= symbolsToRead;
        }

        private void ParseOneBitStatusVector(ushort chunk, List<TWCCPacketStatusType> statusSymbols, ref int remainingStatuses)
        {
            int symbolsToRead = Math.Min(14, remainingStatuses);
            for (int i = 0; i < symbolsToRead; i++)
            {
                int shift = 13 - i;
                int bit = (chunk >> shift) & 0x1;
                statusSymbols.Add(bit == 0 ? TWCCPacketStatusType.NotReceived : TWCCPacketStatusType.ReceivedSmallDelta);
            }
            remainingStatuses -= symbolsToRead;
        }

        private (List<int> deltaValues, int lastOffset) ParseDeltaValues(byte[] packet, int offset, List<TWCCPacketStatusType> statusSymbols)
        {
            var deltaValues = new List<int>();
            foreach (var status in statusSymbols)
            {
                if (status == TWCCPacketStatusType.NotReceived || status == TWCCPacketStatusType.Reserved)
                {
                    deltaValues.Add(int.MinValue); // Add placeholder
                    continue;
                }

                int deltaSize = (status == TWCCPacketStatusType.ReceivedSmallDelta) ? 1 : 2;
                if (offset + deltaSize > packet.Length)
                {
                    deltaValues.Add(int.MinValue);
                    break;
                }

                if (deltaSize == 1)
                {
                    deltaValues.Add((sbyte)packet[offset] * DeltaScale);
                    offset += 1;
                }
                else
                {
                    short rawDelta = (short)((packet[offset] << 8) | packet[offset + 1]);
                    deltaValues.Add(rawDelta * DeltaScale);
                    offset += 2;
                }
            }
            return (deltaValues, offset);
        }

        private void BuildPacketStatusList(List<TWCCPacketStatusType> statusSymbols, List<int> deltaValues)
        {
            PacketStatuses = new List<TWCCPacketStatus>();
            ushort seq = BaseSequenceNumber;

            int deltaValueIndex = 0;
            for (int i = 0; i < statusSymbols.Count; i++)
            {
                int? delta = null;
                if (statusSymbols[i] != TWCCPacketStatusType.NotReceived && statusSymbols[i] != TWCCPacketStatusType.Reserved)
                {
                    if (deltaValueIndex < deltaValues.Count)
                    {
                        if (deltaValues[deltaValueIndex] != int.MinValue)
                        {
                            delta = deltaValues[deltaValueIndex];
                        }
                        deltaValueIndex++;
                    }
                }

                PacketStatuses.Add(new TWCCPacketStatus
                {
                    SequenceNumber = seq++,
                    Status = statusSymbols[i],
                    Delta = delta
                });
            }
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
            List<ushort> chunks = new List<ushort>();
            List<byte> deltaBytes = new List<byte>();
            int i = 0;
            while (i < PacketStatuses.Count)
            {
                var current = PacketStatuses[i].Status;
                int runLength = 1;
                while (i + runLength < PacketStatuses.Count && PacketStatuses[i + runLength].Status == current && runLength < 0x0FFF)
                {
                    runLength++;
                }

                // Check for a long run of the same status
                if (runLength >= 2)
                {
                    ushort statusBits = StatusToBits[current];
                    ushort chunk = (ushort)(statusBits << 12);
                    chunk |= (ushort)(runLength & 0x0FFF);
                    chunks.Add(chunk);
                    i += runLength;
                }
                // Try to use a one-bit status vector for efficiency
                else if (i + 14 <= PacketStatuses.Count && PacketStatuses.Skip(i).Take(14).All(ps => ps.Status == TWCCPacketStatusType.NotReceived || ps.Status == TWCCPacketStatusType.ReceivedSmallDelta))
                {
                    ushort chunk = 0xC000; // Set top bits to 11 for one-bit vector
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
                    ushort chunk = 0x8000; // Set top bits to 10 for two-bit vector
                    for (int j = 0; j < count; j++)
                    {
                        ushort statusBits = StatusToBits[PacketStatuses[i + j].Status];
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
                    sbyte delta = (sbyte)(ps.Delta.HasValue ? ps.Delta.Value / DeltaScale : 0);
                    deltaBytes.Add((byte)delta);
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
            int totalLength = RTCPHeader.HEADER_BYTES_LENGTH + 12 + chunksPart + deltasPart;

            byte[] buffer = new byte[totalLength];
            Buffer.BlockCopy(Header.GetBytes(), 0, buffer, 0, RTCPHeader.HEADER_BYTES_LENGTH);
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

            Header.SetLength((ushort)(totalLength / 4 - 1));
            Buffer.BlockCopy(Header.GetBytes(), 0, buffer, 0, RTCPHeader.HEADER_BYTES_LENGTH);

            return buffer;
        }

        public override string ToString()
        {
            var packetStatusInfo = string.Join(", ", PacketStatuses.Select(ps =>
                $"Seq:{ps.SequenceNumber}({ps.Status}{(ps.Delta.HasValue ? $",Δ:{ps.Delta.Value}" : "")})"));

            return $"TWCC Feedback: SenderSSRC={SenderSSRC}, MediaSSRC={MediaSSRC}, BaseSeq={BaseSequenceNumber}, " +
                   $"StatusCount={PacketStatusCount}, RefTime={ReferenceTime} (1/64 sec), " +
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

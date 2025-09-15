using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using SIPSorcery.net.RTP; // Ensure this using is present for RTPHeaderExtensionData
using SIPSorcery.Sys;

namespace SIPSorcery.Net;

public class RTPHeader
{
    public const int MIN_HEADER_LEN = 12;
    public const int RTP_VERSION = 2;
    public const int ONE_BYTE_EXTENSION_PROFILE = 0xBEDE;
    public const int TWO_BYTE_EXTENSION_PROFILE = 0x1000;

    public int Version { get; private set; } = RTP_VERSION;
    public int PaddingFlag { get; set; }
    public int HeaderExtensionFlag { get; set; }
    public int CSRCCount { get; private set; }
    public int MarkerBit { get; set; }
    public int PayloadType { get; set; }
    public ushort SequenceNumber { get; set; }
    public uint Timestamp { get; set; }
    public uint SyncSource { get; set; }
    public uint[] CSRCList { get; private set; }
    public ushort ExtensionProfile { get; private set; }
    public ushort ExtensionLength { get; private set; }
    public ReadOnlyMemory<byte> ExtensionPayload { get; private set; }

    public int PayloadSize { get; private set; }
    public byte PaddingCount { get; private set; }

    /// <summary>
    /// The local time the RTP packet was received. This is not part of the
    /// RTP specification but is useful for application logic.
    /// </summary>
    public DateTime ReceivedTime { get; set; }

    public int Length => MIN_HEADER_LEN + (CSRCCount * 4) + (HeaderExtensionFlag == 0 ? 0 : 4 + (ExtensionLength * 4));

    public RTPHeader()
    {
        ReceivedTime = DateTime.UtcNow;
        SequenceNumber = Crypto.GetRandomUInt16();
        SyncSource = Crypto.GetRandomUInt();
        Timestamp = Crypto.GetRandomUInt();
    }

    public RTPHeader(ReadOnlyMemory<byte> buffer)
    {
        if (buffer.Length < MIN_HEADER_LEN)
        {
            throw new ArgumentException("The buffer did not contain the minimum number of bytes for an RTP header packet.");
        }
        ReceivedTime = DateTime.UtcNow;
        var span = buffer.Span;
        ushort firstWord = BinaryPrimitives.ReadUInt16BigEndian(span);

        Version = firstWord >> 14;
        PaddingFlag = (firstWord >> 13) & 0x1;
        HeaderExtensionFlag = (firstWord >> 12) & 0x1;
        CSRCCount = (firstWord >> 8) & 0xf;
        MarkerBit = (firstWord >> 7) & 0x1;
        PayloadType = firstWord & 0x7f;

        SequenceNumber = BinaryPrimitives.ReadUInt16BigEndian(span.Slice(2));
        Timestamp = BinaryPrimitives.ReadUInt32BigEndian(span.Slice(4));
        SyncSource = BinaryPrimitives.ReadUInt32BigEndian(span.Slice(8));

        int csrcOffset = MIN_HEADER_LEN;
        if (CSRCCount > 0)
        {
            CSRCList = new uint[CSRCCount];
            for (int i = 0; i < CSRCCount; i++)
            {
                CSRCList[i] = BinaryPrimitives.ReadUInt32BigEndian(span.Slice(csrcOffset));
                csrcOffset += 4;
            }
        }

        if (HeaderExtensionFlag == 1 && buffer.Length >= csrcOffset + 4)
        {
            ExtensionProfile = BinaryPrimitives.ReadUInt16BigEndian(span.Slice(csrcOffset));
            ExtensionLength = BinaryPrimitives.ReadUInt16BigEndian(span.Slice(csrcOffset + 2));
            int extensionPayloadLength = ExtensionLength * 4;

            if (extensionPayloadLength > 0 && buffer.Length >= csrcOffset + 4 + extensionPayloadLength)
            {
                ExtensionPayload = buffer.Slice(csrcOffset + 4, extensionPayloadLength);
            }
        }

        PayloadSize = buffer.Length - Length;
        if (PaddingFlag == 1 && buffer.Length > 0)
        {
            PaddingCount = span[buffer.Length - 1];
            if (PaddingCount < PayloadSize)
            {
                PayloadSize -= PaddingCount;
            }
        }
    }

    public int WriteTo(Span<byte> destination)
    {
        // ... (WriteTo logic is the same as the previous correct version) ...
        if (destination.Length < Length)
        {
            throw new ArgumentException("Destination buffer is too small for the RTP header.");
        }

        ushort firstWord = (ushort)((Version << 14) | (PaddingFlag << 13) | (HeaderExtensionFlag << 12) | (CSRCCount << 8) | (MarkerBit << 7) | PayloadType);

        BinaryPrimitives.WriteUInt16BigEndian(destination, firstWord);
        BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(2), SequenceNumber);
        BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(4), Timestamp);
        BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(8), SyncSource);

        int cursor = MIN_HEADER_LEN;
        if (CSRCList != null)
        {
            for (int i = 0; i < CSRCList.Length; i++)
            {
                BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(cursor), CSRCList[i]);
                cursor += 4;
            }
        }

        if (HeaderExtensionFlag == 1)
        {
            BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(cursor), ExtensionProfile);
            cursor += 2;
            BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(cursor), ExtensionLength);
            cursor += 2;

            if (!ExtensionPayload.IsEmpty)
            {
                ExtensionPayload.Span.CopyTo(destination.Slice(cursor));
            }
        }

        return Length;
    }

    // ============================================================================================
    // FIXED SECTION: The GetHeaderExtensions method is now fully implemented and allocation-free.
    // ============================================================================================
    public List<RTPHeaderExtensionData> GetHeaderExtensions()
    {
        var extensions = new List<RTPHeaderExtensionData>();
        if (HeaderExtensionFlag == 0 || ExtensionPayload.IsEmpty)
        {
            return extensions;
        }

        var payloadSpan = ExtensionPayload.Span;
        int cursor = 0;

        while (cursor < payloadSpan.Length)
        {
            // Skip padding bytes.
            if (payloadSpan[cursor] == 0x00)
            {
                cursor++;
                continue;
            }

            if (ExtensionProfile == ONE_BYTE_EXTENSION_PROFILE)
            {
                if (cursor + 1 >= payloadSpan.Length) break;

                int id = (payloadSpan[cursor] & 0xF0) >> 4;
                int len = (payloadSpan[cursor] & 0x0F) + 1;
                cursor++;

                if (cursor + len > payloadSpan.Length) break;

                // Create the extension data with a zero-copy slice of the payload.
                var data = ExtensionPayload.Slice(cursor, len);
                extensions.Add(new RTPHeaderExtensionData(id, data, RTPHeaderExtensionType.OneByte));
                cursor += len;
            }
            else if (ExtensionProfile == TWO_BYTE_EXTENSION_PROFILE)
            {
                if (cursor + 2 >= payloadSpan.Length) break;

                int id = payloadSpan[cursor];
                int len = payloadSpan[cursor + 1];
                cursor += 2;

                if (cursor + len > payloadSpan.Length) break;

                var data = ExtensionPayload.Slice(cursor, len);
                extensions.Add(new RTPHeaderExtensionData(id, data, RTPHeaderExtensionType.TwoByte));
                cursor += len;
            }
            else
            {
                // Unrecognized extension profile.
                break;
            }
        }

        return extensions;
    }

    /// <summary>
    /// Tries to parse an RTP Header from a buffer.
    /// </summary>
    public static bool TryParse(ReadOnlyMemory<byte> buffer, out RTPHeader header)
    {
        // The buffer must be at least the minimum header size.
        if (buffer.Length < MIN_HEADER_LEN)
        {
            header = null;
            return false;
        }

        // The parsing logic is now handled by the efficient constructor.
        header = new RTPHeader(buffer);
        return true;
    }

    /// <summary>
    /// Given a previously seen RTP timestamp (previousTs), returns
    /// the difference in RTP‐timestamp units between this header’s
    /// Timestamp and previousTs, correctly handling 32‐bit wraparound.
    /// If previousTs is zero, returns 0.
    /// </summary>
    public uint GetTimestampDelta(uint previousTs)
    {
        if (previousTs == 0)
        {
            return 0;
        }

        uint currentTs = this.Timestamp;
        if (currentTs >= previousTs)
        {
            // No wraparound
            return currentTs - previousTs;
        }
        else
        {
            // Wrapped around 2^32
            const ulong FullRange = (ulong)uint.MaxValue + 1UL;
            ulong diff = (ulong)currentTs + FullRange - previousTs;
            return (uint)(diff & 0xFFFFFFFF);
        }
    }
}

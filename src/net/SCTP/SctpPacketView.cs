using System;
using System.Collections.Generic;

using Microsoft.Extensions.Logging;

using SIPSorcery.Sys;

namespace SIPSorcery.Net;

public readonly ref struct SctpPacketView
{
    static readonly ILogger logger = LogFactory.CreateLogger<SctpPacket>();
    readonly ReadOnlySpan<byte> buffer;
    readonly InlineList<Chunk> chunks;
    // Only counted: the unrecognised chunks themselves are never read.
    readonly int unrecognizedCount;

    public readonly SctpHeader Header => SctpHeader.Parse(buffer);
    public int ChunkCount => chunks.Count;
    public SctpChunkView this[int index] => chunks[index].View(buffer);
    public SctpChunkView GetChunk(SctpChunkType type)
    {
        bool found = false;
        SctpChunkView result = default;
        for (int i = 0; i < chunks.Count; i++)
        {
            var chunk = chunks[i];
            var view = chunk.View(buffer);
            if (view.Type == type)
            {
                if (found)
                {
                    throw new InvalidOperationException($"Multiple {type} chunks found.");
                }

                result = view;
                found = true;
            }
        }
        return found ? result : throw new KeyNotFoundException();
    }
    public bool Has(SctpChunkType type)
    {
        for (int i = 0; i < chunks.Count; i++)
        {
            var chunk = chunks[i];
            var view = chunk.View(buffer);
            if (view.Type == type)
            {
                return true;
            }
        }
        return false;
    }
    public int UnrecognizedChunkCount => unrecognizedCount;

    public static SctpPacketView Parse(ReadOnlySpan<byte> buffer)
    {
        var chunks = new InlineList<Chunk>();
        int unrecognizedCount = 0;
        int posn = SctpHeader.SCTP_HEADER_LENGTH;

        bool stop = false;

        while (posn < buffer.Length)
        {
            // The cursor moves on by the declared chunk length, so a length of 0 (an unrecognised chunk type to skip is
            // enough) left it where it was and spun this loop on the receive thread for good. Nothing throws, so the
            // receive loop's per-packet guard never saw it (GHSA-qmvg-569h-hqrh, upstream fe5a1fa4b).
            if (buffer.Length - posn < SctpChunk.SCTP_CHUNK_HEADER_LENGTH)
            {
                throw new ApplicationException("The SCTP packet buffer was too short to contain a complete chunk header.");
            }

            int declaredLength = (int)SctpChunk.GetChunkLengthFromHeader(buffer, posn, false);
            if (declaredLength < SctpChunk.SCTP_CHUNK_HEADER_LENGTH)
            {
                throw new ApplicationException($"The SCTP chunk length was invalid. The minimum length is {SctpChunk.SCTP_CHUNK_HEADER_LENGTH} bytes but the packet specified {declaredLength} bytes.");
            }

            if (posn + declaredLength > buffer.Length)
            {
                throw new ApplicationException($"The SCTP packet buffer was too short. Required {declaredLength} chunk bytes but only {buffer.Length - posn} available.");
            }

            byte chunkType = buffer[posn];
            // Padded as an int: SctpPadding returns a ushort, which wraps a declared 65533-65535 round to 0.
            int chunkLength = (declaredLength + 3) & ~3;
            var chunk = new Chunk() { Offset = posn, Length = chunkLength };

            if (((SctpChunkType)chunkType).IsDefined())
            {
                chunk.View(buffer);
                chunks.Add(chunk);
            }
            else
            {
                switch (SctpChunk.GetUnrecognisedChunkAction(chunkType))
                {
                    case SctpUnrecognisedChunkActions.Stop:
                        stop = true;
                        break;
                    case SctpUnrecognisedChunkActions.StopAndReport:
                        stop = true;
                        unrecognizedCount++;
                        break;
                    case SctpUnrecognisedChunkActions.Skip:
                        break;
                    case SctpUnrecognisedChunkActions.SkipAndReport:
                        unrecognizedCount++;
                        break;
                }
            }

            if (stop)
            {
                logger.LogWarning("SCTP unrecognised chunk type {Type} indicated no further chunks should be processed.", chunkType);
                break;
            }

            posn += chunkLength;
        }
        return new(buffer, chunks, unrecognizedCount);
    }

    public SctpPacket AsPacket() => SctpPacket.Parse(buffer);

    SctpPacketView(ReadOnlySpan<byte> buffer, InlineList<Chunk> chunks, int unrecognizedCount)
    {
        this.buffer = buffer;
        this.chunks = chunks;
        this.unrecognizedCount = unrecognizedCount;
    }

    struct Chunk
    {
        public int Offset { get; set; }
        public int Length { get; set; }
        public SctpChunkView View(ReadOnlySpan<byte> buffer)
            => new(buffer.Slice(Offset, Length));
    }
}

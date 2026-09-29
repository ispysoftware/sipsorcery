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
            byte chunkType = buffer[posn];
            int chunkLength = (int)SctpChunk.GetChunkLengthFromHeader(buffer, posn, true);
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

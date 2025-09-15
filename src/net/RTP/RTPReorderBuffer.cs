using System;
using System.Buffers;
using System.Collections.Generic;
using Microsoft.Extensions.Logging;
using SIPSorcery.Sys;

namespace SIPSorcery.Net
{
    public class RTPReorderBuffer
    {
        /// <summary>
        /// A private struct to hold a packet whose payload is in a rented buffer.
        /// It must be disposed to return the buffer to the memory pool.
        /// </summary>
        public readonly struct PooledRtpPacket : IDisposable
        {
            public readonly RTPHeader Header { get; }
            private readonly IMemoryOwner<byte> _payloadOwner;
            public readonly Memory<byte> Payload { get; }

            public PooledRtpPacket(RTPHeader header, IMemoryOwner<byte> payloadOwner, int payloadLength)
            {
                Header = header;
                _payloadOwner = payloadOwner;
                Payload = _payloadOwner.Memory.Slice(0, payloadLength);
            }

            public void Dispose()
            {
                _payloadOwner?.Dispose();
            }
        }

        private readonly TimeSpan _maxDropOutTime;
        private readonly IDateTime _datetimeProvider;
        // The data store now holds the disposable PooledRtpPacket struct.
        private readonly LinkedList<PooledRtpPacket> _data = new LinkedList<PooledRtpPacket>();

        private ushort? _currentSeqNumber;

        private static ILogger logger = Log.Logger;

        public RTPReorderBuffer(TimeSpan maxDropOutTime, IDateTime datetimeProvider = null)
        {
            _maxDropOutTime = maxDropOutTime;
            _datetimeProvider = datetimeProvider ?? new DefaultTimeProvider();
        }

        // Helper properties now correctly return the pooled packet type.
        private PooledRtpPacket First => _data.First?.Value ?? default;
        private PooledRtpPacket Last => _data.Last?.Value ?? default;

        // Helper methods now correctly accept the pooled packet type.
        private bool IsBeforeWrapAround(PooledRtpPacket packet)
        {
            return IsBeforeWrapAround(packet.Header.SequenceNumber);
        }
        private bool IsBeforeWrapAround(ushort seq)
        {
            return seq > ushort.MaxValue / 2 + ushort.MaxValue / 4;
        }
        private bool IsAfterWrapAround(PooledRtpPacket packet)
        {
            return packet.Header.SequenceNumber < ushort.MaxValue / 4;
        }

        /// <summary>
        /// Gets the next packet from the buffer. The caller is responsible for
        /// calling Dispose() on the returned packet to release its memory buffer.
        /// </summary>
        public bool Get(out PooledRtpPacket packet)
        {
            packet = default;
            // Use _data.Last instead of the Last property to avoid an extra struct copy.
            if (_data.Last == null)
            {
                return false;
            }

            var lastPacket = _data.Last.Value;

            if (_currentSeqNumber.HasValue && _currentSeqNumber != lastPacket.Header.SequenceNumber)
            {
                if (_datetimeProvider.Time - lastPacket.Header.ReceivedTime < _maxDropOutTime)
                {
                    return false;
                }
            }

            packet = lastPacket;
            _data.RemoveLast();
            _currentSeqNumber = (ushort)checked(packet.Header.SequenceNumber + 1);
            return true;
        }

        /// <summary>
        /// Adds an ephemeral RTP packet to the buffer. This method creates a safe,
        /// pooled copy of the packet's payload to store.
        /// </summary>
        public void Add(RTPPacket current)
        {
            // 1. Rent a buffer from the shared memory pool for the payload.
            IMemoryOwner<byte> payloadOwner = MemoryPool<byte>.Shared.Rent(current.Payload.Length);

            // 2. Copy the ephemeral packet's data into our rented buffer.
            current.Payload.Span.CopyTo(payloadOwner.Memory.Span);

            // 3. Create a pooled packet that now owns the rented buffer.
            var safePacket = new PooledRtpPacket(current.Header, payloadOwner, current.Payload.Length);

            // From this point on, ONLY use 'safePacket'.
            if (_data.Count == 0)
            {
                _data.AddFirst(safePacket);
                return;
            }

            // if seq number is greater or equal than we are waiting for then append to last position
            if (_currentSeqNumber.HasValue && _currentSeqNumber >= safePacket.Header.SequenceNumber)
            {
                if (Last.Header.SequenceNumber > _currentSeqNumber || IsAfterWrapAround(Last) && IsBeforeWrapAround(_currentSeqNumber.Value))
                {
                    _data.AddLast(safePacket);
                    return;
                }
            }

            if (IsBeforeWrapAround(Last) && !IsAfterWrapAround(First) && IsAfterWrapAround(safePacket)) // first incoming packet after wraparound
            {
                _data.AddFirst(safePacket);
                return;
            }

            var node = _data.First;
            do
            {
                // if it is packet before wrap around skip all packets after wrap around and then insert the packet
                if (IsBeforeWrapAround(safePacket) && IsBeforeWrapAround(Last) && IsAfterWrapAround(node.Value))
                {
                    node = node.Next;
                    continue;
                }
                if (IsBeforeWrapAround(node.Value) && IsAfterWrapAround(safePacket))
                {
                    _data.AddBefore(node, safePacket);
                    return; // Return after adding
                }
                if (safePacket.Header.SequenceNumber > node.Value.Header.SequenceNumber)
                {
                    _data.AddBefore(node, safePacket);
                    return; // Return after adding
                }
                if (safePacket.Header.SequenceNumber == node.Value.Header.SequenceNumber)
                {
                    logger.LogInformation("Duplicate seq number: {SequenceNumber}", safePacket.Header.SequenceNumber);
                    // IMPORTANT: Dispose of the rented buffer to prevent a memory leak!
                    safePacket.Dispose();
                    return; // Return after handling duplicate
                }

                node = node.Next;
            }
            while (node != null);

            // Fallback case if no suitable position was found in the loop (e.g., smallest seq number).
            _data.AddLast(safePacket);
        }
    }

    // These interfaces remain unchanged.
    public interface IDateTime
    {
        DateTime Time { get; }
    }

    public class DefaultTimeProvider : IDateTime
    {
        public DateTime Time => DateTime.Now;
    }
}

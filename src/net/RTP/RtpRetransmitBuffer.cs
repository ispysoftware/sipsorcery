/*
 * Filename: RtpRetransmitBuffer.cs
 *
 * Description:
 *   Ring buffer of recently sent RTP packet payloads, used to answer RTCP
 *   Generic NACKs (RFC 4585) with same-SSRC retransmissions. Stores the
 *   PLAINTEXT payload plus the header fields needed to rebuild the packet;
 *   the resend goes back through the normal send path (with the original
 *   sequence number) so it is SRTP-protected fresh and picks up a new
 *   transport-wide-cc seqnum, keeping the bandwidth estimator honest.
 *
 *   SRTP rollover fencing: the sender-side SrtpCryptoContext encrypts with
 *   its CURRENT rollover counter (ROC) and increments it when seq 0xFFFF is
 *   sent. Re-protecting a packet from before the last ROC increment would
 *   use the wrong keystream (the receiver would fail auth and drop it), and
 *   re-sending seq 0xFFFF itself would increment the sender ROC a second
 *   time and desynchronise the entire stream. Entries therefore record a
 *   wrap "epoch" (bumped every time seq 0xFFFF is stored) and only
 *   current-epoch entries are eligible for retransmission — which also
 *   excludes 0xFFFF itself, since storing it is what ends its epoch.
 *
 * Author:        Sean Tearney
 * Date:          2026-07-18
 *
 * License:       BSD 3-Clause "New" or "Revised" License, see included LICENSE.md file.
 */

using System;
using System.Buffers;
using System.Diagnostics;

namespace SIPSorcery.net.RTP
{
    internal class RtpRetransmitBuffer : IDisposable
    {
        // 1024 slots ≈ 1-2s of video at typical packet rates; NACKs for anything
        // older are useless for real-time playout anyway.
        private const int CAPACITY = 1024;

        // Minimum interval between retransmissions of the same seqnum. Browsers
        // repeat NACKs every few tens of ms until the gap fills; without a floor
        // we'd send duplicate repairs for requests already in flight.
        private const long MIN_RESEND_INTERVAL_MS = 50;

        private struct Entry
        {
            public byte[] Payload;      // rented; null = slot empty
            public int Length;
            public ushort SequenceNumber;
            public uint Timestamp;
            public int MarkerBit;
            public int PayloadType;
            public long Epoch;
            public long LastResendTicks;
        }

        private readonly Entry[] _entries = new Entry[CAPACITY];
        private readonly object _lock = new object();
        private long _epoch;
        private bool _disposed;

        /// <summary>
        /// Records a just-sent packet. Called from the send path with the plaintext
        /// RTP payload (pre-SRTP). The payload is copied into a pooled buffer.
        /// </summary>
        public void Store(ushort seq, ReadOnlySpan<byte> payload, uint timestamp, int markerBit, int payloadType)
        {
            byte[] copy = ArrayPool<byte>.Shared.Rent(payload.Length);
            payload.CopyTo(copy);

            lock (_lock)
            {
                if (_disposed)
                {
                    ArrayPool<byte>.Shared.Return(copy);
                    return;
                }

                ref Entry slot = ref _entries[seq % CAPACITY];
                if (slot.Payload != null)
                {
                    ArrayPool<byte>.Shared.Return(slot.Payload);
                }

                slot.Payload = copy;
                slot.Length = payload.Length;
                slot.SequenceNumber = seq;
                slot.Timestamp = timestamp;
                slot.MarkerBit = markerBit;
                slot.PayloadType = payloadType;
                slot.Epoch = _epoch;
                slot.LastResendTicks = 0;

                // Sender SRTP ROC increments after seq 0xFFFF goes out — everything
                // stored so far (including 0xFFFF) is now unresendable. See header comment.
                if (seq == 0xFFFF)
                {
                    _epoch++;
                }
            }
        }

        /// <summary>
        /// Attempts to fetch a stored packet for retransmission. Returns a COPY of the
        /// payload in a pooled buffer (caller must return it to ArrayPool) so the slot
        /// can be overwritten by concurrent sends while the resend is in flight.
        /// Returns false if the seq is not buffered, is from a previous SRTP rollover
        /// epoch, or was resent too recently.
        /// </summary>
        public bool TryGetForResend(ushort seq, out byte[] payload, out int length, out uint timestamp, out int markerBit, out int payloadType)
        {
            payload = null;
            length = 0;
            timestamp = 0;
            markerBit = 0;
            payloadType = 0;

            lock (_lock)
            {
                if (_disposed)
                {
                    return false;
                }

                ref Entry slot = ref _entries[seq % CAPACITY];
                if (slot.Payload == null || slot.SequenceNumber != seq || slot.Epoch != _epoch)
                {
                    return false;
                }

                long now = Stopwatch.GetTimestamp();
                if (slot.LastResendTicks != 0 &&
                    (now - slot.LastResendTicks) * 1000 / Stopwatch.Frequency < MIN_RESEND_INTERVAL_MS)
                {
                    return false;
                }
                slot.LastResendTicks = now;

                payload = ArrayPool<byte>.Shared.Rent(slot.Length);
                slot.Payload.AsSpan(0, slot.Length).CopyTo(payload);
                length = slot.Length;
                timestamp = slot.Timestamp;
                markerBit = slot.MarkerBit;
                payloadType = slot.PayloadType;
                return true;
            }
        }

        public void Dispose()
        {
            lock (_lock)
            {
                if (_disposed)
                {
                    return;
                }
                _disposed = true;
                for (int i = 0; i < _entries.Length; i++)
                {
                    if (_entries[i].Payload != null)
                    {
                        ArrayPool<byte>.Shared.Return(_entries[i].Payload);
                        _entries[i].Payload = null;
                    }
                }
            }
        }
    }
}

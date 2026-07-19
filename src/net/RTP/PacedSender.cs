/*
 * Filename: PacedSender.cs
 *
 * Description:
 *   Budget-based packet pacer for outgoing video RTP, modelled on libwebrtc's
 *   PacedSender. Without pacing, a keyframe (tens to hundreds of KB) is
 *   packetized into 40-170 RTP packets and blasted at line rate in a
 *   millisecond-scale burst. Shallow bottleneck queues (mobile uplinks,
 *   Wi-Fi buffers) overflow on the burst, dropping the TAIL OF THE KEYFRAME
 *   ITSELF and spiking jitter — the congestion controller then reads the
 *   self-inflicted loss as network congestion and cuts the bitrate, worst
 *   exactly at PLI-recovery time. Pacing spreads the burst: packets enqueue
 *   here and drain on a byte budget refilled at PACING_FACTOR × the target
 *   bitrate (with a catch-up boost that bounds queue delay), so a 100KB
 *   keyframe leaves over ~100ms instead of ~2ms.
 *
 *   The pacer is BYPASSED until a target bitrate is set (SetTargetBitrate),
 *   so behavior is unchanged for sessions with no bandwidth estimator, and
 *   audio/RTCP never route through it (tiny, timing-sensitive packets gain
 *   nothing from pacing).
 *
 * Author:        Sean Tearney
 * Date:          2026-07-18
 *
 * License:       BSD 3-Clause "New" or "Revised" License, see included LICENSE.md file.
 */

using System;
using System.Buffers;
using System.Diagnostics;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SIPSorcery.Sys;

namespace SIPSorcery.net.RTP
{
    internal class PacedSender : IDisposable
    {
        private static ILogger logger = Log.Logger;

        // Standard libwebrtc pacing multiple: drain at 2.5× the media rate so the
        // queue empties comfortably faster than it fills, without re-creating the
        // original burst.
        private const double PACING_FACTOR = 2.5;

        // Never let queued data represent more than this much wall-clock delay —
        // the accrual rate is boosted to drain the queue within this window, so a
        // keyframe adds bounded latency rather than smooth-but-late video.
        private const double MAX_QUEUE_DELAY_SECONDS = 0.25;

        // Budget accrues while the drain loop sleeps; cap the carry-over so an idle
        // period can't bank enough budget to reproduce an unpaced burst.
        private const double MAX_BUDGET_WINDOW_SECONDS = 0.040;

        // Approximate per-packet overhead on the wire (IP + UDP + SRTP auth).
        private const int PACKET_OVERHEAD_BYTES = 48;

        private const int QUEUE_CAPACITY = 4096;
        private const int DRAIN_INTERVAL_MS = 5;

        internal readonly struct PacedPacket
        {
            public readonly byte[] Payload;   // rented from ArrayPool
            public readonly int Length;
            public readonly uint Timestamp;
            public readonly int MarkerBit;
            public readonly int PayloadType;

            public PacedPacket(byte[] payload, int length, uint timestamp, int markerBit, int payloadType)
            {
                Payload = payload;
                Length = length;
                Timestamp = timestamp;
                MarkerBit = markerBit;
                PayloadType = payloadType;
            }
        }

        private readonly Channel<PacedPacket> _queue = Channel.CreateBounded<PacedPacket>(
            new BoundedChannelOptions(QUEUE_CAPACITY)
            {
                FullMode = BoundedChannelFullMode.Wait, // full ⇒ TryWrite fails; handled at enqueue
                SingleReader = true,
                SingleWriter = false
            });

        private readonly Func<PacedPacket, Task> _sendNow;
        private readonly CancellationTokenSource _cts = new CancellationTokenSource();

        private Task _drainTask;
        private readonly object _startLock = new object();

        private long _queuedBytes;
        private double _paceBytesPerSecond; // 0 = bypass
        private long _dropLogTicks;
        private int _droppedSinceLog;
        private volatile bool _flushRequested;

        public PacedSender(Func<PacedPacket, Task> sendNow)
        {
            _sendNow = sendNow;
        }

        /// <summary>
        /// True once a target bitrate has been supplied; until then callers should
        /// send directly and skip the pacer entirely.
        /// </summary>
        public bool IsEnabled => Volatile.Read(ref _paceBytesPerSecond) > 0;

        /// <summary>
        /// Approximate wall-clock delay the current queue represents at the
        /// configured pacing rate. The application can use this as a send-backlog
        /// signal to skip encoding frames while the link is congested.
        /// </summary>
        public double QueuedMilliseconds
        {
            get
            {
                double rate = Volatile.Read(ref _paceBytesPerSecond);
                if (rate <= 0)
                {
                    return 0;
                }
                return Interlocked.Read(ref _queuedBytes) * 1000.0 / rate;
            }
        }

        /// <summary>
        /// Sets the media target bitrate (bits/sec). The pacer drains at
        /// PACING_FACTOR times this. Zero or negative disables pacing (bypass).
        /// </summary>
        public void SetTargetBitrate(int bitsPerSecond)
        {
            Volatile.Write(ref _paceBytesPerSecond, bitsPerSecond > 0 ? bitsPerSecond * PACING_FACTOR / 8.0 : 0);

            if (IsEnabled && _drainTask == null)
            {
                lock (_startLock)
                {
                    _drainTask ??= Task.Run(DrainLoopAsync);
                }
            }
        }

        /// <summary>
        /// Drops everything currently queued. Used on stream swaps (e.g. live view
        /// changes) so the tail of the previous stream's video — up to
        /// MAX_QUEUE_DELAY_SECONDS of it — can't drain onto the wire after the
        /// application has already switched content and acknowledged the swap.
        /// Sequence numbers are assigned at send time, not enqueue time, so
        /// dropping queued packets creates no RTP sequence gap; the receiver just
        /// never completes the in-flight frame and recovers on the next keyframe.
        /// The actual drop happens on the drain loop's next tick (≤5ms) because it
        /// is the channel's single reader.
        /// </summary>
        public void Clear()
        {
            _flushRequested = true;
        }

        /// <summary>
        /// Queues a packet for paced sending. The payload is copied into a pooled
        /// buffer, so the caller's memory can be reused immediately. Returns false
        /// if the pacer is disabled or the queue is full (caller sends inline /
        /// treats as dropped respectively — a full queue at 4096 packets means the
        /// link is catastrophically behind and dropping is the right call).
        /// </summary>
        public bool TryEnqueue(ReadOnlySpan<byte> payload, uint timestamp, int markerBit, int payloadType)
        {
            if (!IsEnabled || _cts.IsCancellationRequested)
            {
                return false;
            }

            byte[] copy = ArrayPool<byte>.Shared.Rent(payload.Length);
            payload.CopyTo(copy);

            if (_queue.Writer.TryWrite(new PacedPacket(copy, payload.Length, timestamp, markerBit, payloadType)))
            {
                Interlocked.Add(ref _queuedBytes, payload.Length);
                return true;
            }

            // Queue full — shed rather than block the encode path.
            ArrayPool<byte>.Shared.Return(copy);
            _droppedSinceLog++;
            long now = Stopwatch.GetTimestamp();
            if (now - _dropLogTicks >= Stopwatch.Frequency * 5)
            {
                _dropLogTicks = now;
                logger.LogWarning($"Paced sender queue full — dropped {_droppedSinceLog} packet(s); the send path is far behind the encoder.");
                _droppedSinceLog = 0;
            }
            return true; // handled (shed); do not double-send inline
        }

        private async Task DrainLoopAsync()
        {
            var token = _cts.Token;
            double budgetBytes = 0;
            long lastTicks = Stopwatch.GetTimestamp();

            try
            {
                using var timer = new PeriodicTimer(TimeSpan.FromMilliseconds(DRAIN_INTERVAL_MS));
                while (await timer.WaitForNextTickAsync(token).ConfigureAwait(false))
                {
                    long now = Stopwatch.GetTimestamp();
                    double elapsedSec = (double)(now - lastTicks) / Stopwatch.Frequency;
                    lastTicks = now;

                    if (_flushRequested)
                    {
                        _flushRequested = false;
                        while (_queue.Reader.TryRead(out var dropPkt))
                        {
                            Interlocked.Add(ref _queuedBytes, -dropPkt.Length);
                            ArrayPool<byte>.Shared.Return(dropPkt.Payload);
                        }
                        budgetBytes = 0;
                        continue;
                    }

                    double rate = Volatile.Read(ref _paceBytesPerSecond);
                    if (rate <= 0)
                    {
                        // Pacing turned off mid-flight: flush whatever is queued.
                        while (_queue.Reader.TryRead(out var flushPkt))
                        {
                            Interlocked.Add(ref _queuedBytes, -flushPkt.Length);
                            await SendAndReturnAsync(flushPkt).ConfigureAwait(false);
                        }
                        budgetBytes = 0;
                        continue;
                    }

                    // Catch-up boost: never let the queue represent more than
                    // MAX_QUEUE_DELAY_SECONDS of latency at the effective rate.
                    long queued = Interlocked.Read(ref _queuedBytes);
                    double effectiveRate = Math.Max(rate, queued / MAX_QUEUE_DELAY_SECONDS);

                    budgetBytes = Math.Min(budgetBytes + effectiveRate * elapsedSec, effectiveRate * MAX_BUDGET_WINDOW_SECONDS);

                    while (budgetBytes > 0 && _queue.Reader.TryRead(out var pkt))
                    {
                        Interlocked.Add(ref _queuedBytes, -pkt.Length);
                        budgetBytes -= pkt.Length + PACKET_OVERHEAD_BYTES;
                        await SendAndReturnAsync(pkt).ConfigureAwait(false);
                    }
                }
            }
            catch (OperationCanceledException)
            {
                // Normal shutdown.
            }
            catch (Exception excp)
            {
                logger.LogError(excp, "PacedSender drain loop exited with exception.");
            }
            finally
            {
                // Return anything still queued to the pool.
                while (_queue.Reader.TryRead(out var pkt))
                {
                    ArrayPool<byte>.Shared.Return(pkt.Payload);
                }
            }
        }

        private async Task SendAndReturnAsync(PacedPacket pkt)
        {
            try
            {
                await _sendNow(pkt).ConfigureAwait(false);
            }
            catch (Exception excp)
            {
                logger.LogWarning(excp, "PacedSender send failed.");
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(pkt.Payload);
            }
        }

        public void Dispose()
        {
            _cts.Cancel();
            _queue.Writer.TryComplete();
            _cts.Dispose();
        }
    }
}

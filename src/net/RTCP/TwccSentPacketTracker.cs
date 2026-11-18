/*
* Filename: TwccSentPacketTracker.cs
*
* Description:
*   Tracks the wire-send timestamp for each TWCC-tagged outgoing RTP packet so a
*   send-side bandwidth estimator can correlate browser-reported TWCC feedback
*   against the actual moment each packet was put on the wire.
*
*   Needed for any delay-gradient based bandwidth estimator (the standard WebRTC
*   GCC approach):
*       send_delta_us  = sendTime[N] - sendTime[N-1]      (this tracker, sender clock)
*       recv_delta_us  = packet.Delta                     (TWCC feedback, receiver clock)
*       delay_change   = recv_delta_us - send_delta_us    (clock-domain-independent)
*
*   The clock-domain subtraction property means we do NOT need clock sync between
*   sender and receiver — any constant offset between the two clocks cancels in
*   the per-packet delta computation. We only require that each clock be monotonic.
*   Stopwatch.GetTimestamp() on the sender side gives us that on every supported
*   .NET platform.
*
* Author:    Sean Tearney
* License:   BSD 3-Clause "New" or "Revised" License.
*/

using System;
using System.Threading;

namespace SIPSorcery.Net
{
    /// <summary>
    /// Maintains a seqnum → send-time map for outgoing TWCC-tagged RTP packets.
    /// One instance per MediaStream (matches how sipsorcery assigns TWCC seqnums,
    /// which is per-stream rather than truly transport-wide).
    /// </summary>
    /// <remarks>
    /// A ring of the most recent <see cref="WINDOW"/> seqnums, indexed by the low bits of the
    /// seqnum. Each slot remembers which seqnum it holds, so a lookup for a seqnum that has since
    /// been overwritten (more than a window old) misses rather than returning another packet's
    /// time. No background cleanup needed.
    ///
    /// The caller should still reject an implausibly old timestamp: on a stream that has stopped
    /// sending, a slot keeps its last entry until the seqnums come round to it again.
    /// </remarks>
    public sealed class TwccSentPacketTracker
    {
        // 8192 seqnums is 16 seconds of video at 500 packets a second; feedback arrives within a
        // second or so of the send. Was one slot per 16-bit seqnum: a 512 KB array on the large
        // object heap for every stream of every peer connection, the audio stream's never written
        // to. The two arrays here are 64 KB and 16 KB, under the large object threshold, and are
        // not allocated until the stream sends its first TWCC-tagged packet.
        private const int WINDOW = 8192; // power of two
        private const int WINDOW_MASK = WINDOW - 1;

        // 0 in _sendTimes marks an empty slot: Stopwatch timestamps are never 0 in practice.
        private long[] _sendTimes;
        private ushort[] _seqnums;
        private int _count;

        /// <summary>
        /// Record the wire-send time for an outgoing TWCC seqnum. Call this from
        /// the RTP send path immediately after stamping the packet with its seqnum.
        /// Calls must not overlap (the send path makes them under the stream's send lock).
        /// </summary>
        /// <param name="sequenceNumber">TWCC sequence number stamped on the packet.</param>
        /// <param name="sendTimeTicks">Monotonic timestamp, typically Stopwatch.GetTimestamp().</param>
        public void RecordSend(ushort sequenceNumber, long sendTimeTicks)
        {
            var sendTimes = _sendTimes;
            if (sendTimes == null)
            {
                // The seqnum array first: a reader takes _sendTimes being set to mean both are there.
                Volatile.Write(ref _seqnums, new ushort[WINDOW]);
                sendTimes = new long[WINDOW];
                Volatile.Write(ref _sendTimes, sendTimes);
            }

            int index = sequenceNumber & WINDOW_MASK;
            if (Volatile.Read(ref sendTimes[index]) == 0)
            {
                Interlocked.Increment(ref _count);
            }

            // Seqnum before time, and the reader takes them in the opposite order: it can then never
            // pair this packet's time with the seqnum the slot held before.
            Volatile.Write(ref _seqnums[index], sequenceNumber);
            Volatile.Write(ref sendTimes[index], sendTimeTicks);
        }

        /// <summary>
        /// Look up the previously-recorded send time for a seqnum.
        /// </summary>
        /// <param name="sendTimeTicks">Send time in Stopwatch ticks if found, 0 otherwise.</param>
        /// <returns>True if a send time is held for this seqnum (the caller should still
        /// reject a timestamp that is implausibly old).</returns>
        public bool TryGetSendTime(ushort sequenceNumber, out long sendTimeTicks)
        {
            var sendTimes = Volatile.Read(ref _sendTimes);
            if (sendTimes != null)
            {
                int index = sequenceNumber & WINDOW_MASK;
                long ticks = Volatile.Read(ref sendTimes[index]);
                if (ticks != 0 && Volatile.Read(ref _seqnums[index]) == sequenceNumber)
                {
                    sendTimeTicks = ticks;
                    return true;
                }
            }

            sendTimeTicks = 0;
            return false;
        }

        /// <summary>
        /// Drop all recorded entries. Call this when the session restarts so the
        /// new session's seqnums don't accidentally match stale times from the old.
        /// </summary>
        public void Reset()
        {
            var sendTimes = Volatile.Read(ref _sendTimes);
            if (sendTimes != null)
            {
                Array.Clear(sendTimes);
            }
            Volatile.Write(ref _count, 0);
        }

        /// <summary>
        /// Number of recorded entries. For diagnostics.
        /// </summary>
        public int Count => Volatile.Read(ref _count);
    }
}

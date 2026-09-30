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
    /// One slot per 16-bit TWCC seqnum. New writes overwrite the slot at the same
    /// seqnum, so old entries are recycled automatically when seqnums wrap. No
    /// background cleanup needed.
    ///
    /// Lookup-time staleness checking is the CALLER'S responsibility — typically
    /// the bandwidth estimator discards entries older than the TWCC feedback
    /// window (~1 second). Stale entries from a previous seqnum wrap will return
    /// `true` with a timestamp from minutes ago; the caller should compare against
    /// "now" and reject anything implausibly old.
    /// </remarks>
    public sealed class TwccSentPacketTracker
    {
        // Flat array indexed by seqnum (512 KB, one allocation per stream). Replaced a
        // ConcurrentDictionary<ushort,long> that allocated a node per seqnum until all 65536
        // existed (~1 minute of video), then held those ~3 MB of small objects in Gen2 for the
        // life of every peer connection - GC mark work for a lookup table - and hashed + locked
        // on every packet. 0 marks an empty slot: Stopwatch timestamps are never 0 in practice.
        // Volatile read/write keeps each long atomic on 32-bit ARM too.
        private readonly long[] _sendTimes = new long[ushort.MaxValue + 1];
        private int _count;

        /// <summary>
        /// Record the wire-send time for an outgoing TWCC seqnum. Call this from
        /// the RTP send path immediately after stamping the packet with its seqnum.
        /// </summary>
        /// <param name="sequenceNumber">TWCC sequence number stamped on the packet.</param>
        /// <param name="sendTimeTicks">Monotonic timestamp, typically Stopwatch.GetTimestamp().</param>
        public void RecordSend(ushort sequenceNumber, long sendTimeTicks)
        {
            ref long slot = ref _sendTimes[sequenceNumber];
            if (Volatile.Read(ref slot) == 0)
            {
                Interlocked.Increment(ref _count);
            }
            Volatile.Write(ref slot, sendTimeTicks);
        }

        /// <summary>
        /// Look up the previously-recorded send time for a seqnum.
        /// </summary>
        /// <param name="sendTimeTicks">Send time in Stopwatch ticks if found, 0 otherwise.</param>
        /// <returns>True if a send time was recorded for this seqnum (caller should still
        /// validate the timestamp isn't from a stale pre-wrap entry).</returns>
        public bool TryGetSendTime(ushort sequenceNumber, out long sendTimeTicks)
        {
            sendTimeTicks = Volatile.Read(ref _sendTimes[sequenceNumber]);
            return sendTimeTicks != 0;
        }

        /// <summary>
        /// Drop all recorded entries. Call this when the session restarts so the
        /// new session's seqnums don't accidentally match stale times from the old.
        /// </summary>
        public void Reset()
        {
            Array.Clear(_sendTimes);
            Volatile.Write(ref _count, 0);
        }

        /// <summary>
        /// Number of recorded entries. For diagnostics.
        /// </summary>
        public int Count => Volatile.Read(ref _count);
    }
}

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

using System.Collections.Concurrent;

namespace SIPSorcery.Net
{
    /// <summary>
    /// Maintains a seqnum → send-time map for outgoing TWCC-tagged RTP packets.
    /// One instance per MediaStream (matches how sipsorcery assigns TWCC seqnums,
    /// which is per-stream rather than truly transport-wide).
    /// </summary>
    /// <remarks>
    /// Memory is bounded by the 16-bit TWCC seqnum space: at most 65536 entries
    /// once every seqnum has been seen (typically ~3.5 minutes at 300 packets/sec).
    /// New writes overwrite the entry at the same seqnum slot, so old entries are
    /// recycled automatically when seqnums wrap. No background cleanup needed.
    ///
    /// Lookup-time staleness checking is the CALLER'S responsibility — typically
    /// the bandwidth estimator discards entries older than the TWCC feedback
    /// window (~1 second). Stale entries from a previous seqnum wrap will return
    /// `true` with a timestamp from minutes ago; the caller should compare against
    /// "now" and reject anything implausibly old.
    /// </remarks>
    public sealed class TwccSentPacketTracker
    {
        // ConcurrentDictionary is fine here: write volume is ~300/sec (one per
        // outgoing RTP packet at 30fps × ~10 packets/frame), read volume is
        // ~50-100/sec (one lookup per TWCC-acked packet). No contention concern.
        // Memory cap is ~3 MB at full population (65K entries × ~50 bytes/entry).
        private readonly ConcurrentDictionary<ushort, long> _sendTimes = new ConcurrentDictionary<ushort, long>();

        /// <summary>
        /// Record the wire-send time for an outgoing TWCC seqnum. Call this from
        /// the RTP send path immediately after stamping the packet with its seqnum.
        /// </summary>
        /// <param name="sequenceNumber">TWCC sequence number stamped on the packet.</param>
        /// <param name="sendTimeTicks">Monotonic timestamp, typically Stopwatch.GetTimestamp().</param>
        public void RecordSend(ushort sequenceNumber, long sendTimeTicks)
        {
            // Indexer = AddOrUpdate semantics. Faster than .AddOrUpdate(seq, t, (_, _) => t)
            // and we don't care about the previous value if a wrap caused a collision.
            _sendTimes[sequenceNumber] = sendTimeTicks;
        }

        /// <summary>
        /// Look up the previously-recorded send time for a seqnum.
        /// </summary>
        /// <param name="sendTimeTicks">Send time in Stopwatch ticks if found, 0 otherwise.</param>
        /// <returns>True if a send time was recorded for this seqnum (caller should still
        /// validate the timestamp isn't from a stale pre-wrap entry).</returns>
        public bool TryGetSendTime(ushort sequenceNumber, out long sendTimeTicks)
        {
            return _sendTimes.TryGetValue(sequenceNumber, out sendTimeTicks);
        }

        /// <summary>
        /// Drop all recorded entries. Call this when the session restarts so the
        /// new session's seqnums don't accidentally match stale times from the old.
        /// </summary>
        public void Reset()
        {
            _sendTimes.Clear();
        }

        /// <summary>
        /// Number of recorded entries. For diagnostics.
        /// </summary>
        public int Count => _sendTimes.Count;
    }
}

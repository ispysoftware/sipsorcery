//-----------------------------------------------------------------------------
// Filename: SctpDataSender.cs
//
// Description: This class manages sending data chunks to an association's
// remote peer.
//
// Remarks: Most of the logic for this class is specified in
// https://tools.ietf.org/html/rfc4960#section-6.1.
//
// Author(s):
// Aaron Clauson (aaron@sipsorcery.com)
// 
// History:
// Easter Sunday 2021	Aaron Clauson	Created, Dublin, Ireland.
//
// License: 
// BSD 3-Clause "New" or "Revised" License, see included LICENSE.md file.
//-----------------------------------------------------------------------------

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.ObjectPool;
using SIPSorcery.Sys;

namespace SIPSorcery.Net
{
    public class SctpDataSender
    {
        public const ushort DEFAULT_SCTP_MTU = 1300;

        /// <summary>
        /// The initial congestion window, in MTUs. RFC 9260 7.2.1 gives min(4 * MTU, max(2 * MTU, 4404)),
        /// about 3 packets, which made the first data channel responses on a long round trip (a TURN relay
        /// far from both peers, ~0.75s) arrive at ~16KB per round trip: a 77KB object list took 5 round
        /// trips. 10 MTUs is TCP's initial window (RFC 6928) and what browsers' SCTP starts with.
        /// </summary>
        public const int INITIAL_CONGESTION_WINDOW_MTUS = 10;

        /// <summary>
        /// Used to limit the number of packets that are sent at any one time, i.e. when 
        /// the transmit timer fires do not send more than this many packets.
        /// </summary>
        public const int MAX_BURST = 8;

        /// <summary>
        /// Milliseconds to wait between bursts if no SACK chunks are received in the interim.
        /// Eventually if no SACK chunks are received the congestion or receiver windows
        /// will reach zero and enforce a longer period.
        /// </summary>
        public const int BURST_PERIOD_MILLISECONDS = 5;

        /// <summary>
        /// Retransmission timeout initial value, used until the first round trip time measurement
        /// (RFC 4960 15: 3 seconds). It was 200ms, which is no more than a browser's delayed SACK and far
        /// below the round trip of a relayed connection (~770ms via a distant TURN server): everything
        /// sent before the first measurement was retransmitted before its SACK could arrive. Retransmitted
        /// chunks give no measurement, and each timeout cut the congestion window back to its floor, so a
        /// 78KB response took 4 to 7 round trips instead of 2 or 3.
        /// </summary>
        public const int RTO_INITIAL_MILLISECONDS = 3000;

        /// <summary>
        /// The minimum value for the Retransmission timeout.
        /// </summary>
        public const int RTO_MIN_MILLISECONDS = 500;

        /// <summary>
        /// The maximum value for the Retransmission timeout.
        /// </summary>
        public const int RTO_MAX_MILLISECONDS = 20000;

        /// <summary>
        /// The maximum time Close waits for the send thread to exit. If it has not exited by then
        /// the send thread releases the queued chunks itself when it does.
        /// </summary>
        private const int CLOSE_JOIN_TIMEOUT_MILLISECONDS = 2000;

        private static ILogger logger = LogFactory.CreateLogger<SctpDataSender>();

        /// <summary>
        /// Callback method that sends data chunks.
        /// </summary>
        internal Action<SctpDataChunk> _sendDataChunk;

        private string _associationID;
        private ushort _defaultMTU;
        private uint _initialTSN;
        private bool _isStarted;
        private Once _closed;
        private Once _resourcesReleased;
        private Thread _sendThread;
        /// <summary>
        /// The user data bytes the SACK being processed has acknowledged (removed from the unconfirmed
        /// chunks). Only ever accessed inside <see cref="GotSack(SctpChunkView)"/>.
        /// </summary>
        private uint _bytesAckedBySack;
        /// <summary>
        /// RFC 9260 7.2.2 partial_bytes_acked: the bytes acknowledged in congestion avoidance since the
        /// congestion window was last increased.
        /// </summary>
        private uint _partialBytesAcked;
        private OnOff _inFastRecoveryMode;
        /// <summary>Only ever accessed inside <see cref="GotSack(SctpChunkView)"/></summary>
        private uint _fastRecoveryExitPoint;

        /// <summary>
        /// The TSN of the newest DATA chunk put on the wire. Written by the send thread, read when
        /// a SACK starts fast recovery.
        /// </summary>
        private volatile uint _highestSentTSN;

        /// <summary>
        /// Guards the congestion and retransmission state shared by the send thread (choosing what to
        /// send) and the thread delivering SACKs. Never held while a chunk is handed to the transport.
        /// </summary>
        private readonly Lock _stateLock = new Lock();

        /// <summary>
        /// User data bytes in flight: sent, not acknowledged and not marked for retransmission by a
        /// timeout. Written under <see cref="_stateLock"/>.
        /// </summary>
        private long _flightBytes;

        /// <summary>User data bytes queued by the application and not yet sent.</summary>
        private long _bufferedBytes;

        /// <summary>
        /// The unconfirmed chunks a timeout has marked for retransmission and that have not been resent
        /// or acknowledged since. Written under <see cref="_stateLock"/>.
        /// </summary>
        private int _retransmitPendingCount;

        /// <summary>
        /// When the T3-rtx timer was last started, as a Stopwatch timestamp. 0 when it is not running.
        /// Written under <see cref="_stateLock"/>.
        /// </summary>
        private long _t3StartedAt;

        /// <summary>
        /// How many times the RTO has been doubled by a timeout since the last round trip measurement.
        /// Written under <see cref="_stateLock"/>.
        /// </summary>
        private int _rtoBackoffShift;

        /// <summary>More doublings than this can't matter: the RTO is capped at its maximum first.</summary>
        private const int MAX_RTO_BACKOFF_SHIFT = 16;

        /// <summary>
        /// The most TSNs walked in order when looking for chunks to retransmit, far more than a
        /// congestion window can hold.
        /// </summary>
        private const uint MAX_RETRANSMIT_SCAN = 1 << 18;

        /// <summary>Acknowledged chunks waiting for the send thread to return them to the pool.</summary>
        private readonly ConcurrentQueue<SctpDataChunk> _ackedChunks = new ConcurrentQueue<SctpDataChunk>();

        /// <summary>The chunks chosen for the current pass. Send thread only.</summary>
        private readonly List<SctpDataChunk> _sendBatch = new List<SctpDataChunk>(MAX_BURST);

        private long _lastSendErrorLogAt = -1000;

        private ManualResetEventSlim _senderMre = new ManualResetEventSlim();

        /// <summary>
        /// Used to synchronise access to the send queue and stream sequence number logic.
        /// </summary>
        private readonly Lock _sendLock = new Lock();

        /// <summary>
        /// Cancellation token source to gracefully shut down the sender, especially unblocking
        /// any threads waiting to add to the send queue.
        /// </summary>
        private readonly CancellationTokenSource _closeCts = new CancellationTokenSource();

        /// <summary>
        /// Congestion control window (cwnd, in bytes), which is adjusted by
        /// the sender based on observed network conditions.
        /// </summary>
        internal uint _congestionWindow;

        /// <summary>
        /// The current Advertised Receiver Window Credit for the remote peer.
        /// This value represents the dedicated  buffer space on the remote peer, 
        /// in number of bytes, that will be used for the receive buffer for DATA 
        /// chunks sent to it.
        /// </summary>
        internal uint _receiverWindow;

        /// <summary>
        /// Slow-start threshold (ssthresh, in bytes), which is used by the
        /// sender to distinguish slow-start and congestion avoidance phases.
        /// </summary>
        private uint _slowStartThreshold;


        internal int _burstPeriodMilliseconds = BURST_PERIOD_MILLISECONDS;
        /// <summary>
        /// Retransmission timeout. 
        /// See https://datatracker.ietf.org/doc/html/rfc4960#section-6.3.1
        /// </summary>
        internal double _rto = RTO_INITIAL_MILLISECONDS;
        internal int _rtoInitialMilliseconds = RTO_INITIAL_MILLISECONDS;
        internal int _rtoMinimumMilliseconds = RTO_MIN_MILLISECONDS;
        internal int _rtoMaximumMilliseconds = RTO_MAX_MILLISECONDS;
        private bool _hasRoundTripTime;
        private double _smoothedRoundTripTime; // "SRTT"
        private double _roundTripTimeVariation; // "RTTVAR"
        private double _rtoAlpha = 0.125; // Suggested value in rfc4960#section-15
        private double _rtoBeta = 0.25; // Suggested value in rfc4960#section-15

        /// <summary>
        /// A count of the bytes currently in-flight to the remote peer.
        /// </summary>
        internal int _outstandingBytes => (int)Math.Max(0L, Volatile.Read(ref _flightBytes));

        /// <summary>
        /// The TSN that the remote peer has acknowledged. Starts one behind the initial TSN, i.e. nothing
        /// acknowledged. Accessed under <see cref="_stateLock"/>.
        /// </summary>
        private uint _cumulativeAckTSN;

        /// <summary>
        /// Keeps track of the sequence numbers for each of the streams being
        /// used by the association.
        /// </summary>
        private Dictionary<ushort, ushort> _streamSeqnums = new Dictionary<ushort, ushort>();

        //public int MaxSendQueueCount => 1280;

        /// <summary>
        /// Queue to hold SCTP frames that are waiting to be sent to the remote peer.
        /// Using a BlockingCollection provides a bounded queue to create backpressure
        /// if the consumer cannot keep up.
        /// </summary>
        private BlockingCollection<SctpDataChunk> _sendQueue;

        /// <summary>
        /// Chunks that have been sent to the remote peer but have yet to be acknowledged.
        /// </summary>
        private ConcurrentDictionary<uint, SctpDataChunk> _unconfirmedChunks = new ConcurrentDictionary<uint, SctpDataChunk>();

        /// <summary>
        /// Chunks that have been flagged by a gap report from the remote peer as missing
        /// and that need to be re-sent.
        /// </summary>
        internal ConcurrentDictionary<uint, int> _missingChunks = new ConcurrentDictionary<uint, int>();

        /// <summary>
        /// The total size (in bytes) of queued user data that will be sent to the peer.
        /// </summary>
        public ulong BufferedAmount => (ulong)Math.Max(0L, Interlocked.Read(ref _bufferedBytes));

        int tsn;
        /// <summary>
        /// The Transaction Sequence Number (TSN) that will be used in the next DATA chunk sent.
        /// </summary>
        public uint TSN => unchecked((uint)Interlocked.CompareExchange(ref tsn, 0, 0));

        public SctpDataSender(
            string associationID,
            Action<SctpDataChunk> sendDataChunk,
            ushort defaultMTU,
            uint initialTSN,
            uint remoteARwnd)
        {
            _associationID = associationID;
            _sendDataChunk = sendDataChunk;
            _defaultMTU = defaultMTU > 0 ? defaultMTU : DEFAULT_SCTP_MTU;
            _initialTSN = initialTSN;
            tsn = unchecked((int)initialTSN);
            _cumulativeAckTSN = unchecked(initialTSN - 1);
            _highestSentTSN = unchecked(initialTSN - 1);
            _sendQueue = new BlockingCollection<SctpDataChunk>();

            // Larger than RFC4960 7.2.1 (point 1) allows, see INITIAL_CONGESTION_WINDOW_MTUS.
            _congestionWindow = (uint)(INITIAL_CONGESTION_WINDOW_MTUS * _defaultMTU);

            // RFC4960 7.2.1 (point 3)
            _receiverWindow = _slowStartThreshold = remoteARwnd;
        }

        public void SetReceiverWindow(uint remoteARwnd)
        {
            _receiverWindow = _slowStartThreshold = remoteARwnd;
        }

        /// <summary>
        /// Handler for SACK chunks received from the remote peer.
        /// </summary>
        /// <param name="sack">The SACK chunk from the remote peer.</param>
        public void GotSack(SctpChunkView sack)
        {
            using (_stateLock.EnterScope())
            {
                ProcessSack(sack);
            }

            // SACK's will normally allow more data to be sent.
            _senderMre.Set();
        }

        /// <summary>
        /// Applies a SACK to the sender state. Must be called with <see cref="_stateLock"/> held.
        /// </summary>
        private void ProcessSack(SctpChunkView sack)
        {
            _bytesAckedBySack = 0;
            uint cumulativeAckBeforeSack = _cumulativeAckTSN;

            unchecked
            {
                uint maxTSNDistance = SctpDataReceiver.GetDistance(_cumulativeAckTSN, TSN);
                bool processGapReports = true;
                uint cumAckTSNBeforeSackProcessing = _cumulativeAckTSN;

                if (_unconfirmedChunks.TryGetValue(sack.CumulativeTsnAck, out var result))
                {
                    // Don't include retransmits in round trip calculation
                    if (result.SendCount == 1)
                    {
                        UpdateRoundTripTime(result);
                    }
                }

                // The first SACK needs no special case: the cumulative ack starts one behind the initial
                // TSN. It used to be accepted only if it acknowledged the initial TSN or later, so when
                // the very first chunk was lost the peer's SACKs (cumulative ack still one behind, gap
                // reports for what did arrive) were dropped and the gap reports resolved against TSN 0:
                // no fast retransmit, and the chunk waited out the 3 second initial timeout.
                {
                    if (_cumulativeAckTSN != sack.CumulativeTsnAck)
                    {
                        if (SctpDataReceiver.GetDistance(_cumulativeAckTSN, sack.CumulativeTsnAck) > maxTSNDistance)
                        {
                            logger.LogWarning("SCTP SACK TSN from remote peer of {PeerCumulativeTsnAck} was too distant from the expected {ExpectedCumulativeAckTSN}, ignoring.",
                                sack.CumulativeTsnAck, _cumulativeAckTSN);
                            processGapReports = false;
                        }
                        else if (!SctpDataReceiver.IsNewer(_cumulativeAckTSN, sack.CumulativeTsnAck))
                        {
                            logger.LogWarning("SCTP SACK TSN from remote peer of {PeerCumulativeTsnAck} was behind expected {ExpectedCumulativeAckTSN}, ignoring.",
                                sack.CumulativeTsnAck, _cumulativeAckTSN);
                            processGapReports = false;
                        }
                        else
                        {
                            logger.LogTrace("SCTP SACK remote peer TSN ACK {CumulativeTsnAck}, next sender TSN {TSN}, arwnd {ARwnd} (gap reports {NumGapAckBlocks}).",
                                sack.CumulativeTsnAck, TSN, sack.ARwnd, sack.NumGapAckBlocks);
                            RemoveAckedUnconfirmedChunks(sack.CumulativeTsnAck);
                        }
                    }
                    else
                    {
                        logger.LogTrace("SCTP SACK remote peer TSN ACK no change {CumulativeAckTSN}, next sender TSN {TSN}, arwnd {ARwnd} (gap reports {NumGapAckBlocks}).",
                            _cumulativeAckTSN, TSN, sack.ARwnd, sack.NumGapAckBlocks);
                        RemoveAckedUnconfirmedChunks(sack.CumulativeTsnAck);
                    }
                }

                if (sack.NumDuplicateTSNs > 0)
                {
                    // The remote is reporting that we have sent a duplicate TSN. 
                    // This is probably because a SACK chunk was dropped. 
                    // Ensure that we stop sending the duplicate.
                    for (int tsnIndex = 0; tsnIndex < sack.NumDuplicateTSNs; tsnIndex++)
                    {
                        uint duplicateTSN = sack.GetDuplicateTSN(tsnIndex);
                        RemoveUnconfirmedChunk(duplicateTSN);
                        _missingChunks.TryRemove(duplicateTSN, out _);
                    }
                }


                // Check gap reports. Only process them if the cumulative ACK TSN was acceptable.
                if (processGapReports && sack.NumGapAckBlocks > 0)
                {
                    bool didIncrementCumAckTSN = SctpDataReceiver.IsNewer(cumAckTSNBeforeSackProcessing, _cumulativeAckTSN);
                    ProcessGapReports(sack.GapAckBlocks, maxTSNDistance, didIncrementCumAckTSN);
                }

                // rfc4960 6.2.1 D iv
                // If the Cumulative TSN Ack matches or exceeds the Fast Recovery exitpoint(Section 7.2.4), Fast Recovery is exited.
                if (SctpDataReceiver.IsNewerOrEqual(_fastRecoveryExitPoint, _cumulativeAckTSN) && _inFastRecoveryMode.TryTurnOff())
                {
                    logger.LogTrace("SCTP sender exiting fast recovery at TSN {TSN}", _fastRecoveryExitPoint);
                }
            }

            var outstandingBytes = _outstandingBytes;
            _receiverWindow = CalculateReceiverWindow(sack.ARwnd, outstandingBytes: (uint)outstandingBytes);
            // The congestion window only grows if it was fully used when the SACK arrived, i.e. counting the
            // bytes this SACK has just acknowledged. This used to pass the bytes left outstanding afterwards,
            // so only the first SACK for each flight grew the window: one MTU per round trip in slow start.
            _congestionWindow = CalculateCongestionWindow(_bytesAckedBySack, outstandingBeforeSack: (uint)outstandingBytes + _bytesAckedBySack);

            if (outstandingBytes == 0)
            {
                // RFC 9260 7.2.2: when all of the data sent has been acknowledged.
                _partialBytesAcked = 0;
            }

            // RFC4960 6.3.2 R2/R3: stop the retransmission timer when nothing is left unacknowledged,
            // restart it when the earliest outstanding chunk has been acknowledged.
            if (_unconfirmedChunks.IsEmpty)
            {
                _t3StartedAt = 0;
            }
            else if (cumulativeAckBeforeSack != _cumulativeAckTSN)
            {
                _t3StartedAt = Stopwatch.GetTimestamp();
            }
        }

        private static readonly ObjectPool<List<SctpDataChunk>> _listPool = new DefaultObjectPool<List<SctpDataChunk>>(
            new ListObjectPolicy<SctpDataChunk>()
        );
        // In your class, add the new pool alongside your list pool
        private static readonly ObjectPool<SctpDataChunk> _chunkPool =
            new DefaultObjectPool<SctpDataChunk>(new SctpDataChunkPolicy());
        /// <summary>
        /// Sends a DATA chunk to the remote peer.
        /// </summary>
        /// <param name="streamID">The stream ID to sent the data on.</param>
        /// <param name="ppid">The payload protocol ID for the data.</param>
        /// <param name="data">The byte data to send.</param>
        public void SendData(ushort streamID, uint ppid, ReadOnlySpan<byte> data)
        {
            if (_closed.HasOccurred || _closeCts.IsCancellationRequested)
            {
                return;
            }

            // 1. Get a list from the pool instead of creating a new one.
            List<SctpDataChunk> chunksToQueue = _listPool.Get();
            bool chunkQueued = false;
            try
            {
                using (_sendLock.EnterScope())
                {
                    // Double check closed state after acquiring lock.
                    if (_closed.HasOccurred)
                    {
                        return;
                    }

                    ushort seqnum = 0;
                    if (_streamSeqnums.ContainsKey(streamID))
                    {
                        unchecked
                        {
                            _streamSeqnums[streamID] = (ushort)(_streamSeqnums[streamID] + 1);
                            seqnum = _streamSeqnums[streamID];
                        }
                    }
                    else
                    {
                        _streamSeqnums.Add(streamID, 0);
                    }

                    for (int index = 0; index * _defaultMTU < data.Length; index++)
                    {
                        int offset = (index == 0) ? 0 : (index * _defaultMTU);
                        int payloadLength = (offset + _defaultMTU < data.Length) ? _defaultMTU : data.Length - offset;

                        bool isBegining = index == 0;
                        bool isEnd = ((offset + payloadLength) >= data.Length) ? true : false;

                        SctpDataChunk dataChunk = _chunkPool.Get();
                        dataChunk.Initialize(
                            false,
                            isBegining,
                            isEnd,
                            TSN,
                            streamID,
                            seqnum,
                            ppid,
                            data.Slice(offset, payloadLength));
                        //SctpDataChunk dataChunk = new SctpDataChunk(
                        //    false,
                        //    isBegining,
                        //    isEnd,
                        //    TSN,
                        //    streamID,
                        //    seqnum,
                        //    ppid,
                        //    data.Slice(offset, payloadLength));

                        chunksToQueue.Add(dataChunk);

                        Interlocked.Increment(ref tsn);
                    }

                    // Queued inside the lock that assigned the TSNs. Queued outside it, two channels
                    // sending at once could reach the queue out of TSN order; the peer saw that as
                    // reordering and gap reported chunks that were merely behind in the queue, which
                    // counted towards a fast retransmit and a cut to the congestion window. The queue has
                    // no bound, so the add does not block.
                    foreach (var chunk in chunksToQueue)
                    {
                        // Counted before it is queued, so the send thread can't take it off first.
                        Interlocked.Add(ref _bufferedBytes, chunk.UserDataLength);
                        try
                        {
                            // Throws if the collection is closed or the cancellation token is triggered.
                            _sendQueue.Add(chunk, _closeCts.Token);
                            chunkQueued = true;
                        }
                        catch (Exception ex) when (ex is InvalidOperationException || ex is OperationCanceledException)
                        {
                            Interlocked.Add(ref _bufferedBytes, -chunk.UserDataLength);
                            logger.LogWarning(ex, "SCTP SendData could not queue chunk for TSN {TSN} as sender is closing.", chunk.TSN);
                            _chunkPool.Return(chunk);
                        }
                    }
                }

                if (chunkQueued)
                {
                    // Wake the sender thread to process the new chunk(s).
                    _senderMre.Set();
                }
            }
            finally
            {
                _listPool.Return(chunksToQueue);
            }
        }


        /// <summary>
        /// Start the sending thread to process the new DATA chunks from the application and
        /// any retransmits or timed out chunks.
        /// </summary>
        public void StartSending()
        {
            if (!_isStarted)
            {
                _isStarted = true;
                _sendThread = new Thread(DoSend)
                {
                    IsBackground = true,
                    Name = $"{nameof(SctpDataSender)}-{_associationID}",
                };
                _sendThread.Start();
            }
        }

        /// <summary>
        /// Stops the sending thread and cleans up resources.
        /// </summary>
        public void Close()
        {
            if (_closed.TryMarkOccurred())
            {
                // Cancel any operations and signal that no more items will be added.
                _closeCts.Cancel();
                _sendQueue.CompleteAdding();

                // Wake the send thread so it sees the closed flag now rather than at the end of its current wait.
                _senderMre.Set();

                var sendThread = _sendThread;
                if (sendThread == null)
                {
                    // The send thread never started so there is nobody else to release the chunks.
                    ReleaseResources();
                }
                else if (sendThread != Thread.CurrentThread)
                {
                    // The send thread releases the chunks as it exits. If it is closed from within its own
                    // send callback, or does not exit in time, it is left to do that when it gets there.
                    try
                    {
                        if (!sendThread.Join(CLOSE_JOIN_TIMEOUT_MILLISECONDS))
                        {
                            logger.LogWarning("SCTP association data send thread for association {ID} did not stop within {Timeout}ms of close.",
                                _associationID, CLOSE_JOIN_TIMEOUT_MILLISECONDS);
                        }
                    }
                    catch (ThreadStateException)
                    {
                        // StartSending has assigned the thread but not yet started it. Once started it sees the
                        // closed flag on its first loop check and releases the chunks as it exits.
                    }
                }
            }
        }

        /// <summary>
        /// Returns the unacknowledged and unsent chunks to the pool once the sender is closed. Only called
        /// from the send thread as it exits, or from Close if the send thread never started.
        /// </summary>
        private void ReleaseResources()
        {
            if (_resourcesReleased.TryMarkOccurred())
            {
                // Under the state lock, and removing each chunk before returning it: a SACK can still be
                // processed on the receive thread while the sender closes, and it must not hand back a
                // chunk this loop has already returned (a chunk returned twice ends up shared by two sends).
                using (_stateLock.EnterScope())
                {
                    foreach (var unconfirmedTSN in _unconfirmedChunks.Keys)
                    {
                        if (_unconfirmedChunks.TryRemove(unconfirmedTSN, out var unconfirmed))
                        {
                            _chunkPool.Return(unconfirmed);
                        }
                    }

                    ReleaseAckedChunks();
                }

                // Drain the send queue and dispose any chunks that were never sent.
                while (_sendQueue.TryTake(out var chunk))
                {
                    _chunkPool.Return(chunk);
                }
                Interlocked.Exchange(ref _bufferedBytes, 0);

                _sendQueue.Dispose();
                _closeCts.Dispose();
            }
        }

        /// <summary>
        /// Updates the sender state for the gap reports received in a SACH chunk from the
        /// remote peer.
        /// </summary>
        /// <param name="sackGapBlocks">The gap reports from the remote peer.</param>
        /// <param name="maxTSNDistance">The maximum distance any valid TSN should be from the current
        /// ACK'ed TSN. If this distance gets exceeded by a gap report then it's likely something has been
        /// miscalculated.</param>
        /// <param name="didSackIncrementTSN">If true, processing of the SACK incremented the <see cref="_cumulativeAckTSN"/></param>
        private void ProcessGapReports(ReadOnlySpan<byte> sackGapBlocks, uint maxTSNDistance, bool didSackIncrementTSN)
        {
            uint lastAckTSN = _cumulativeAckTSN;

            // https://www.rfc-editor.org/rfc/rfc4960#section-7.2.4
            // For each incoming SACK, miss indications are incremented only for missing TSNs prior to the highest TSN newly acknowledged in the SACK.
            uint highestTsnNewlyAcknowledged = lastAckTSN;

            unchecked
            {

                // Parse the gap report to identify missing chunks that have now been acknowledged in the gap report
                for (int index = 0; index < sackGapBlocks.Length; index += SctpSackChunk.GAP_REPORT_LENGTH)
                {
                    var block = SctpTsnGapBlock.Read(sackGapBlocks.Slice(index));
                    // int, not ushort: with End = 65535 a ushort counter wraps to 0 and never fails the test,
                    // which spun the receive thread forever on one SACK from the peer.
                    // Nothing further ahead than the newest TSN assigned can have been sent, so a block
                    // claiming more is not walked past that point.
                    int blockEnd = (int)Math.Min(block.End, maxTSNDistance);
                    for (int offset = block.Start; offset <= blockEnd; offset++)
                    {
                        uint goodTSN = _cumulativeAckTSN + (uint)offset;

                        _missingChunks.TryRemove(goodTSN, out _);
                        if (_unconfirmedChunks.TryRemove(goodTSN, out var chunk))
                        {
                            logger.LogTrace("SCTP acknowledged data chunk receipt in gap report for TSN {TSN}", goodTSN);
                            highestTsnNewlyAcknowledged = goodTSN;
                            OnChunkAcked(chunk);
                        }
                    }
                }

                for (int index = 0; index < sackGapBlocks.Length; index += SctpSackChunk.GAP_REPORT_LENGTH)
                {
                    var gapBlock = SctpTsnGapBlock.Read(sackGapBlocks.Slice(index));
                    uint goodTSNStart = _cumulativeAckTSN + gapBlock.Start;

                    if (SctpDataReceiver.GetDistance(lastAckTSN, goodTSNStart) > maxTSNDistance)
                    {
                        logger.LogWarning($"SCTP SACK gap report had a start TSN of {goodTSNStart} too distant from last good TSN {lastAckTSN}, ignoring rest of SACK.");
                        break;
                    }
                    else if (!SctpDataReceiver.IsNewer(lastAckTSN, goodTSNStart))
                    {
                        logger.LogWarning($"SCTP SACK gap report had a start TSN of {goodTSNStart} behind last good TSN {lastAckTSN}, ignoring rest of SACK.");
                        break;
                    }
                    else
                    {
                        uint missingTSN = lastAckTSN + 1;

                        logger.LogTrace($"SCTP SACK gap report start TSN {goodTSNStart} gap report end TSN {_cumulativeAckTSN + gapBlock.End} " +
                            $"first missing TSN {missingTSN}.");

                        while (missingTSN != goodTSNStart)
                        {
                            if (!_missingChunks.TryGetValue(missingTSN, out int missCount))
                            {
                                if (!_unconfirmedChunks.ContainsKey(missingTSN))
                                {
                                    // What to do? Can't retransmit a chunk that's no longer available. 
                                    // Hope it's a transient error from a duplicate or out of order SACK.
                                    // TODO: Maybe keep count of how many time this occurs and send an ABORT if it
                                    // gets to a certain threshold.
                                    logger.LogWarning($"SCTP SACK gap report reported missing TSN of {missingTSN} but no matching unconfirmed chunk available.");
                                    break;
                                }
                                else
                                {
                                    logger.LogTrace($"SCTP SACK gap adding retransmit entry for TSN {missingTSN}.");
                                    _missingChunks.TryAdd(missingTSN, 1);
                                }
                            }
                            else if (
                                // If an endpoint is in Fast Recovery and a SACK arrives that advances the Cumulative TSN Ack
                                // Point, the miss indications are incremented for all TSNs reported missing in the SACK.
                                (_inFastRecoveryMode.IsOn() && didSackIncrementTSN) ||
                                //  For each incoming SACK, miss indications are incremented only
                                //  for missing TSNs prior to the highest TSN newly acknowledged in the SACK.
                                SctpDataReceiver.IsNewer(missingTSN, highestTsnNewlyAcknowledged))
                            {
                                _missingChunks.TryUpdate(missingTSN, missCount + 1, missCount);

                                // rfc 7.2.4: When the third consecutive miss indication is received for a TSN(s), the data sender shall do the following...
                                if (missCount + 1 == 3)
                                {
                                    // Not while a timeout's retransmissions are still going out: the window
                                    // was collapsed to one MTU for this loss, and the formula below would
                                    // raise it to four.
                                    if (_retransmitPendingCount == 0 && _inFastRecoveryMode.TryTurnOn()) // RFC4960 7.2.4 (2)
                                    {
                                        // Mark the highest outstanding TSN as the Fast Recovery exit point: the last
                                        // chunk put on the wire, not the last one this SACK happens to gap-ack. Using
                                        // the gap-ack ended recovery early, so a second loss in the same window started
                                        // another recovery and halved cwnd again (RFC4960 7.2.4 allows one cut a window).
                                        // Not TSN - 1: TSNs are assigned when data is queued, and with megabytes waiting
                                        // unsent that point is not reached until the whole queue has been acknowledged.
                                        _fastRecoveryExitPoint = _highestSentTSN;

                                        logger.LogDebug($"SCTP sender entering fast recovery mode due to missing TSN {missingTSN}. Fast recovery exit point {_fastRecoveryExitPoint}.");
                                        // RFC4960 7.2.3
                                        _slowStartThreshold = (uint)Math.Max(_congestionWindow / 2, 4 * _defaultMTU);
                                        _congestionWindow = _slowStartThreshold;
                                        _partialBytesAcked = 0;
                                    }
                                }
                            }

                            missingTSN++;
                        }
                    }

                    lastAckTSN = _cumulativeAckTSN + gapBlock.End;
                }
            }
        }


        /// <summary>
        /// Removes the chunks waiting for a SACK confirmation from the unconfirmed queue.
        /// </summary>
        /// <param name="sackTSN">The acknowledged TSN received from in a SACK from the remote peer.</param>
        private void RemoveAckedUnconfirmedChunks(uint sackTSN)
        {
            logger.LogTrace("SCTP data sender removing unconfirmed chunks cumulative ACK TSN {CumulativeAckTSN}, SACK TSN {SackTSN}.",
                _cumulativeAckTSN, sackTSN);

            if (_cumulativeAckTSN == sackTSN)
            {
                // This is normal for the first SACK received.
                RemoveUnconfirmedChunk(_cumulativeAckTSN);
                _missingChunks.TryRemove(_cumulativeAckTSN, out _);
            }
            else
            {
                unchecked
                {
                    for (uint offset = 0; offset <= SctpDataReceiver.GetDistance(_cumulativeAckTSN, sackTSN); offset++)
                    {
                        uint ackd = _cumulativeAckTSN + offset;
                        RemoveUnconfirmedChunk(ackd);
                        _missingChunks.TryRemove(ackd, out _);
                    }
                    _cumulativeAckTSN = sackTSN;
                }
            }
        }

        private void RemoveUnconfirmedChunk(uint tsn)
        {
            if (_unconfirmedChunks.TryRemove(tsn, out var chunk))
            {
                _bytesAckedBySack += (uint)chunk.UserDataLength;
                OnChunkAcked(chunk);
            }
        }

        /// <summary>
        /// Worker thread to process the send and retransmit queues.
        /// </summary>
        private void DoSend(object state)
        {
            logger.LogDebug("SCTP association data send thread started for association {ID}.", _associationID);

            while (!_closed.HasOccurred)
            {
                _senderMre.Reset();

                // Re-check after the Reset: if Close marked and signalled between the loop check and the Reset,
                // the Reset has swallowed its wake-up signal.
                if (_closed.HasOccurred)
                {
                    break;
                }

                // Nothing on this thread holds a chunk reference here, so the chunks SACKs have acknowledged
                // since the last pass can go back to the pool.
                ReleaseAckedChunks();

                // The chunks to send are chosen with the sender state locked, then put on the wire with it
                // released: the transport must never be called under the lock the SACK handler takes.
                _sendBatch.Clear();
                using (_stateLock.EnterScope())
                {
                    SelectChunksToSend(_sendBatch);
                }

                SendBatch(_sendBatch);

  
                int wait = GetSendWaitMilliseconds();
                _senderMre.Wait(wait);
            }

            ReleaseResources();

            logger.LogDebug("SCTP association data send thread stopped for association {ID}.", _associationID);
        }

        /// <summary>
        /// Determines how many milliseconds the send thread should wait before the next send attempt.
        /// </summary>
        private int GetSendWaitMilliseconds()
        {
            int wait;

            if (_sendQueue.Count > 0 || !_missingChunks.IsEmpty || Volatile.Read(ref _retransmitPendingCount) > 0)
            {
                if (_receiverWindow > 0 && _congestionWindow > (uint)_outstandingBytes)
                {
                    wait = _burstPeriodMilliseconds;
                }
                else
                {
                    wait = _rtoMinimumMilliseconds;
                }
            }
            else
            {
                wait = _rtoInitialMilliseconds;
            }

            // Never sleep past the retransmission timer: a SACK or new data wakes the thread early, but
            // a timeout has nothing else to wake it.
            long t3StartedAt = Volatile.Read(ref _t3StartedAt);
            if (t3StartedAt != 0)
            {
                double remaining = CurrentRtoMilliseconds() - Stopwatch.GetElapsedTime(t3StartedAt).TotalMilliseconds;
                int untilTimeout = remaining <= 1 ? 1 : (int)Math.Min(remaining, int.MaxValue);
                wait = Math.Min(wait, untilTimeout);
            }

            return wait;
        }

        /// <summary>
        /// The retransmission timeout in force: the measured (or initial) RTO, doubled for each
        /// timeout since the last round trip measurement (RFC4960 6.3.3 E2) and capped at the maximum.
        /// </summary>
        private double CurrentRtoMilliseconds()
        {
            double rto = _hasRoundTripTime ? _rto : _rtoInitialMilliseconds;
            int shift = Volatile.Read(ref _rtoBackoffShift);
            return shift > 0 ? Math.Min(_rtoMaximumMilliseconds, rto * (1L << shift)) : rto;
        }

        /// <summary>
        /// Chooses the chunks for this pass of the send thread, in priority order: fast retransmits,
        /// chunks a timeout marked for retransmission, then new data. Must be called with
        /// <see cref="_stateLock"/> held. The chunks are sent by the caller once the lock is released.
        /// </summary>
        private void SelectChunksToSend(List<SctpDataChunk> batch)
        {
            var now = SctpDataChunk.Timestamp.Now;

            // T3-rtx. One timer for the association, running while anything is unacknowledged and
            // restarted when a SACK moves the cumulative ack on (RFC4960 6.3.2). Each chunk used to carry
            // its own timer: when a whole flight was lost, the first timeout resent a few chunks, doubled
            // the RTO and so pushed the rest of that same flight out by another timeout, and every round
            // after that halved the window and doubled the RTO again. Losing 100 chunks took minutes.
            if (_unconfirmedChunks.IsEmpty)
            {
                _t3StartedAt = 0;
            }
            else if (_t3StartedAt == 0)
            {
                _t3StartedAt = now.Ticks;
            }
            else if (Stopwatch.GetElapsedTime(_t3StartedAt, now.Ticks).TotalMilliseconds >= CurrentRtoMilliseconds())
            {
                OnRetransmissionTimeout(now);
            }

            uint flightAtStart = (uint)Math.Max(0L, _flightBytes);
            int burstSize = (_inFastRecoveryMode.IsOn() || _congestionWindow < flightAtStart || _receiverWindow == 0) ? 1 : MAX_BURST;

            // Missing chunks from a SACK gap report take priority. RFC4960 7.2.4 fast retransmission,
            // sent whatever the congestion window.
            if (!_missingChunks.IsEmpty)
            {
                foreach (var missing in _missingChunks)
                {
                    if (missing.Value >= 3 && _unconfirmedChunks.TryGetValue(missing.Key, out var missingChunk))
                    {
                        AddRetransmit(batch, missingChunk, now);
                        _missingChunks.TryUpdate(missing.Key, 0, missing.Value);
                    }
                    if (batch.Count >= burstSize)
                    {
                        break;
                    }
                }
            }

            // Chunks marked by a timeout, lowest TSN first (the one holding back the peer's cumulative
            // ack) and only as the congestion window allows: it restarts at one MTU and each SACK for a
            // resent chunk opens it further, so the lost flight goes back out in slow start rather than
            // a few chunks per timeout.
            if (_retransmitPendingCount > 0)
            {
                uint first = unchecked(_cumulativeAckTSN + 1);
                uint last = _highestSentTSN;
                uint span = SctpDataReceiver.IsNewerOrEqual(first, last) ? unchecked(last - first + 1) : 0;
                bool found = false;

                for (uint offset = 0; offset < span && offset < MAX_RETRANSMIT_SCAN; offset++)
                {
                    if (batch.Count >= MAX_BURST || _retransmitPendingCount == 0 || _flightBytes >= _congestionWindow)
                    {
                        found = true; // Stopped by a limit, not by running out of chunks.
                        break;
                    }

                    if (_unconfirmedChunks.TryGetValue(unchecked(first + offset), out var chunk) && chunk.RetransmitPending)
                    {
                        AddRetransmit(batch, chunk, now);
                        found = true;
                    }
                }

                if (!found)
                {
                    // Nothing pending in the TSN range walked (it is only that large if the peer has
                    // acknowledged TSNs out of all proportion). Fall back to whatever order the dictionary
                    // gives, and if it holds no marked chunk either the count is stale.
                    foreach (var entry in _unconfirmedChunks)
                    {
                        if (batch.Count >= MAX_BURST || _flightBytes >= _congestionWindow)
                        {
                            found = true;
                            break;
                        }
                        if (entry.Value.RetransmitPending)
                        {
                            AddRetransmit(batch, entry.Value, now);
                            found = true;
                        }
                    }

                    if (!found)
                    {
                        _retransmitPendingCount = 0;
                    }
                }
            }

            // rfc4960 6.1: At any given time, the sender MUST NOT transmit new data to a given transport address
            // if it has cwnd or more bytes of data outstanding to that transport address.
            // New data waits until everything a timeout marked has been resent. The window is tested once
            // for the pass, as it always has been, so a burst can run a few chunks over it.
            if (_retransmitPendingCount == 0 && batch.Count < burstSize && _sendQueue.Count > 0 && _congestionWindow > flightAtStart)
            {
                while (batch.Count < burstSize && _sendQueue.TryTake(out var dataChunk))
                {
                    Interlocked.Add(ref _bufferedBytes, -dataChunk.UserDataLength);

                    dataChunk.LastSentAt = now;
                    dataChunk.SendCount = 1;
                    dataChunk.RetransmitPending = false;

                    if (_unconfirmedChunks.TryAdd(dataChunk.TSN, dataChunk))
                    {
                        _flightBytes += dataChunk.UserDataLength;
                        if (SctpDataReceiver.IsNewer(_highestSentTSN, dataChunk.TSN))
                        {
                            _highestSentTSN = dataChunk.TSN;
                        }
                        batch.Add(dataChunk);
                    }
                    else
                    {
                        logger.LogDebug("SCTP duplicate TSN {TSN} detected in send queue.", dataChunk.TSN);
                        _chunkPool.Return(dataChunk);
                    }
                }
            }

            if (batch.Count > 0 && _t3StartedAt == 0)
            {
                // RFC4960 6.3.2 R1: start the timer when data is sent and it isn't running.
                _t3StartedAt = now.Ticks;
            }
        }

        /// <summary>
        /// Adds a chunk that has been sent before to the batch. Must be called with <see cref="_stateLock"/> held.
        /// </summary>
        private void AddRetransmit(List<SctpDataChunk> batch, SctpDataChunk chunk, SctpDataChunk.Timestamp now)
        {
            if (chunk.RetransmitPending)
            {
                // Back in flight.
                chunk.RetransmitPending = false;
                _retransmitPendingCount--;
                _flightBytes += chunk.UserDataLength;
            }

            chunk.LastSentAt = now;
            chunk.SendCount += 1;

            logger.LogTrace("SCTP retransmitting data chunk for TSN {TSN}, data length {Length}, " +
                "flags {Flags:X2}, send count {Count}.",
                chunk.TSN, chunk.UserDataLength, chunk.ChunkFlags, chunk.SendCount);

            batch.Add(chunk);
        }

        /// <summary>
        /// The T3-rtx timer has expired (RFC4960 6.3.3): back the timer off, restart the congestion
        /// window in slow start, and mark everything outstanding for retransmission. Marked chunks no
        /// longer count as in flight until they are resent. Must be called with <see cref="_stateLock"/> held.
        /// </summary>
        private void OnRetransmissionTimeout(SctpDataChunk.Timestamp now)
        {
            // RFC4960 7.2.3.
            _slowStartThreshold = (uint)Math.Max(_congestionWindow / 2, 4 * _defaultMTU);
            _congestionWindow = _defaultMTU;
            _partialBytesAcked = 0;

            // RFC4960 6.3.3 E2. Undone by the next round trip measurement.
            if (_rtoBackoffShift < MAX_RTO_BACKOFF_SHIFT)
            {
                _rtoBackoffShift++;
            }

            // The window has been cut for this loss already, and every chunk the gap reports were
            // counting is about to be resent anyway.
            _inFastRecoveryMode.TryTurnOff();
            _missingChunks.Clear();

            int marked = 0;
            foreach (var entry in _unconfirmedChunks)
            {
                var chunk = entry.Value;
                if (!chunk.RetransmitPending)
                {
                    chunk.RetransmitPending = true;
                    _retransmitPendingCount++;
                    _flightBytes -= chunk.UserDataLength;
                    marked++;
                }
            }

            // E3: restart the timer for the chunk(s) about to be resent.
            _t3StartedAt = now.Ticks;

            logger.LogDebug("SCTP sender retransmission timeout for association {ID}: {Marked} chunk(s) marked for retransmission, " +
                "next timeout in {RTO}ms.", _associationID, marked, CurrentRtoMilliseconds());
        }

        /// <summary>
        /// Puts the chosen chunks on the wire. Called by the send thread without <see cref="_stateLock"/>.
        /// </summary>
        private void SendBatch(List<SctpDataChunk> batch)
        {
            for (int i = 0; i < batch.Count; i++)
            {
                try
                {
                    _sendDataChunk(batch[i]);
                }
                catch (Exception excp)
                {
                    // An exception leaving this thread would take the process down. The chunks stay
                    // unacknowledged, so the timeout resends them if the transport recovers.
                    if (!_closed.HasOccurred)
                    {
                        long nowMs = Environment.TickCount64;
                        if (nowMs - _lastSendErrorLogAt >= 1000)
                        {
                            _lastSendErrorLogAt = nowMs;
                            logger.LogWarning(excp, "SCTP sender for association {ID} could not send a data chunk.", _associationID);
                        }
                    }
                    break;
                }
            }
        }

        /// <summary>
        /// A SACK has acknowledged a sent chunk that was just removed from the unconfirmed chunks.
        /// Must be called with <see cref="_stateLock"/> held.
        /// </summary>
        private void OnChunkAcked(SctpDataChunk chunk)
        {
            if (chunk.RetransmitPending)
            {
                // Marked by a timeout and acknowledged before it was resent: it was not counted as in flight.
                chunk.RetransmitPending = false;
                _retransmitPendingCount--;
            }
            else
            {
                _flightBytes -= chunk.UserDataLength;
            }

            // Not returned to the pool here. The send thread may be in the middle of sending this very
            // chunk, and the pool is shared by every association: returned now, the chunk and its buffer
            // could be handed to another connection's send while this one is still being serialised.
            // The send thread returns it once it holds no chunk references (ReleaseAckedChunks).
            _ackedChunks.Enqueue(chunk);
        }

        /// <summary>
        /// Returns the chunks acknowledged since the last pass to the pool. Send thread only.
        /// </summary>
        private void ReleaseAckedChunks()
        {
            while (_ackedChunks.TryDequeue(out var chunk))
            {
                _chunkPool.Return(chunk);
            }
        }


        /// <summary>
        /// Updates the round trip time. 
        /// See https://datatracker.ietf.org/doc/html/rfc4960#section-6.3.1
        /// </summary>
        /// <param name="acknowledgedChunk">The last sent and acknowledged chunk used to calculate the round trip time</param>
        private void UpdateRoundTripTime(SctpDataChunk acknowledgedChunk)
        {
            // rfc 4960 6.3.1 C5: RTT measurements MUST NOT be made using packets that were retransmitted
            if (acknowledgedChunk.SendCount > 1)
            {
                return;
            }

            var rttMilliseconds = (SctpDataChunk.Timestamp.Now - acknowledgedChunk.LastSentAt).TotalMilliseconds;

            if (!_hasRoundTripTime)
            {
                // rfc 4960 6.3.1 C2
                _smoothedRoundTripTime = rttMilliseconds;
                _roundTripTimeVariation = rttMilliseconds / 2;
                _rto = _smoothedRoundTripTime + 4 * _roundTripTimeVariation;
                _hasRoundTripTime = true;
            }
            else
            {
                // rfc 4960 6.3.1 C3
                _roundTripTimeVariation = (1 - _rtoBeta) * _roundTripTimeVariation + _rtoBeta * Math.Abs(_smoothedRoundTripTime - rttMilliseconds);
                _smoothedRoundTripTime = (1 - _rtoAlpha) * _smoothedRoundTripTime + _rtoAlpha * rttMilliseconds;
                _rto = _smoothedRoundTripTime + 4 * _roundTripTimeVariation;
            }

            // rfc 4960 6.3.1 C6-7
            _rto = Math.Min(Math.Max(_rto, _rtoMinimumMilliseconds), _rtoMaximumMilliseconds);

            // A fresh measurement replaces any backed off RTO.
            _rtoBackoffShift = 0;
        }

        /// <summary>
        /// Calculates the receiver window based on the value supplied from a SACK chunk.
        /// Note the receive window in the SACK chunk does not take account for in flight
        /// DATA chunks hence the need for this calculation.
        /// </summary>
        /// <param name="advertisedReceiveWindow">The last receive window value supplied by the remote peer 
        /// either in the INIT handshake or in a SACK chunk.</param>
        /// <remarks>
        /// See https://tools.ietf.org/html/rfc4960#section-6.2.1.
        /// </remarks>
        /// <returns>The new value to use for the receiver window.</returns>
        private uint CalculateReceiverWindow(uint advertisedReceiveWindow, uint outstandingBytes)
        {
            return (advertisedReceiveWindow > outstandingBytes) ? advertisedReceiveWindow - outstandingBytes : 0;
        }

        /// <summary>
        /// Calculates an updated value for the congestion window.
        /// </summary>
        /// <param name="ackedBytes">The user data bytes the SACK acknowledged.</param>
        /// <param name="outstandingBeforeSack">The bytes that were in flight when the SACK arrived.</param>
        /// <returns>A congestion window value.</returns>
        private uint CalculateCongestionWindow(uint ackedBytes, uint outstandingBeforeSack)
        {
            if (ackedBytes == 0)
            {
                // The window only grows when the SACK acknowledges new data.
                return _congestionWindow;
            }

            if (_congestionWindow <= _slowStartThreshold)
            {
                // In Slow-Start mode, see RFC4960 7.2.1.
                // Updated to RFC9260 7.2.1
                if (_congestionWindow <= outstandingBeforeSack && !_inFastRecoveryMode.IsOn())
                {
                    // When cwnd is less than or equal to ssthresh, an SCTP endpoint MUST
                    // use the slow - start algorithm to increase cwnd only if the current
                    // congestion window is being fully utilized.
                    uint increasedCwnd = _congestionWindow + Math.Min(ackedBytes, _defaultMTU);

                    logger.LogTrace("SCTP sender congestion window in slow-start increased from {Original} to {Increased}.",
                        _congestionWindow, increasedCwnd);

                    return increasedCwnd;
                }
                else
                {
                    return _congestionWindow;
                }
            }
            else
            {
                // In Congestion Avoidance mode, see RFC4960 7.2.2: one MTU for each congestion window's
                // worth of acknowledged data, i.e. about once a round trip, not once a SACK.
                _partialBytesAcked += ackedBytes;

                if (_partialBytesAcked >= _congestionWindow && _congestionWindow <= outstandingBeforeSack)
                {
                    _partialBytesAcked -= _congestionWindow;

                    logger.LogTrace("SCTP sender congestion window in congestion avoidance increased from {Original} to {Increased}.",
                        _congestionWindow, _congestionWindow + _defaultMTU);

                    return _congestionWindow + _defaultMTU;
                }
                else
                {
                    return _congestionWindow;
                }
            }
        }
    }

    public class ListObjectPolicy<T> : IPooledObjectPolicy<List<T>>
    {
        /// <summary>
        /// Creates a new List<T> when the pool is empty.
        /// </summary>
        public List<T> Create()
        {
            return new List<T>();
        }

        /// <summary>
        /// Resets the list by calling .Clear() when it's returned to the pool.
        /// Returns true to indicate the object is safe to be reused.
        /// </summary>
        public bool Return(List<T> obj)
        {
            obj.Clear();
            return true;
        }
    }

    // Policy for creating and resetting SctpDataChunk objects
    public class SctpDataChunkPolicy : IPooledObjectPolicy<SctpDataChunk>
    {
        public SctpDataChunk Create() => new SctpDataChunk();

        public bool Return(SctpDataChunk obj)
        {
            // When an object is returned to the pool, dispose its internal buffer
            // so the array is returned to the ArrayPool.
            obj.Dispose();
            return true;
        }
    }
}

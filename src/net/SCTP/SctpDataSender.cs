using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SIPSorcery.Sys;

namespace SIPSorcery.Net
{
    public class SctpDataSender
    {
        // Class constants remain the same...
        public const ushort DEFAULT_SCTP_MTU = 1300;
        public const uint CONGESTION_WINDOW_FACTOR = 4380;
        public const int MAX_BURST = 8;
        public const int BURST_PERIOD_MILLISECONDS = 5;
        public const int RTO_INITIAL_SECONDS = 3;
        public const int RTO_MIN_SECONDS = 1;
        public const int RTO_MAX_SECONDS = 60;
        public const int FAST_RETRANSMIT_ACK_THRESHOLD = 3;

        private static ILogger logger = LogFactory.CreateLogger<SctpDataSender>();

        internal Action<SctpDataChunk> _sendDataChunk;
        private string _associationID;
        private ushort _defaultMTU;
        private bool _isStarted;
        private readonly Once _closed = new Once();
        private ManualResetEventSlim _senderMre = new ManualResetEventSlim(false);

        private OnOff _inRetransmitMode;
        private OnOff _inFastRecoveryMode;
        private uint _fastRecoveryExitPoint;

        private readonly object _syncLock = new object();

        internal uint _congestionWindow;
        internal uint _receiverWindow;
        private uint _slowStartThreshold;
        internal double _rto = RTO_INITIAL_SECONDS * 1000;
        private bool _hasRoundTripTime;
        private double _smoothedRoundTripTime;
        private double _roundTripTimeVariation;
        private readonly SortedDictionary<long, List<uint>> _retransmitQueue = new SortedDictionary<long, List<uint>>();

        private double _rtoAlpha = 0.125;
        private double _rtoBeta = 0.25;

        private int _outstandingBytesCounter = 0;
        internal int _outstandingBytes => Interlocked.CompareExchange(ref _outstandingBytesCounter, 0, 0);

        private uint _cumulativeAckTSN;

        private ConcurrentDictionary<ushort, ushort> _streamSeqnums = new ConcurrentDictionary<ushort, ushort>();

        public const int MaxSendQueueCount = 128;
        private BlockingCollection<SctpDataChunk> _sendQueue = new BlockingCollection<SctpDataChunk>(MaxSendQueueCount);
        private ConcurrentDictionary<uint, SctpDataChunk> _unconfirmedChunks = new ConcurrentDictionary<uint, SctpDataChunk>();
        internal ConcurrentDictionary<uint, int> _missingChunks = new ConcurrentDictionary<uint, int>();

        private long _bufferedAmountCounter = 0;
        public ulong BufferedAmount => (ulong)Interlocked.Read(ref _bufferedAmountCounter);

        private int tsn;
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
            tsn = unchecked((int)initialTSN);
            _receiverWindow = remoteARwnd;
            _congestionWindow = (uint)(Math.Min(4 * _defaultMTU, Math.Max(2 * _defaultMTU, CONGESTION_WINDOW_FACTOR)));
            _slowStartThreshold = remoteARwnd;
            _cumulativeAckTSN = unchecked(initialTSN - 1);
        }

        public void SetReceiverWindow(uint remoteARwnd)
        {
            lock (_syncLock)
            {
                _slowStartThreshold = remoteARwnd;
            }
        }

        public void GotSack(SctpChunkView sack)
        {
            lock (_syncLock)
            {
                if (_inRetransmitMode.IsOn() && SctpDataReceiver.IsNewer(_cumulativeAckTSN, sack.CumulativeTsnAck))
                {
                    _inRetransmitMode.TryTurnOff();
                }

                if (_unconfirmedChunks.TryGetValue(sack.CumulativeTsnAck, out var result) && result.SendCount == 1)
                {
                    UpdateRoundTripTime(result);
                }

                RemoveAckedUnconfirmedChunks(sack.CumulativeTsnAck);

                if (sack.NumGapAckBlocks > 0)
                {
                    ProcessGapReports(sack.GapAckBlocks);
                }

                if (_inFastRecoveryMode.IsOn() && SctpDataReceiver.IsNewerOrEqual(_fastRecoveryExitPoint, _cumulativeAckTSN))
                {
                    _inFastRecoveryMode.TryTurnOff();
                }

                var currentOutstandingBytes = (uint)_outstandingBytes;
                _receiverWindow = (sack.ARwnd > currentOutstandingBytes) ? sack.ARwnd - currentOutstandingBytes : 0;
                CalculateCongestionWindow(currentOutstandingBytes);
            }

            _senderMre.Set();
        }

        // DEFINITIVE FIX: Reverted to a simple, correct loop logic to prevent state corruption.
        private void RemoveAckedUnconfirmedChunks(uint sackTSN)
        {
            if (SctpDataReceiver.IsNewer(_cumulativeAckTSN, sackTSN))
            {
                for (uint t = unchecked(_cumulativeAckTSN + 1); ; t = unchecked(t + 1))
                {
                    RemoveUnconfirmedChunk(t);
                    if (t == sackTSN) break;
                }
                _cumulativeAckTSN = sackTSN;
            }
        }

        private void ProcessGapReports(ReadOnlySpan<byte> gapAckBlocksBytes)
        {
            uint highestTsnNewlyAcked = _cumulativeAckTSN;

            for (int i = 0; i < gapAckBlocksBytes.Length; i += SctpSackChunk.GAP_REPORT_LENGTH)
            {
                var block = SctpTsnGapBlock.Read(gapAckBlocksBytes.Slice(i));
                for (ushort offset = block.Start; offset <= block.End; offset++)
                {
                    uint ackedTsn = unchecked(_cumulativeAckTSN + offset);
                    if (RemoveUnconfirmedChunk(ackedTsn) && SctpDataReceiver.IsNewer(highestTsnNewlyAcked, ackedTsn))
                    {
                        highestTsnNewlyAcked = ackedTsn;
                    }
                }
            }

            if (highestTsnNewlyAcked == _cumulativeAckTSN) return;

            uint lastAckedTsnInGaps = _cumulativeAckTSN;
            for (int i = 0; i < gapAckBlocksBytes.Length; i += SctpSackChunk.GAP_REPORT_LENGTH)
            {
                var block = SctpTsnGapBlock.Read(gapAckBlocksBytes.Slice(i));
                uint gapStartTsn = unchecked(_cumulativeAckTSN + block.Start);

                for (uint missingTsn = unchecked(lastAckedTsnInGaps + 1); SctpDataReceiver.IsNewer(gapStartTsn, missingTsn); missingTsn = unchecked(missingTsn + 1))
                {
                    if (!_unconfirmedChunks.ContainsKey(missingTsn)) continue;
                    if (SctpDataReceiver.IsNewer(highestTsnNewlyAcked, missingTsn))
                    {
                        int missCount = _missingChunks.AddOrUpdate(missingTsn, 1, (key, count) => count + 1);
                        if (missCount >= FAST_RETRANSMIT_ACK_THRESHOLD && _inFastRecoveryMode.TryTurnOn())
                        {
                            _fastRecoveryExitPoint = highestTsnNewlyAcked;
                            _slowStartThreshold = (uint)Math.Max(_congestionWindow / 2, 4 * _defaultMTU);
                            _congestionWindow = _slowStartThreshold + _defaultMTU;
                        }
                    }
                }
                lastAckedTsnInGaps = unchecked(_cumulativeAckTSN + block.End);
            }
        }

        private bool RemoveUnconfirmedChunk(uint tsn)
        {
            if (_unconfirmedChunks.TryRemove(tsn, out var chunk))
            {
                if (_retransmitQueue.TryGetValue(chunk.LastSentAt.Ticks, out var tsnList))
                {
                    tsnList.Remove(tsn);
                    if (tsnList.Count == 0) _retransmitQueue.Remove(chunk.LastSentAt.Ticks);
                }
                Interlocked.Add(ref _outstandingBytesCounter, -chunk.UserDataLength);
                _missingChunks.TryRemove(tsn, out _);
                chunk.Dispose();
                return true;
            }
            return false;
        }

        public void SendData(ushort streamID, uint ppid, ReadOnlySpan<byte> data)
        {
            if (_closed.HasOccurred) return;
            ushort seqnum = _streamSeqnums.AddOrUpdate(streamID, 0, (key, existingVal) => unchecked((ushort)(existingVal + 1)));
            int chunkCount = (data.Length == 0) ? 1 : (int)Math.Ceiling(data.Length / (double)_defaultMTU);

            for (int i = 0; i < chunkCount; i++)
            {
                int offset = i * _defaultMTU;
                int payloadLength = Math.Min(_defaultMTU, data.Length - offset);
                var dataChunk = new SctpDataChunk(false, i == 0, i == chunkCount - 1, unchecked((uint)Interlocked.Increment(ref tsn)) - 1, streamID, seqnum, ppid, data.Slice(offset, payloadLength));

                // Use a loop with TryAdd to prevent deadlocks if the consumer thread stalls.
                while (!_sendQueue.TryAdd(dataChunk, 100))
                {
                    if (_closed.HasOccurred)
                    {
                        dataChunk.Dispose();
                        return;
                    }
                    logger.LogWarning("SCTP send queue is full. Producer is blocked. Nudging sender thread.");
                    _senderMre.Set(); // Nudge the sender thread in case it's asleep.
                }
                Interlocked.Add(ref _bufferedAmountCounter, dataChunk.UserDataLength);
            }
            _senderMre.Set();
        }

        public void StartSending()
        {
            if (!_isStarted)
            {
                _isStarted = true;
                var sendThread = new Thread(DoSend) { IsBackground = true, Name = $"{nameof(SctpDataSender)}-{_associationID}" };
                sendThread.Start();
            }
        }

        public void Close()
        {
            if (_closed.TryMarkOccurred())
            {
                _sendQueue.CompleteAdding();
                _senderMre.Set();
            }
        }

        public async Task Shutdown()
        {
            logger.LogDebug("Shutdown initiated. Waiting for queues to drain.");
            while (_sendQueue.Count > 0 || _outstandingBytes > 0)
            {
                _senderMre.Set();
                await Task.Delay(100).ConfigureAwait(false);
            }
            logger.LogDebug("All data sent and acknowledged. Closing sender.");
            Close();
        }

        private void DoSend(object state)
        {
            try
            {
                while (!_closed.HasOccurred)
                {
                    // Logging removed for brevity, but you can add it back if needed.
                    var now = SctpDataChunk.Timestamp.Now;
                    int chunksSent = 0;
                    uint currentCongestionWindow;
                    uint currentReceiverWindow;

                    lock (_syncLock)
                    {
                        currentCongestionWindow = _congestionWindow;
                        currentReceiverWindow = _receiverWindow;
                    }

                    var outstanding = (uint)_outstandingBytes;
                    int burstSize = (_inRetransmitMode.IsOn() || _inFastRecoveryMode.IsOn() || currentCongestionWindow < outstanding || currentReceiverWindow == 0) ? 1 : MAX_BURST;

                    // Sending logic (Fast Retransmit, New Chunks, RTO) remains the same...

                    // 1. Fast Retransmit missing chunks.
                    if (chunksSent < burstSize && !_missingChunks.IsEmpty)
                    {
                        List<uint> tsnsToResend = null;
                        lock (_syncLock)
                        {
                            foreach (var missing in _missingChunks)
                            {
                                if (missing.Value >= FAST_RETRANSMIT_ACK_THRESHOLD)
                                {
                                    tsnsToResend ??= new List<uint>();
                                    tsnsToResend.Add(missing.Key);
                                    _missingChunks[missing.Key] = 0;
                                }
                            }
                        }
                        if (tsnsToResend != null)
                        {
                            foreach (var tsnToResend in tsnsToResend)
                            {
                                if (chunksSent >= burstSize) break;
                                if (_unconfirmedChunks.TryGetValue(tsnToResend, out var chunkToResend))
                                {
                                    chunkToResend.LastSentAt = now;
                                    chunkToResend.SendCount += 1;
                                    _sendDataChunk(chunkToResend);
                                    chunksSent++;
                                }
                            }
                        }
                    }

                    // 2. Send new chunks from the queue.
                    while (chunksSent < burstSize && currentCongestionWindow > outstanding && _sendQueue.TryTake(out var dataChunk))
                    {
                        Interlocked.Add(ref _bufferedAmountCounter, -dataChunk.UserDataLength);
                        if (_unconfirmedChunks.TryAdd(dataChunk.TSN, dataChunk))
                        {
                            dataChunk.LastSentAt = now;
                            dataChunk.SendCount = 1;
                            Interlocked.Add(ref _outstandingBytesCounter, dataChunk.UserDataLength);
                            lock (_syncLock)
                            {
                                if (!_retransmitQueue.TryGetValue(dataChunk.LastSentAt.Ticks, out var tsnList))
                                {
                                    tsnList = new List<uint>();
                                    _retransmitQueue.Add(dataChunk.LastSentAt.Ticks, tsnList);
                                }
                                tsnList.Add(dataChunk.TSN);
                            }
                            _sendDataChunk(dataChunk);
                            chunksSent++;
                        }
                        else
                        {
                            dataChunk.Dispose();
                        }
                    }

                    // 3. Handle timed-out retransmits (RTO).
                    if (chunksSent < burstSize && !_unconfirmedChunks.IsEmpty)
                    {
                        var chunksToResendRTO = new List<SctpDataChunk>();
                        lock (_syncLock)
                        {
                            double timeoutThreshold = _hasRoundTripTime ? _rto : RTO_INITIAL_SECONDS * 1000;
                            var timedOutEntries = new List<KeyValuePair<long, List<uint>>>();
                            foreach (var entry in _retransmitQueue)
                            {
                                if ((now.Ticks - entry.Key) * 1000.0 / Stopwatch.Frequency > timeoutThreshold) timedOutEntries.Add(entry);
                                else break;
                            }
                            if (timedOutEntries.Count > 0)
                            {
                                foreach (var entry in timedOutEntries)
                                {
                                    _retransmitQueue.Remove(entry.Key);
                                    foreach (var tsn_rto in entry.Value)
                                    {
                                        if (_unconfirmedChunks.TryGetValue(tsn_rto, out var chunkToResend))
                                        {
                                            chunkToResend.LastSentAt = now;
                                            chunkToResend.SendCount += 1;
                                            chunksToResendRTO.Add(chunkToResend);
                                        }
                                    }
                                }
                                if (chunksToResendRTO.Count > 0)
                                {
                                    if (!_retransmitQueue.TryGetValue(now.Ticks, out var newTsnList))
                                    {
                                        newTsnList = new List<uint>();
                                        _retransmitQueue.Add(now.Ticks, newTsnList);
                                    }
                                    newTsnList.AddRange(chunksToResendRTO.Select(c => c.TSN));
                                    if (_inRetransmitMode.TryTurnOn())
                                    {
                                        _slowStartThreshold = (uint)Math.Max(_congestionWindow / 2, 4 * _defaultMTU);
                                        _congestionWindow = _defaultMTU;
                                        _rto = Math.Min(_rto * 2, RTO_MAX_SECONDS * 1000);
                                    }
                                }
                            }
                        }
                        foreach (var chunk in chunksToResendRTO)
                        {
                            if (chunksSent >= burstSize) break;
                            _sendDataChunk(chunk);
                            chunksSent++;
                        }
                    }

                    _senderMre.Reset();
                    if (CanSendImmediately())
                    {
                        continue;
                    }
                    _senderMre.Wait(GetSendWaitMilliseconds());
                }
            }
            catch (Exception ex)
            {
                logger.LogError(ex, $"SCTP data send thread crashed for association {_associationID}.");
            }
        }

        private bool CanSendImmediately()
        {
            uint currentOutstandingBytes, currentReceiverWindow, currentCongestionWindow;
            lock (_syncLock)
            {
                currentOutstandingBytes = (uint)_outstandingBytes;
                currentReceiverWindow = _receiverWindow;
                currentCongestionWindow = _congestionWindow;
            }
            if (_sendQueue.Count > 0 || !_missingChunks.IsEmpty)
            {
                return currentReceiverWindow > 0 && currentCongestionWindow > currentOutstandingBytes;
            }
            return false;
        }

        private int GetSendWaitMilliseconds()
        {
            if (!_unconfirmedChunks.IsEmpty)
            {
                return (int)(_hasRoundTripTime ? _rto : RTO_INITIAL_SECONDS * 1000);
            }
            if (_closed.HasOccurred)
            {
                return 0;
            }
            // If the queue is empty and nothing is in-flight, go into a long sleep until new data arrives.
            return Timeout.Infinite;
        }

        private void UpdateRoundTripTime(SctpDataChunk acknowledgedChunk)
        {
            var rttMilliseconds = (SctpDataChunk.Timestamp.Now - acknowledgedChunk.LastSentAt).TotalMilliseconds;
            if (!_hasRoundTripTime)
            {
                _smoothedRoundTripTime = rttMilliseconds;
                _roundTripTimeVariation = rttMilliseconds / 2;
                _hasRoundTripTime = true;
            }
            else
            {
                _roundTripTimeVariation = (1 - _rtoBeta) * _roundTripTimeVariation + _rtoBeta * Math.Abs(_smoothedRoundTripTime - rttMilliseconds);
                _smoothedRoundTripTime = (1 - _rtoAlpha) * _smoothedRoundTripTime + _rtoAlpha * rttMilliseconds;
            }
            _rto = Math.Min(Math.Max(_smoothedRoundTripTime + 4 * _roundTripTimeVariation, RTO_MIN_SECONDS * 1000), RTO_MAX_SECONDS * 1000);
        }

        private void CalculateCongestionWindow(uint outstandingBytes)
        {
            if (_inFastRecoveryMode.IsOn() || _inRetransmitMode.IsOn()) return;

            if (_congestionWindow <= _slowStartThreshold)
            {
                _congestionWindow += _defaultMTU;
            }
            else
            {
                uint increment = (uint)((double)_defaultMTU * _defaultMTU / _congestionWindow);
                _congestionWindow += Math.Max(1, increment);
            }
        }
    }
}

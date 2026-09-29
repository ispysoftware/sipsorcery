//-----------------------------------------------------------------------------
// Filename: DtlsSrtpTransport.cs
//
// Description: This class represents the DTLS SRTP transport connection to use
// as Client or Server.
//
// Author(s):
// Rafael Soares (raf.csoares@kyubinteractive.com)
//
// History:
// 01 Jul 2020	Rafael Soares   Created.
// 02 Jul 2020  Aaron Clauson   Switched underlying transport from socket to
//                              piped memory stream.
// 30 Dec 2025  Lukas Volf      New DTLS/SRTP impl
// Sep 2026     iSpyConnect     Blocking receive queue (no polling), copy-in
//                              receive for reused socket buffers, fail-fast
//                              on close, configurable MTU, Span SRTP API.
//
// License:
// BSD 3-Clause "New" or "Revised" License, see included LICENSE.md file.
//-----------------------------------------------------------------------------

using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Net.Sockets;
using System.Threading;
using Org.BouncyCastle.Tls;
using SIPSorcery.Net.SharpSRTP.DTLS;
using SIPSorcery.Net.SharpSRTP.DTLSSRTP;
using SIPSorcery.Net.SharpSRTP.SRTP;

namespace SIPSorcery.Net
{
    public delegate void OnDataReadyEvent(byte[] data);
    public delegate void OnDtlsAlertEvent(TlsAlertLevelsEnum alertLevel, TlsAlertTypesEnum alertType, string alertDescription);

    public class DtlsSrtpTransport : DatagramTransport, IDisposable
    {
        public const int DEFAULT_MTU = 1500;
        public const int MIN_IP_OVERHEAD = 20;
        public const int MAX_IP_OVERHEAD = MIN_IP_OVERHEAD + 64;
        public const int UDP_OVERHEAD = 8;
        public const int MAXIMUM_MTU = DEFAULT_MTU - MIN_IP_OVERHEAD - UDP_OVERHEAD; // 1472
        public const int DTLS_RETRANSMISSION_CODE = -1;

        private readonly IDtlsSrtpPeer _connection;
        private readonly int _receiveLimit;
        private readonly int _sendLimit;

        /// <summary>
        /// Received datagrams waiting for BouncyCastle to read them. Each entry is a copy in a pooled
        /// array (the caller's buffer is reused for the next datagram), returned to the pool once read.
        /// </summary>
        private readonly BlockingCollection<ArraySegment<byte>> _data = new BlockingCollection<ArraySegment<byte>>(new ConcurrentQueue<ArraySegment<byte>>());
        private int _isClosed;
        private Certificate _peerCertificate;

        public DatagramTransport Transport { get; internal set; }
        public bool IsClient { get { return _connection is DtlsSrtpClient; } }
        public SrtpKeys Keys { get; private set; }

        public ThreadSafeSrtpSessionContext Context { get; private set; }

        public int TimeoutMilliseconds { get { return _connection.TimeoutMilliseconds; } set { _connection.TimeoutMilliseconds = value; } }

        public event OnDataReadyEvent OnDataReady;

        public event OnDtlsAlertEvent OnAlert;

        /// <param name="connection">The DTLS-SRTP client or server.</param>
        /// <param name="mtu">Path MTU. Records are sized for the worst-case IP overhead
        /// (1500 gives 1408 bytes) so handshake flights still fit when relayed over TURN.</param>
        public DtlsSrtpTransport(IDtlsSrtpPeer connection, int mtu = DEFAULT_MTU)
        {
            this._connection = connection;
            this._receiveLimit = mtu - MIN_IP_OVERHEAD - UDP_OVERHEAD;
            this._sendLimit = mtu - MAX_IP_OVERHEAD - UDP_OVERHEAD;
            this._connection.OnSessionStarted += DtlsSrtpTransport_OnSessionStarted;
            this._connection.OnAlert += DtlsSrtpTransport_OnAlert;
        }

        private void DtlsSrtpTransport_OnSessionStarted(object sender, DtlsSessionStartedEventArgs e)
        {
            this._peerCertificate = e.PeerCertificate;
            this.Context = new ThreadSafeSrtpSessionContext(e.Context);
        }

        private void DtlsSrtpTransport_OnAlert(object sender, DtlsAlertEventArgs args)
        {
            OnAlert?.Invoke(args.Level, args.AlertType, args.Description);
        }

        public bool DoHandshake(out string handshakeError)
        {
            DtlsTransport transport = _connection.DoHandshake(out handshakeError, this, null);
            Transport = transport;
            return string.IsNullOrEmpty(handshakeError);
        }

        public bool IsHandshakeComplete()
        {
            return Transport != null;
        }

        // Span-based to match the fork's ProtectRtpPacket delegate (RTPSession.cs); packets are protected
        // in place, so the caller's buffer needs room past `length` for the auth tag.
        public int ProtectRTP(Span<byte> payload, int length, out int outputBufferLength)
        {
            return Context.ProtectRtp(payload, length, out outputBufferLength);
        }

        public int UnprotectRTP(Span<byte> payload, int length, out int outputBufferLength)
        {
            return Context.UnprotectRtp(payload, length, out outputBufferLength);
        }

        public int ProtectRTCP(Span<byte> payload, int length, out int outputBufferLength)
        {
            return Context.ProtectRtcp(payload, length, out outputBufferLength);
        }

        public int UnprotectRTCP(Span<byte> payload, int length, out int outputBufferLength)
        {
            return Context.UnprotectRtcp(payload, length, out outputBufferLength);
        }

        public Certificate GetRemoteCertificate()
        {
            return _peerCertificate;
        }

        public int GetReceiveLimit() => _receiveLimit;

        public int GetSendLimit() => _sendLimit;

        /// <summary>
        /// Queues a received DTLS datagram. The data is copied, so the caller may reuse its buffer.
        /// </summary>
        public void WriteToRecvStream(ReadOnlySpan<byte> buffer)
        {
            if (Volatile.Read(ref _isClosed) != 0 || buffer.IsEmpty)
            {
                return;
            }

            var chunk = ArrayPool<byte>.Shared.Rent(buffer.Length);
            buffer.CopyTo(chunk);

            try
            {
                _data.Add(new ArraySegment<byte>(chunk, 0, buffer.Length));
            }
            catch (InvalidOperationException)
            {
                // Closed between the check above and the add.
                ArrayPool<byte>.Shared.Return(chunk);
            }
        }

        public void Close()
        {
            // BouncyCastle's DtlsTransport.Close calls back into this Close, so clear Transport first.
            var transport = Transport;
            try
            {
                if (transport != null)
                {
                    Transport = null;
                    transport.Close();
                }
            }
            finally
            {
                if (Interlocked.Exchange(ref _isClosed, 1) == 0)
                {
                    // Wakes any Receive blocked in TryTake so a handshake in progress fails immediately
                    // instead of running on to the handshake timeout.
                    _data.CompleteAdding();
                    while (_data.TryTake(out var item))
                    {
                        ArrayPool<byte>.Shared.Return(item.Array);
                    }
                }
            }
        }

        public void Dispose()
        {
            Close();
        }

        public int Receive(byte[] buf, int off, int len, int waitMillis)
        {
            return Receive(buf.AsSpan(off, len), waitMillis);
        }

        public void Send(byte[] buf, int off, int len)
        {
            // Always hand an owned copy to OnDataReady: the send is asynchronous and BouncyCastle may reuse its buffer.
            OnDataReady?.Invoke(buf.AsSpan(off, len).ToArray());
        }

        public int Receive(Span<byte> buffer, int waitMillis)
        {
            if (Volatile.Read(ref _isClosed) != 0)
            {
                throw new SocketException((int)SocketError.NotConnected);
            }

            if (_data.TryTake(out var item, waitMillis))
            {
                // A datagram larger than the caller's buffer is truncated, as a socket would.
                int count = Math.Min(buffer.Length, item.Count);
                item.AsSpan(0, count).CopyTo(buffer);
                ArrayPool<byte>.Shared.Return(item.Array);
                return count;
            }

            if (Volatile.Read(ref _isClosed) != 0)
            {
                throw new SocketException((int)SocketError.NotConnected);
            }

            return DTLS_RETRANSMISSION_CODE;
        }

        public void Send(ReadOnlySpan<byte> buffer)
        {
            OnDataReady?.Invoke(buffer.ToArray());
        }
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SIPSorcery.Sys;

namespace SIPSorcery.net.RTP
{
    /// <summary>
    /// A basic UDP socket manager. The RTP channel may need both an RTP and Control socket. This class encapsulates
    /// the common logic for UDP socket management.
    /// </summary>
    /// <remarks>
    /// .NET Framework Socket source:
    /// https://referencesource.microsoft.com/#system/net/system/net/Sockets/Socket.cs
    /// .NET Core Socket source:
    /// https://github.com/dotnet/runtime/blob/master/src/libraries/System.Net.Sockets/src/System/Net/Sockets/Socket.cs
    /// Mono Socket source:
    /// https://github.com/mono/mono/blob/master/mcs/class/System/System.Net.Sockets/Socket.cs
    /// </remarks>
    public class UdpReceiver
    {
        protected const int RECEIVE_BUFFER_SIZE = 2048;
        protected static ILogger logger = Log.Logger;

        protected readonly Socket m_socket;
        protected readonly byte[] m_recvBuffer;
        protected bool m_isClosed;
        private bool m_isRunningReceive;
        protected readonly IPEndPoint m_localEndPoint;
        protected readonly EndPoint m_anyEndPoint;

        public bool IsClosed => m_isClosed;
        public bool IsRunningReceive => m_isRunningReceive;

        public event Action<UdpReceiver, int, IPEndPoint, Memory<byte>> OnPacketReceived;
        public event Action<string> OnClosed;

        public UdpReceiver(Socket socket, int mtu = RECEIVE_BUFFER_SIZE)
        {
            m_socket = socket;
            m_localEndPoint = m_socket.LocalEndPoint as IPEndPoint;
            m_recvBuffer = new byte[mtu];
            m_anyEndPoint = m_socket.LocalEndPoint.AddressFamily == AddressFamily.InterNetwork ?
                new IPEndPoint(IPAddress.Any, 0) : new IPEndPoint(IPAddress.IPv6Any, 0);
        }

        /// <summary>
        /// Starts the receive loop.
        /// </summary>
        public void Start()
        {
            if (m_isRunningReceive || m_isClosed)
            {
                return;
            }
            m_isRunningReceive = true;
            // Fire and forget the receive loop.
            _ = ReceiveLoopAsync();
        }

        /// <summary>
        /// The main non-blocking receive loop. Replaces the old Begin/EndReceiveFrom pattern.
        /// </summary>
        protected virtual async Task ReceiveLoopAsync()
        {
            var buffer = m_recvBuffer.AsMemory();
            while (!m_isClosed)
            {
                try
                {
                    var result = await m_socket.ReceiveFromAsync(buffer, SocketFlags.None, m_anyEndPoint).ConfigureAwait(false);
                    if (result.ReceivedBytes > 0)
                    {
                        RaisePacketReceived((IPEndPoint)result.RemoteEndPoint, buffer.Slice(0, result.ReceivedBytes));
                    }
                }
                catch (SocketException sockExcp)
                {
                    // This exception is expected when a remote client disconnects (ICMP port unreachable).
                    // We log it but continue the loop without closing, which prevents stutters for other clients.
                    logger.LogTrace($"SocketException in UdpReceiver loop ({sockExcp.SocketErrorCode}): {sockExcp.Message}");
                }
                catch (ObjectDisposedException)
                {
                    // The socket was closed, so we can safely exit the loop.
                    break;
                }
                catch (Exception excp)
                {
                    // For any other unexpected errors, log it and close the receiver.
                    logger.LogError(excp, $"Exception in UdpReceiver.ReceiveLoopAsync: {excp.Message}");
                    Close(excp.Message);
                    break;
                }
            }
            m_isRunningReceive = false;
        }

        /// <summary>
        /// This helper method allows the base class and any derived classes to safely
        /// invoke the OnPacketReceived event.
        /// </summary>
        protected virtual void RaisePacketReceived(IPEndPoint remoteEndPoint, Memory<byte> packet)
        {
            OnPacketReceived?.Invoke(this, m_localEndPoint.Port, remoteEndPoint, packet);
        }

        /// <summary>
        /// Closes the socket and stops the receive loop.
        /// </summary>
        public virtual void Close(string reason)
        {
            if (!m_isClosed)
            {
                m_isClosed = true;
                try { m_socket?.Close(); }
                catch { }
                OnClosed?.Invoke(reason);
            }
        }
    }

}

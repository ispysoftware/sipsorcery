using System;
using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using System.Threading.Tasks;
using SIPSorcery.net.RTP;
using SIPSorcery.Net;

namespace SIPSorcery.net.ICE
{
    public class IceTcpReceiver : UdpReceiver
    {
        protected const int REVEIVE_TCP_BUFFER_SIZE = RECEIVE_BUFFER_SIZE * 2;

        protected int m_recvOffset;

        public IceTcpReceiver(Socket socket, int mtu = REVEIVE_TCP_BUFFER_SIZE) : base(socket, mtu)
        {
            m_recvOffset = 0;
        }

        /// <summary>
        /// Overrides the base class's receive loop with one suitable for a TCP stream.
        /// This loop manages a buffer that can hold partial messages between reads.
        /// </summary>
        protected override async Task ReceiveLoopAsync()
        {
            var bufferSegment = new Memory<byte>(m_recvBuffer);

            while (!m_isClosed && m_socket.Connected)
            {
                try
                {
                    // Receive new data, appending it after any leftover data from the previous read.
                    int bytesRead = await m_socket.ReceiveAsync(bufferSegment.Slice(m_recvOffset), SocketFlags.None).ConfigureAwait(false);

                    if (bytesRead > 0)
                    {
                        // Process the entire buffer which now contains old + new data.
                        // The ProcessRawBuffer method will parse STUN messages and update m_recvOffset.
                        ProcessRawBuffer(bytesRead + m_recvOffset, m_socket.RemoteEndPoint as IPEndPoint);
                    }
                    else
                    {
                        // A return value of 0 indicates the remote side has gracefully closed the connection.
                        Close("remote side closed");
                        break;
                    }
                }
                catch (SocketException sockExcp)
                {
                    logger.LogWarning($"SocketException in IceTcpReceiver loop ({sockExcp.SocketErrorCode}): {sockExcp.Message}");
                    // For TCP, a socket error is often fatal for the connection.
                    Close(sockExcp.Message);
                    break;
                }
                catch (ObjectDisposedException)
                {
                    // The socket was closed, so we can safely exit the loop.
                    break;
                }
                catch (Exception excp)
                {
                    logger.LogError(excp, $"Exception in IceTcpReceiver.ReceiveLoopAsync: {excp.Message}");
                    Close(excp.Message);
                    break;
                }
            }
        }

        // This is the custom logic for this class that we want to preserve.
        // It processes the buffer to extract one or more STUN messages from the TCP stream.
        protected virtual int ProcessRawBuffer(int bytesRead, IPEndPoint remoteEP)
        {
            var extractCount = 0;
            if (bytesRead > 0)
            {
                var isFragmented = true;
                var recvRemainingSegment = new ArraySegment<byte>(m_recvBuffer, 0, bytesRead);

                while (recvRemainingSegment.Count > STUNHeader.STUN_HEADER_LENGTH)
                {
                    isFragmented = false;
                    STUNHeader header = null;
                    try
                    {
                        header = STUNHeader.ParseSTUNHeader(recvRemainingSegment);
                    }
                    catch
                    {
                        header = null;
                    }
                    if (header != null)
                    {
                        int stunMsgBytes = STUNHeader.STUN_HEADER_LENGTH + header.MessageLength;
                        if (stunMsgBytes % 4 != 0)
                        {
                            stunMsgBytes = stunMsgBytes - (stunMsgBytes % 4) + 4;
                        }

                        //We have the packet count all inside current receiving buffer
                        if (recvRemainingSegment.Count >= stunMsgBytes)
                        {
                            extractCount++;
                            m_recvOffset = recvRemainingSegment.Offset + recvRemainingSegment.Count;

                            byte[] packetBuffer = new byte[stunMsgBytes];
                            Buffer.BlockCopy(recvRemainingSegment.Array, recvRemainingSegment.Offset, packetBuffer, 0, stunMsgBytes);

                            RaisePacketReceived(remoteEP, packetBuffer);

                            var newOffset = recvRemainingSegment.Offset + stunMsgBytes;
                            var newCount = recvRemainingSegment.Count - stunMsgBytes;
                            if (newCount > STUNHeader.STUN_HEADER_LENGTH && newOffset >= 0)
                            {
                                recvRemainingSegment = new ArraySegment<byte>(recvRemainingSegment.Array, newOffset, newCount);
                            }
                            else
                            {
                                if (newCount > 0 && newOffset >= 0)
                                {
                                    recvRemainingSegment = new ArraySegment<byte>(recvRemainingSegment.Array, newOffset, newCount);
                                    isFragmented = true;
                                }
                                else
                                {
                                    recvRemainingSegment = new ArraySegment<byte>();
                                    isFragmented = false;
                                }
                                break;
                            }
                        }
                        //We have a fragmentation but the header is intact, we need to cache the fragmentation for the next receive cycle
                        else
                        {
                            isFragmented = true;
                            break;
                        }
                    }
                    //Save Remaining Buffer in start of m_recvBuffer
                    else
                    {
                        isFragmented = true;
                        break;
                    }
                }

                if (isFragmented)
                {
                    m_recvOffset = recvRemainingSegment.Count;
                    Buffer.BlockCopy(recvRemainingSegment.Array, recvRemainingSegment.Offset, m_recvBuffer, 0, recvRemainingSegment.Count);
                }
                else
                {
                    m_recvOffset = 0;
                }
            }

            return extractCount;
        }

        /// <summary>
        /// Closes the socket and stops any new receives from being initiated.
        /// </summary>
        public override void Close(string reason)
        {
            if (!m_isClosed)
            {
                if (m_socket != null && m_socket.Connected)
                {
                    try { m_socket?.Disconnect(false); }
                    catch { }
                }
                base.Close(reason);
            }
        }
    }
}

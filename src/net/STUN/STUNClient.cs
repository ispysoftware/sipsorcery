using System;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SIPSorcery.Sys;

namespace SIPSorcery.Net;

public class STUNClient
{
    public const int DEFAULT_STUN_PORT = 3478;
    private const int STUN_SERVER_RESPONSE_TIMEOUT_SECONDS = 3;

    private static readonly ILogger logger = Log.Logger;

    // This synchronous method is kept for backward compatibility.
    // It calls the new async version and blocks for the result.
    //public static IPEndPoint GetPublicIPEndPoint(string stunServer, int port = DEFAULT_STUN_PORT) =>
    //    GetPublicIPEndPointAsync(stunServer, port).GetAwaiter().GetResult();

    /// <summary>
    /// Asynchronously gets the public IP address and port as seen by a STUN server.
    /// </summary>
    public static async Task<IPEndPoint> GetPublicIPEndPointAsync(string stunServer, int port = DEFAULT_STUN_PORT)
    {
        try
        {
            logger.LogDebug("STUNClient attempting to determine public IP from {stunServer}.", stunServer);

            using var udpClient = new UdpClient(stunServer, port);

            var initMessage = new STUNMessage(STUNMessageTypesEnum.BindingRequest);
            byte[] stunMessageBytes = initMessage.ToByteBuffer(null, false);
            await udpClient.SendAsync(stunMessageBytes, stunMessageBytes.Length);

            var receiveTask = udpClient.ReceiveAsync();
            var delayTask = Task.Delay(TimeSpan.FromSeconds(STUN_SERVER_RESPONSE_TIMEOUT_SECONDS));

            var winner = await Task.WhenAny(receiveTask, delayTask);

            if (winner != receiveTask)
            {
                logger.LogWarning("STUNClient server response timed out after {Timeout}s.", STUN_SERVER_RESPONSE_TIMEOUT_SECONDS);
                return null;
            }

            var result = await receiveTask; // This won't block as the task is already complete.

            if (result.Buffer?.Length > 0)
            {
                var stunResponse = STUNMessage.ParseSTUNMessage(result.Buffer);

                foreach (var attr in stunResponse.Attributes)
                {
                    if (attr is STUNXORAddressAttribute xorAttr)
                    {
                        var publicEndPoint = new IPEndPoint(xorAttr.Address, xorAttr.Port);
                        logger.LogDebug("STUNClient Public IP={address} Port={port} (from XOR-MAPPED-ADDRESS).", publicEndPoint.Address, publicEndPoint.Port);
                        return publicEndPoint;
                    }
                    // If it's not the XOR type, then check for the general base type.
                    // This will now only match the plain MAPPED-ADDRESS.
                    else if (attr is STUNAddressAttribute mapAttr)
                    {
                        var publicEndPoint = new IPEndPoint(mapAttr.Address, mapAttr.Port);
                        logger.LogDebug("STUNClient Public IP={address} Port={port} (from MAPPED-ADDRESS).", publicEndPoint.Address, publicEndPoint.Port);
                        return publicEndPoint;
                    }
                }
            }

            return null;
        }
        catch (Exception excp)
        {
            logger.LogError(excp, "Exception STUNClient GetPublicIPEndPointAsync. {ErrorMessage}", excp.Message);
            return null;
        }
    }

    /// <summary>
    /// Gets the public IP address and port for an existing RTP Channel.
    /// </summary>
    public static async Task<IPEndPoint> GetPublicIPEndPointForSocketAsync(
        IPEndPoint stunServer,
        RTPChannel rtpChannel)
    {
        var tcs = new TaskCompletionSource<IPEndPoint>(TaskCreationOptions.RunContinuationsAsynchronously);

        void OnRtpDataReceived(int localPort, IPEndPoint remoteEndPoint, Memory<byte> packet)
        {
            // Note: The method signature is updated to Memory<byte> to avoid issues.
            try
            {
                if (!packet.IsEmpty)
                {
                    // ParseSTUNMessage now takes a single ReadOnlyMemory<byte> argument.
                    var stunResponse = STUNMessage.ParseSTUNMessage(packet);
                    IPEndPoint result = null;

                    foreach (var attr in stunResponse.Attributes)
                    {
                        if (attr is STUNAddressAttribute stunAddress)
                        {
                            result = new IPEndPoint(stunAddress.Address, stunAddress.Port);
                            break;
                        }
                    }

                    if (result != null)
                    {
                        logger.LogDebug("STUNClient public IP={PublicAddress} Port={PublicPort}.", result.Address, result.Port);
                    }

                    tcs.TrySetResult(result);
                }
            }
            catch (Exception ex)
            {
                tcs.TrySetException(ex);
            }
        }

        rtpChannel.OnRTPDataReceived += OnRtpDataReceived;

        try
        {
            var initMessage = new STUNMessage(STUNMessageTypesEnum.BindingRequest);
            var bytes = initMessage.ToByteBuffer(null, false);
            await rtpChannel.SendAsync(RTPChannelSocketsEnum.RTP, stunServer, bytes);

            var delayTask = Task.Delay(TimeSpan.FromSeconds(STUN_SERVER_RESPONSE_TIMEOUT_SECONDS));
            if (await Task.WhenAny(tcs.Task, delayTask) == delayTask)
            {
                logger.LogWarning("STUNClient server response timed out after {Timeout}s.", STUN_SERVER_RESPONSE_TIMEOUT_SECONDS);
                return null;
            }

            return await tcs.Task;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Exception in STUNClient.GetPublicIPEndPointForSocketAsync: {ErrorMessage}", ex.Message);
            return null;
        }
        finally
        {
            rtpChannel.OnRTPDataReceived -= OnRtpDataReceived;
        }
    }
}

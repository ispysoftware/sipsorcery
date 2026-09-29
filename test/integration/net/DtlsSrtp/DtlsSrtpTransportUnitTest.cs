//-----------------------------------------------------------------------------
// Filename: DtlsSrtpTransportUnitTest.cs
//
// Description: Unit tests for the DtlsSrtpTransport class.
//
// History:
// 03 Jul 2020	Aaron Clauson	Created.
// 14 Dec 2020  Aaron Clauson   Moved from unit to integration tests (while not
//              really integration tests the duration is long'ish for a unit test).
// Sep 2026     iSpyConnect     SharpSRTP port: WebRTC peer handshake with SRTP/SRTCP
//                              round trip, close during handshake.
//
// License:
// BSD 3-Clause "New" or "Revised" License, see included LICENSE.md file.
//-----------------------------------------------------------------------------

using System;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using SIPSorcery.Net.SharpSRTP.DTLSSRTP;
using Xunit;

namespace SIPSorcery.Net.IntegrationTests
{
    [Trait("Category", "integration")]
    public class DtlsSrtpTransportUnitTest
    {
        private Microsoft.Extensions.Logging.ILogger logger = null;

        public DtlsSrtpTransportUnitTest(Xunit.Abstractions.ITestOutputHelper output)
        {
            logger = SIPSorcery.UnitTests.TestLogHelper.InitTestLogger(output);
        }

        /// <summary>
        /// Tests that creating a new client DtlsSrtpTransport instance works correctly.
        /// </summary>
        [Fact]
        public void CreateClientInstanceUnitTest()
        {
            logger.LogDebug("--> {MethodName}", System.Reflection.MethodBase.GetCurrentMethod().Name);
            logger.BeginScope(System.Reflection.MethodBase.GetCurrentMethod().Name);

            var crypto = new BcTlsCrypto();
            (var tlsCert, var pvtKey) = DtlsUtils.CreateSelfSignedTlsCert(crypto);
            DtlsSrtpTransport dtlsTransport = new DtlsSrtpTransport(new DtlsSrtpClient(crypto, tlsCert, pvtKey));

            Assert.NotNull(dtlsTransport);
        }

        /// <summary>
        /// Tests that creating a new server DtlsSrtpTransport instance works correctly.
        /// </summary>
        [Fact]
        public void CreateServerInstanceUnitTest()
        {
            logger.LogDebug("--> {MethodName}", System.Reflection.MethodBase.GetCurrentMethod().Name);
            logger.BeginScope(System.Reflection.MethodBase.GetCurrentMethod().Name);

            DtlsSrtpTransport dtlsTransport = new DtlsSrtpTransport(new DtlsSrtpServer(new BcTlsCrypto()));

            Assert.NotNull(dtlsTransport);
        }

        /// <summary>
        /// Tests that creating a client and server DtlsSrtpTransport can perform a DTLS
        /// handshake successfully.
        /// </summary>
        [Fact]
        public async Task DoHandshakeUnitTest()
        {
            logger.LogDebug("--> {MethodName}", System.Reflection.MethodBase.GetCurrentMethod().Name);
            logger.BeginScope(System.Reflection.MethodBase.GetCurrentMethod().Name);

            var dtlsClient = new DtlsSrtpClient(new BcTlsCrypto());
            var dtlsServer = new DtlsSrtpServer(new BcTlsCrypto());

            var (dtlsClientTransport, dtlsServerTransport) = await HandshakeAsync(dtlsClient, dtlsServer, 5000);

            logger.LogDebug("DTLS client fingerprint       : {Fingerprint}", DtlsUtils.Fingerprint(dtlsClient.Certificate));
            logger.LogDebug("DTLS server fingerprint       : {Fingerprint}", DtlsUtils.Fingerprint(dtlsServer.Certificate));

            Assert.NotNull(dtlsClientTransport.GetRemoteCertificate());
            Assert.NotNull(dtlsServerTransport.GetRemoteCertificate());
        }

        /// <summary>
        /// Tests the peers RTCPeerConnection uses: a DTLS handshake between the WebRTC client and server
        /// with self-signed ECDSA certificates, fingerprints that match the certificates each side was
        /// given, and SRTP/SRTCP packets protected in place by one side and recovered by the other.
        /// </summary>
        [Fact]
        public async Task WebRtcPeersHandshakeAndSrtpRoundTripUnitTest()
        {
            logger.LogDebug("--> {MethodName}", System.Reflection.MethodBase.GetCurrentMethod().Name);
            logger.BeginScope(System.Reflection.MethodBase.GetCurrentMethod().Name);

            var crypto = new BcTlsCrypto();
            (var clientCert, var clientKey) = DtlsUtils.CreateSelfSignedTlsCert(crypto);
            (var serverCert, var serverKey) = DtlsUtils.CreateSelfSignedTlsCert(crypto);

            var client = new WebRtcDtlsSrtpClient(crypto, clientCert, clientKey, SignatureAlgorithm.ecdsa);
            var server = new WebRtcDtlsSrtpServer(crypto, serverCert, serverKey, SignatureAlgorithm.ecdsa);

            var (clientTransport, serverTransport) = await HandshakeAsync(client, server, 5000);

            // Each side sees the other's certificate, as the SDP fingerprint check in RTCPeerConnection expects.
            var serverFingerprint = DtlsUtils.Fingerprint(serverCert);
            var seenByClient = DtlsUtils.Fingerprint(serverFingerprint.algorithm, clientTransport.GetRemoteCertificate().GetCertificateAt(0));
            Assert.Equal(serverFingerprint.value, seenByClient.value);

            var clientFingerprint = DtlsUtils.Fingerprint(clientCert);
            var seenByServer = DtlsUtils.Fingerprint(clientFingerprint.algorithm, serverTransport.GetRemoteCertificate().GetCertificateAt(0));
            Assert.Equal(clientFingerprint.value, seenByServer.value);

            // SRTP: client -> server and server -> client, across the 16-bit sequence wrap (ROC increment).
            foreach (ushort seq in new ushort[] { 0xFFFD, 0xFFFE, 0xFFFF, 0, 1, 2 })
            {
                AssertRtpRoundTrip(clientTransport, serverTransport, seq, 0x11111111);
                AssertRtpRoundTrip(serverTransport, clientTransport, seq, 0x22222222);
            }

            // SRTCP both ways.
            for (int i = 0; i < 3; i++)
            {
                AssertRtcpRoundTrip(clientTransport, serverTransport, 0x11111111);
                AssertRtcpRoundTrip(serverTransport, clientTransport, 0x22222222);
            }

            // A replayed SRTP packet is rejected.
            var replay = BuildRtpPacket(5, 0x11111111, out int replayLen);
            Assert.Equal(0, clientTransport.ProtectRTP(replay, replayLen, out int protectedLen));
            var copy = (byte[])replay.Clone();
            Assert.Equal(0, serverTransport.UnprotectRTP(replay, protectedLen, out _));
            Assert.NotEqual(0, serverTransport.UnprotectRTP(copy, protectedLen, out _));
        }

        /// <summary>
        /// Tests that closing the transport while a handshake is waiting for the peer ends the handshake
        /// promptly rather than at the handshake timeout.
        /// </summary>
        [Fact]
        public async Task CloseDuringHandshakeUnitTest()
        {
            logger.LogDebug("--> {MethodName}", System.Reflection.MethodBase.GetCurrentMethod().Name);
            logger.BeginScope(System.Reflection.MethodBase.GetCurrentMethod().Name);

            var crypto = new BcTlsCrypto();
            (var cert, var key) = DtlsUtils.CreateSelfSignedTlsCert(crypto);
            var clientTransport = new DtlsSrtpTransport(new WebRtcDtlsSrtpClient(crypto, cert, key, SignatureAlgorithm.ecdsa));
            clientTransport.TimeoutMilliseconds = 20000;

            var sw = Stopwatch.StartNew();
            var handshake = Task.Run(() => clientTransport.DoHandshake(out _));
            await Task.Delay(300);
            clientTransport.Close();

            var winner = await Task.WhenAny(handshake, Task.Delay(5000));
            Assert.Same(handshake, winner);
            Assert.False(await handshake);
            Assert.True(sw.ElapsedMilliseconds < 5000);
        }

        /// <summary>
        /// Tests that attempting a client handshake times out correctly.
        /// </summary>
        [Fact]
        public async Task DoHandshakeClientTimeoutUnitTest()
        {
            logger.LogDebug("--> {MethodName}", System.Reflection.MethodBase.GetCurrentMethod().Name);
            logger.BeginScope(System.Reflection.MethodBase.GetCurrentMethod().Name);

            DtlsSrtpTransport dtlsClientTransport = new DtlsSrtpTransport(new DtlsSrtpClient(new BcTlsCrypto()));
            dtlsClientTransport.TimeoutMilliseconds = 2000;

            var result = await Task.Run<bool>(() => dtlsClientTransport.DoHandshake(out _));

            Assert.False(result);
        }

        /// <summary>
        /// Tests that attempting a server handshake times out correctly.
        /// </summary>
        [Fact]
        public async Task DoHandshakeServerTimeoutUnitTest()
        {
            logger.LogDebug("--> {MethodName}", System.Reflection.MethodBase.GetCurrentMethod().Name);
            logger.BeginScope(System.Reflection.MethodBase.GetCurrentMethod().Name);

            DtlsSrtpTransport dtlsServerTransport = new DtlsSrtpTransport(new DtlsSrtpServer(new BcTlsCrypto()));
            dtlsServerTransport.TimeoutMilliseconds = 2000;

            var result = await Task.Run<bool>(() => dtlsServerTransport.DoHandshake(out _));

            Assert.False(result);
        }

        private async Task<(DtlsSrtpTransport client, DtlsSrtpTransport server)> HandshakeAsync(IDtlsSrtpPeer client, IDtlsSrtpPeer server, int timeout)
        {
            var clientTransport = new DtlsSrtpTransport(client) { TimeoutMilliseconds = timeout };
            var serverTransport = new DtlsSrtpTransport(server) { TimeoutMilliseconds = timeout };

            clientTransport.OnDataReady += (buf) => serverTransport.WriteToRecvStream(buf);
            serverTransport.OnDataReady += (buf) => clientTransport.WriteToRecvStream(buf);

            var serverTask = Task.Run(() => serverTransport.DoHandshake(out _));
            var clientTask = Task.Run(() => clientTransport.DoHandshake(out _));

            var both = Task.WhenAll(serverTask, clientTask);
            if (await Task.WhenAny(both, Task.Delay(timeout)) != both)
            {
                Assert.Fail($"Test timed out after {timeout}ms.");
            }

            Assert.True(await serverTask);
            Assert.True(await clientTask);

            return (clientTransport, serverTransport);
        }

        private static byte[] BuildRtpPacket(ushort seq, uint ssrc, out int length)
        {
            const int payloadLength = 100;
            length = 12 + payloadLength;
            var packet = new byte[length + RTPSession.SRTP_MAX_PREFIX_LENGTH];
            packet[0] = 0x80;
            packet[1] = 96;
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2), seq);
            BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(4), 90000u * seq);
            BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(8), ssrc);
            for (int i = 0; i < payloadLength; i++)
            {
                packet[12 + i] = (byte)(i + seq);
            }
            return packet;
        }

        private static void AssertRtpRoundTrip(DtlsSrtpTransport sender, DtlsSrtpTransport receiver, ushort seq, uint ssrc)
        {
            var packet = BuildRtpPacket(seq, ssrc, out int length);
            var original = packet.AsSpan(0, length).ToArray();

            Assert.Equal(0, sender.ProtectRTP(packet, length, out int protectedLength));
            Assert.True(protectedLength > length);
            Assert.False(packet.AsSpan(12, length - 12).SequenceEqual(original.AsSpan(12)));

            Assert.Equal(0, receiver.UnprotectRTP(packet, protectedLength, out int plainLength));
            Assert.Equal(length, plainLength);
            Assert.True(packet.AsSpan(0, plainLength).SequenceEqual(original));
        }

        private static void AssertRtcpRoundTrip(DtlsSrtpTransport sender, DtlsSrtpTransport receiver, uint ssrc)
        {
            // Receiver report with one report block.
            const int length = 32;
            var packet = new byte[length + RTPSession.SRTP_MAX_PREFIX_LENGTH];
            packet[0] = 0x81;
            packet[1] = 201;
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2), (length / 4) - 1);
            BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(4), ssrc);
            for (int i = 8; i < length; i++)
            {
                packet[i] = (byte)i;
            }
            var original = packet.AsSpan(0, length).ToArray();

            Assert.Equal(0, sender.ProtectRTCP(packet, length, out int protectedLength));
            Assert.True(protectedLength > length);

            Assert.Equal(0, receiver.UnprotectRTCP(packet, protectedLength, out int plainLength));
            Assert.Equal(length, plainLength);
            Assert.True(packet.AsSpan(0, plainLength).SequenceEqual(original));
        }
    }
}

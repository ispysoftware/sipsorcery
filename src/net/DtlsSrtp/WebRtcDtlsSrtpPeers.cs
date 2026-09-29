//-----------------------------------------------------------------------------
// Filename: WebRtcDtlsSrtpPeers.cs
//
// Description: WebRTC settings for the SharpSRTP DTLS-SRTP client and server:
// the SRTP protection profiles offered, no MKI (RFC 8827) and tolerance of
// peers without renegotiation_info (Pion).
//
// History:
// Sep 2026     iSpyConnect     Created for the SharpSRTP port.
//
// License:
// BSD 3-Clause "New" or "Revised" License, see included LICENSE.md file.
//-----------------------------------------------------------------------------

using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;
using SIPSorcery.Net.SharpSRTP.DTLSSRTP;

namespace SIPSorcery.Net
{
    internal static class WebRtcSrtpProfiles
    {
        // SRTP protection profiles, in preference order, matching what the previous DTLS-SRTP code negotiated:
        // the client offers only AES128_CM_HMAC_SHA1_80; the server prefers it and falls back to _32.
        // Browsers also accept SRTP_AEAD_AES_128_GCM / SRTP_AEAD_AES_256_GCM (16 byte tag); MediaStream reserves
        // room for either, so GCM can be enabled by adding them here once tested.

        internal static readonly int[] ClientOffered =
        {
            SrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_80,
        };

        internal static readonly int[] ServerAccepted =
        {
            SrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_80,
            SrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_32,
        };
    }

    public class WebRtcDtlsSrtpClient : DtlsSrtpClient
    {
        public WebRtcDtlsSrtpClient(TlsCrypto crypto, Certificate certificate, AsymmetricKeyParameter privateKey, short certificateSignatureAlgorithm)
            : base(crypto, certificate, privateKey, certificateSignatureAlgorithm)
        { }

        protected override int[] GetSupportedProtectionProfiles()
        {
            // Called from the base constructor, so it must not depend on instance state.
            return WebRtcSrtpProfiles.ClientOffered;
        }

        // BouncyCastle's initial DTLS handshake resend timer is 1000ms (doubling on each retry); the previous
        // transport retried from ~100ms. RFC 6347 4.2.4.1 allows a shorter initial timer: 250ms recovers a lost
        // first flight quickly without flooding high-RTT (e.g. TURN relayed) links.
        public override int GetHandshakeResendTimeMillis() => 250;
    }

    public class WebRtcDtlsSrtpServer : DtlsSrtpServer
    {
        private static readonly ILogger logger = LogFactory.CreateLogger<WebRtcDtlsSrtpServer>();

        public WebRtcDtlsSrtpServer(TlsCrypto crypto, Certificate certificate, AsymmetricKeyParameter privateKey, short certificateSignatureAlgorithm)
            : base(crypto, certificate, privateKey, certificateSignatureAlgorithm)
        {
            // RFC 8827: an SRTP Master Key Identifier MUST NOT be used.
            ForceDisableMKI = true;
        }

        protected override int[] GetSupportedProtectionProfiles()
        {
            return WebRtcSrtpProfiles.ServerAccepted;
        }

        // See WebRtcDtlsSrtpClient.GetHandshakeResendTimeMillis.
        public override int GetHandshakeResendTimeMillis() => 250;

        /// <summary>
        /// This override prevents a TLS fault from being generated if a "Client Hello" is received that
        /// does not support TLS renegotiation (https://tools.ietf.org/html/rfc5746).
        /// This override is required to be able to complete a DTLS handshake with the Pion WebRTC library,
        /// see https://github.com/pion/dtls/issues/274.
        /// </summary>
        public override void NotifySecureRenegotiation(bool secureRenegotiation)
        {
            if (!secureRenegotiation)
            {
                logger.LogWarning("DTLS server received a client handshake without renegotiation support.");
            }
        }
    }
}

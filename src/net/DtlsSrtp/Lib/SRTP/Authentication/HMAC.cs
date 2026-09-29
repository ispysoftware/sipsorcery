// SharpSRTP
// Copyright (C) 2025 Lukas Volf
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE 
// SOFTWARE.
// Modified for Agent DVR: allocation-free tag generation into a caller-supplied span (.NET IncrementalHash or BouncyCastle IMac).

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Macs;
using System;
using System.Security.Cryptography;
#if NET8_0_OR_GREATER
using ReadOnlyBytes = System.ReadOnlySpan<byte>;
#else
using ReadOnlyBytes = System.ArraySegment<byte>;
#endif

namespace SIPSorcery.Net.SharpSRTP.SRTP.Authentication
{
    public static class HMAC
    {
        /// <summary>
        /// Full HMAC-SHA1 output length in bytes. SRTP/SRTCP tags are this value truncated to N_tag.
        /// </summary>
        public const int HMAC_SHA1_LENGTH = 20;

        public static byte[] GenerateAuthTag(HMac hmac, ReadOnlyBytes payload)
        {
#if NET8_0_OR_GREATER
            hmac.BlockUpdate(payload);
#else
            hmac.BlockUpdate(payload.Array, payload.Offset, payload.Count);
#endif

            byte[] output = new byte[hmac.GetMacSize()];
            hmac.DoFinal(output, 0);

            return output;
        }

        /// <summary>
        /// Computes the full MAC of <paramref name="payload"/> || <paramref name="suffix"/> into <paramref name="tag"/>
        /// using a keyed, reusable .NET <see cref="IncrementalHash"/>. The hash is reset afterwards, ready for the next packet.
        /// </summary>
        /// <param name="suffix">Bytes authenticated after the payload (the SRTP ROC); may be empty.</param>
        /// <param name="tag">Receives the full MAC; must be at least <see cref="IncrementalHash.HashLengthInBytes"/> long.</param>
        public static void GenerateAuthTag(IncrementalHash hmac, ReadOnlySpan<byte> payload, ReadOnlySpan<byte> suffix, Span<byte> tag)
        {
            hmac.AppendData(payload);
            if (!suffix.IsEmpty)
            {
                hmac.AppendData(suffix);
            }

            if (!hmac.TryGetHashAndReset(tag, out _))
            {
                throw new ArgumentException("Destination is too small for the authentication tag.", nameof(tag));
            }
        }

        /// <summary>
        /// BouncyCastle equivalent of <see cref="GenerateAuthTag(IncrementalHash, ReadOnlySpan{byte}, ReadOnlySpan{byte}, Span{byte})"/>.
        /// </summary>
        public static void GenerateAuthTag(IMac hmac, ReadOnlySpan<byte> payload, ReadOnlySpan<byte> suffix, Span<byte> tag)
        {
            hmac.BlockUpdate(payload);
            if (!suffix.IsEmpty)
            {
                hmac.BlockUpdate(suffix);
            }

            hmac.DoFinal(tag);
        }
    }
}

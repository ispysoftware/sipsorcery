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
// Modified for Agent DVR: .NET AesGcm seal/open and a keyed-once BouncyCastle GCM path (no per-packet key schedule).

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Buffers.Binary;
using System.Security.Cryptography;
#if NET8_0_OR_GREATER
using ReadOnlyBytes = System.ReadOnlySpan<byte>;
using Bytes = System.Span<byte>;
#else
using ReadOnlyBytes = System.ArraySegment<byte>;
using Bytes = System.ArraySegment<byte>;
#endif

namespace SIPSorcery.Net.SharpSRTP.SRTP.Encryption
{
    public static class AEAD
    {
        public const int BLOCK_SIZE = 12;

        /// <summary>
        /// Length of the nonce used to prime an engine in <see cref="SetKey"/>. It differs from the 12-byte SRTP nonce, so
        /// BouncyCastle GCM's encrypt-side "cannot reuse nonce" check (which compares against the previous Init's nonce)
        /// can never fire on the first real packet.
        /// </summary>
        private const int PRIMING_NONCE_LENGTH = 16;

        public static void Encrypt(IAeadBlockCipher engine, bool encrypt, ReadOnlyBytes input, Bytes output, byte[] iv, byte[] K_e, int N_tag, ReadOnlyBytes associatedData)
        {
            Encrypt(engine, encrypt, input, output, iv, new KeyParameter(K_e), N_tag, associatedData);
        }

        public static void Encrypt(IAeadBlockCipher engine, bool encrypt, ReadOnlyBytes input, Bytes output, byte[] iv, KeyParameter K_e, int N_tag, ReadOnlyBytes associatedData)
        {
            var parameters = new AeadParameters(K_e, N_tag << 3, iv);
            engine.Init(encrypt, parameters);

            engine.ProcessAadBytes(associatedData);

            int len = engine.ProcessBytes(input, output);

            // throws when the MAC fails to match
            engine.DoFinal(output.Slice(len));
        }

        /// <summary>
        /// Keys a BouncyCastle GCM engine once. Afterwards use <see cref="EncryptWithPresetKey"/>, which re-Inits per packet
        /// with a null key: GcmBlockCipher then keeps the AES key schedule and the GHASH key H instead of rebuilding them.
        /// GCM only (the null-key re-Init is GcmBlockCipher behaviour).
        /// </summary>
        public static void SetKey(IAeadBlockCipher engine, KeyParameter K_e, int N_tag)
        {
            engine.Init(false, new AeadParameters(K_e, N_tag << 3, new byte[PRIMING_NONCE_LENGTH]));
        }

        /// <summary>
        /// Same as the KeyParameter overload of Encrypt, for an engine keyed by <see cref="SetKey"/>. Output is ciphertext || tag when encrypting; throws
        /// <see cref="InvalidCipherTextException"/> when decryption fails authentication.
        /// </summary>
        public static void EncryptWithPresetKey(IAeadBlockCipher engine, bool encrypt, ReadOnlyBytes input, Bytes output, byte[] iv, int N_tag, ReadOnlyBytes associatedData)
        {
            Encrypt(engine, encrypt, input, output, iv, (KeyParameter)null, N_tag, associatedData);
        }

        /// <summary>
        /// AES-GCM encrypt with the .NET system implementation. Writes ciphertext || tag to <paramref name="output"/>, byte-identical
        /// to the BouncyCastle path. <paramref name="plaintext"/> and <paramref name="output"/> may start at the same address (SRTP
        /// protects in place).
        /// </summary>
        public static void Encrypt(AesGcm aesGcm, ReadOnlySpan<byte> plaintext, Span<byte> output, ReadOnlySpan<byte> nonce, int N_tag, ReadOnlySpan<byte> associatedData)
        {
            var ciphertext = output.Slice(0, plaintext.Length);

            // AesGcm needs plaintext and ciphertext to be the same memory or disjoint. In-place protection (same start) and separate
            // buffers are both fine; a shifted, partially overlapping pair is moved into place first and then encrypted in place.
            if (plaintext.Overlaps((ReadOnlySpan<byte>)ciphertext, out int elementOffset) && elementOffset != 0)
            {
                plaintext.CopyTo(ciphertext);
                plaintext = ciphertext;
            }

            aesGcm.Encrypt(nonce, plaintext, ciphertext, output.Slice(plaintext.Length, N_tag), associatedData);
        }

        /// <summary>
        /// AES-GCM decrypt with the .NET system implementation. <paramref name="input"/> is ciphertext || tag; the plaintext is
        /// written to the start of <paramref name="output"/>, which may be the same memory as <paramref name="input"/>.
        /// Throws <see cref="AuthenticationTagMismatchException"/> when authentication fails (the plaintext span is then zeroed),
        /// or <see cref="InvalidCipherTextException"/> when the input is shorter than the tag, as BouncyCastle does.
        /// </summary>
        public static void Decrypt(AesGcm aesGcm, ReadOnlySpan<byte> input, Span<byte> output, ReadOnlySpan<byte> nonce, int N_tag, ReadOnlySpan<byte> associatedData)
        {
            var ciphertextLength = input.Length - N_tag;
            if (ciphertextLength < 0)
            {
                throw new InvalidCipherTextException("data too short");
            }

            ReadOnlySpan<byte> ciphertext = input.Slice(0, ciphertextLength);
            scoped ReadOnlySpan<byte> tag = input.Slice(ciphertextLength, N_tag);
            var plaintext = output.Slice(0, ciphertextLength);

            // See Encrypt: only a shifted, partially overlapping pair needs moving. The tag is saved first because the move may cover it.
            if (ciphertext.Overlaps((ReadOnlySpan<byte>)plaintext, out int elementOffset) && elementOffset != 0)
            {
                Span<byte> savedTag = stackalloc byte[N_tag];
                tag.CopyTo(savedTag);
                tag = savedTag;
                ciphertext.CopyTo(plaintext);
                ciphertext = plaintext;
            }

            aesGcm.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);
        }

        public static void GenerateMessageKeyIV(ReadOnlySpan<byte> k_s, uint ssrc, ulong index, Span<byte> iv)
        {
            k_s.Slice(0, BLOCK_SIZE).CopyTo(iv);

            // XOR ssrc at offset 2 (3 bytes for 48-bit index)
            var ssrcSpan = iv.Slice(2, 4);
            BinaryPrimitives.WriteUInt32BigEndian(ssrcSpan,
                BinaryPrimitives.ReadUInt32BigEndian(ssrcSpan) ^ ssrc);

            // XOR index at offset 6 (6 bytes for 48-bit index)
            var indexSpan = iv.Slice(4, 8);
            BinaryPrimitives.WriteUInt64BigEndian(indexSpan,
                BinaryPrimitives.ReadUInt64BigEndian(indexSpan) ^ (index & 0x0000_FFFF_FFFF_FFFF));
        }
    }
}

using System;
using System.Collections.Generic;

namespace SIPSorcery.Net
{
    public class H264Packetiser
    {
        public const int H264_RTP_HEADER_LENGTH = 2;

        public readonly struct H264Nal
        {
            public ReadOnlyMemory<byte> NAL { get; }
            public bool IsLast { get; }

            public H264Nal(ReadOnlyMemory<byte> nal, bool isLast)
            {
                NAL = nal;
                IsLast = isLast;
            }
        }

        /// <summary>
        /// Public iterator method. It orchestrates the parsing but contains no complex logic.
        /// </summary>
        public static IEnumerable<H264Nal> ParseNals(ReadOnlyMemory<byte> accessUnit)
        {
            if (accessUnit.IsEmpty)
            {
                yield break;
            }

            // 1. Call the synchronous, Span-based helper to find all NAL boundaries.
            var nalRanges = FindNalRanges(accessUnit.Span);
            bool isLast = false;

            // 2. Safely iterate through the results and yield Memory slices.
            for (int i = 0; i < nalRanges.Count; i++)
            {
                var (start, length) = nalRanges[i];
                isLast = (i == nalRanges.Count - 1);
                yield return new H264Nal(accessUnit.Slice(start, length), isLast);
            }
        }

        /// <summary>
        /// A private, synchronous helper method that does the actual parsing using a Span.
        /// Since this method does NOT use 'yield', it's safe to use Spans inside it.
        /// </summary>
        /// <returns>A list of start positions and lengths for each NAL found.</returns>
        private static List<(int Start, int Length)> FindNalRanges(ReadOnlySpan<byte> accessUnit)
        {
            var ranges = new List<(int, int)>();
            int zeroes = 0;
            int nalStartPosn = 0;

            for (int i = 0; i < accessUnit.Length; i++)
            {
                if (accessUnit[i] == 0x00)
                {
                    zeroes++;
                }
                else if (accessUnit[i] == 0x01 && zeroes >= 2)
                {
                    // Found a start code. The previous NAL unit ends here.
                    int startCodeLength = (zeroes == 2) ? 3 : 4;
                    int nalEndPosn = i - startCodeLength;

                    if (nalEndPosn >= nalStartPosn)
                    {
                        int nalLength = nalEndPosn - nalStartPosn + 1;
                        if (nalLength > 0)
                        {
                            ranges.Add((nalStartPosn, nalLength));
                        }
                    }

                    // The next NAL starts after the 0x01 byte.
                    nalStartPosn = i + 1;
                    zeroes = 0;
                }
                else
                {
                    zeroes = 0;
                }
            }

            // Add the final NAL unit in the access unit.
            if (nalStartPosn < accessUnit.Length)
            {
                ranges.Add((nalStartPosn, accessUnit.Length - nalStartPosn));
            }

            return ranges;
        }

        public static byte[] GetH264RtpHeader(byte nal0, bool isFirstPacket, bool isFinalPacket)
        {
            byte nalType = (byte)(nal0 & 0x1F);
            byte firstHdrByte = (byte)(nal0 & 0xE0);
            byte fuIndicator = (byte)(firstHdrByte | 28);
            byte fuHeader = nalType;
            if (isFirstPacket) fuHeader |= 0x80;
            if (isFinalPacket) fuHeader |= 0x40;
            return new byte[] { fuIndicator, fuHeader };
        }
    }
}

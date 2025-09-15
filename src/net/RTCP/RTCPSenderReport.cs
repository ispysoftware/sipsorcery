//-----------------------------------------------------------------------------
// Filename: RTCPSenderReport.cs
//
// Description:
//
//        RTCP Sender Report Packet
//        0                   1                   2                   3
//        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// header |V=2|P|    RC   |   PT=SR=200   |             length            |
//        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//        |                         SSRC of sender                        |
//        +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
// sender |              NTP timestamp, most significant word             |
// info   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//        |             NTP timestamp, least significant word             |
//        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//        |                         RTP timestamp                         |
//        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//        |                     sender's packet count                     |
//        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//        |                      sender's octet count                     |
//        +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
// report |                 SSRC_1(SSRC of first source)                  |
// block  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  1     | fraction lost |       cumulative number of packets lost       |
//        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//        |           extended highest sequence number received           |
//        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//        |                      interarrival jitter                      |
//        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//        |                         last SR(LSR)                          |
//        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//        |                   delay since last SR(DLSR)                   |
//        +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
//
// Author(s):
// Aaron Clauson (aaron@sipsorcery.com)
// 
// History:
// 12 Aug 2019  Aaron Clauson   Created, Montreux, Switzerland.
//
// License: 
// BSD 3-Clause "New" or "Revised" License, see included LICENSE.md file.
//-----------------------------------------------------------------------------

using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using SIPSorcery.Sys;

namespace SIPSorcery.Net
{
    /// <summary>
    /// An RTCP sender report is for use by active RTP senders. 
    /// </summary>
    /// <remarks>
    /// From https://tools.ietf.org/html/rfc3550#section-6.4:
    /// "The only difference between the
    /// sender report(SR) and receiver report(RR) forms, besides the packet
    /// type code, is that the sender report includes a 20-byte sender
    /// information section for use by active senders.The SR is issued if a
    /// site has sent any data packets during the interval since issuing the
    /// last report or the previous one, otherwise the RR is issued."
    /// </remarks>
    public class RTCPSenderReport
    {
        public const int SENDER_PAYLOAD_SIZE = 24; // SSRC (4) + Sender Info (20)
        public const int MIN_PACKET_SIZE = RTCPHeader.HEADER_BYTES_LENGTH + SENDER_PAYLOAD_SIZE;

        public RTCPHeader Header { get; set; }
        public uint SSRC { get; set; }
        public ulong NtpTimestamp { get; set; }
        public uint RtpTimestamp { get; set; }
        public uint PacketCount { get; set; }
        public uint OctetCount { get; set; }
        public List<ReceptionReportSample> ReceptionReports { get; set; }

        /// <summary>
        /// The total length of this report in bytes.
        /// </summary>
        public int Length => MIN_PACKET_SIZE + (ReceptionReports?.Count ?? 0) * ReceptionReportSample.PAYLOAD_SIZE;

        // Constructor for building a new report.
        public RTCPSenderReport(uint ssrc, ulong ntpTimestamp, uint rtpTimestamp, uint packetCount, uint octetCount, List<ReceptionReportSample> receptionReports)
        {
            int rrCount = receptionReports?.Count ?? 0;

            // First, calculate the total length of this report in bytes.
            int totalLength = RTCPHeader.HEADER_BYTES_LENGTH + SENDER_PAYLOAD_SIZE + (rrCount * ReceptionReportSample.PAYLOAD_SIZE);

            // The length field in the header is the number of 32-bit words minus one.
            ushort lengthInWords = (ushort)(totalLength / 4 - 1);

            // This is the corrected, two-step way to create and configure the header.
            Header = new RTCPHeader(RTCPReportTypesEnum.SR, rrCount);
            Header.Length = lengthInWords;

            // The rest of the constructor remains the same.
            SSRC = ssrc;
            NtpTimestamp = ntpTimestamp;
            RtpTimestamp = rtpTimestamp;
            PacketCount = packetCount;
            OctetCount = octetCount;
            ReceptionReports = receptionReports;
        }

        /// <summary>
        /// High-performance parsing constructor (already well-written, with minor corrections).
        /// </summary>
        public RTCPSenderReport(ReadOnlySpan<byte> buffer)
        {
            if (buffer.Length < MIN_PACKET_SIZE)
            {
                throw new ApplicationException("Packet is too small for an RTCPSenderReport.");
            }

            Header = new RTCPHeader(buffer);
            ReceptionReports = new List<ReceptionReportSample>();

            SSRC = BinaryPrimitives.ReadUInt32BigEndian(buffer.Slice(4));
            NtpTimestamp = BinaryPrimitives.ReadUInt64BigEndian(buffer.Slice(8));
            RtpTimestamp = BinaryPrimitives.ReadUInt32BigEndian(buffer.Slice(16));
            PacketCount = BinaryPrimitives.ReadUInt32BigEndian(buffer.Slice(20));
            OctetCount = BinaryPrimitives.ReadUInt32BigEndian(buffer.Slice(24));

            int reportOffset = 28;
            for (int i = 0; i < Header.ReceptionReportCount && buffer.Length >= reportOffset + ReceptionReportSample.PAYLOAD_SIZE; i++)
            {
                var rr = new ReceptionReportSample(buffer.Slice(reportOffset));
                ReceptionReports.Add(rr);
                reportOffset += ReceptionReportSample.PAYLOAD_SIZE;
            }
        }

        /// <summary>
        /// Allocation-free serialization method.
        /// </summary>
        public int WriteTo(Span<byte> destination)
        {
            if (destination.Length < Length)
            {
                return 0; // Buffer is too small.
            }

            Header.Length = (ushort)(Length / 4 - 1);
            Header.WriteTo(destination);

            int cursor = RTCPHeader.HEADER_BYTES_LENGTH;
            BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(cursor), SSRC);
            cursor += 4;
            BinaryPrimitives.WriteUInt64BigEndian(destination.Slice(cursor), NtpTimestamp);
            cursor += 8;
            BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(cursor), RtpTimestamp);
            cursor += 4;
            BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(cursor), PacketCount);
            cursor += 4;
            BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(cursor), OctetCount);
            cursor += 4;

            if (ReceptionReports != null)
            {
                foreach (var report in ReceptionReports)
                {
                    cursor += report.WriteTo(destination.Slice(cursor));
                }
            }

            return cursor;
        }

        /// <summary>
        /// Gets a new byte array containing the report.
        /// NOTE: This method allocates and is less efficient than WriteTo.
        /// </summary>
        public byte[] GetBytes()
        {
            byte[] buffer = new byte[Length];
            WriteTo(buffer);
            return buffer;
        }
    }
}

//-----------------------------------------------------------------------------
// Filename: RTCPReceiverReport.cs
//
// Description:
//
//        RTCP Receiver Report Packet
//  0                   1                   2                   3
//         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// header |V=2|P|    RC   |   PT=RR=201   |             length            |
//        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//        |                     SSRC of packet sender                     |
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
// report |                 SSRC_2(SSRC of second source)                 |
// block  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  2     :                               ...                             :
//        +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
//        |                  profile-specific extensions                  |
//        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//  An empty RR packet (RC = 0) MUST be put at the head of a compound
//  RTCP packet when there is no data transmission or reception to
//  report.
//
// Author(s):
// Aaron Clauson (aaron@sipsorcery.com)
// 
// History:
// 28 Dec 2019  Aaron Clauson   Created, Dublin, Ireland.
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
    public class RTCPReceiverReport
    {
        public const int MIN_PACKET_SIZE = RTCPHeader.HEADER_BYTES_LENGTH + 4;

        public RTCPHeader Header;
        public uint SSRC;
        public List<ReceptionReportSample> ReceptionReports;
        /// <summary>
        /// Gets the total size of the serialised packet in bytes.
        /// </summary>
        public int PacketSize =>
            RTCPHeader.HEADER_BYTES_LENGTH + 4 + (ReceptionReports?.Count ?? 0) * ReceptionReportSample.PAYLOAD_SIZE;


        /// <summary>
        /// Creates a new RTCP Reception Report payload.
        /// </summary>
        /// <param name="ssrc">The synchronisation source of the RTP packet being sent. Can be zero
        /// if there are none being sent.</param>
        /// <param name="receptionReports">A list of the reception reports to include. Can be empty.</param>
        public RTCPReceiverReport(uint ssrc, List<ReceptionReportSample> receptionReports)
        {
            Header = new RTCPHeader(RTCPReportTypesEnum.RR, receptionReports != null ? receptionReports.Count : 0);
            SSRC = ssrc;
            ReceptionReports = receptionReports;
        }

        /// <summary>
        /// Create a new RTCP Receiver Report from a serialised byte array.
        /// </summary>
        /// <param name="packet">The byte array holding the serialised receiver report.</param>
        public RTCPReceiverReport(ReadOnlySpan<byte> packet)
        {
            if (packet.Length < MIN_PACKET_SIZE)
            {
                throw new ApplicationException("The packet did not contain the minimum number of bytes for an RTCPReceiverReport packet.");
            }

            Header = new RTCPHeader(packet);
            ReceptionReports = new List<ReceptionReportSample>();
            SSRC = BinaryPrimitives.ReadUInt32BigEndian(packet.Slice(4));

            int rrIndex = 8;
            for (int i = 0; i < Header.ReceptionReportCount; i++)
            {
                var rr = new ReceptionReportSample(packet.Slice(rrIndex + i * ReceptionReportSample.PAYLOAD_SIZE));
                ReceptionReports.Add(rr);
            }
        }

        /// <summary>
        /// Serialises the RTCP Receiver Report into a new byte array.
        /// </summary>
        /// <returns>A new byte array containing the serialised report.</returns>
        public byte[] GetBytes()
        {
            byte[] buffer = new byte[PacketSize];
            WriteTo(buffer);
            return buffer;
        }

        /// <summary>
        /// Serialises the RTCP Receiver Report into a provided buffer.
        /// </summary>
        /// <param name="buffer">The buffer to write the report into.</param>
        /// <returns>The number of bytes written to the buffer.</returns>
        public int WriteTo(Span<byte> buffer)
        {
            int requiredSize = PacketSize;
            if (buffer.Length < requiredSize)
            {
                throw new ArgumentException($"The buffer is too small for the RTCP Receiver Report. Required {requiredSize}, available {buffer.Length}.", nameof(buffer));
            }

            // The length field in the RTCP header is the packet length in 32-bit words minus one.
            Header.Length = (ushort)(requiredSize / 4 - 1);
            Header.ReceptionReportCount = ReceptionReports?.Count ?? 0;

            // Write the header.
            Header.WriteTo(buffer);

            // Write the SSRC.
            BinaryPrimitives.WriteUInt32BigEndian(buffer.Slice(4), SSRC);

            // Write the reception report blocks.
            if (ReceptionReports != null && ReceptionReports.Count > 0)
            {
                int offset = 8; // Start after header and SSRC.
                foreach (var report in ReceptionReports)
                {
                    report.WriteTo(buffer.Slice(offset));
                    offset += ReceptionReportSample.PAYLOAD_SIZE;
                }
            }

            return requiredSize;
        }
    }
}

//-----------------------------------------------------------------------------
// Filename: STUNErrorCodeAttribute.cs
//
// Description: Implements STUN error attribute as defined in RFC5389.
//
// Author(s):
// Aaron Clauson (aaron@sipsorcery.com)
//
// History:
// 04 Feb 2016	Aaron Clauson	Created, Hobart, Australia.
//
// License: 
// BSD 3-Clause "New" or "Revised" License, see included LICENSE.md file.
//-----------------------------------------------------------------------------

using System;
using System.Buffers.Binary;
using System.Text;
using SIPSorcery.Sys;

namespace SIPSorcery.Net
{
    public class STUNConnectionIdAttribute : STUNAttribute
    {
        public readonly uint ConnectionId;

        public STUNConnectionIdAttribute(byte[] attributeValue)
            : base(STUNAttributeTypesEnum.ConnectionId, attributeValue)
        {
            ConnectionId = BinaryPrimitives.ReadUInt32BigEndian(attributeValue.AsSpan(0));
        }

        public STUNConnectionIdAttribute(uint connectionId): base(STUNAttributeTypesEnum.ConnectionId, new byte[4])
        {
            ConnectionId = connectionId;
            BinaryPrimitives.WriteUInt32BigEndian(base.Value, connectionId);
        }

        public override string ToString()
        {
            string attrDescrStr = "STUN CONNECTION_ID Attribute: value=" + ConnectionId + ".";

            return attrDescrStr;
        }
    }
}

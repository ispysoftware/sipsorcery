//------------------------------------------------------------------------------
// <auto-generated>
//    This code was generated from a template.
//
//    Manual changes to this file may cause unexpected behavior in your application.
//    Manual changes to this file will be overwritten if the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

namespace SIPSorcery.Entities
{
    using System;
    using System.Collections.Generic;
    
    public partial class Rate
    {
        public string ID { get; set; }
        public string Owner { get; set; }
        public string Description { get; set; }
        public string Prefix { get; set; }
        public decimal Rate1 { get; set; }
        public string RateCode { get; set; }
        public string Inserted { get; set; }
        public decimal SetupCost { get; set; }
        public int IncrementSeconds { get; set; }
        public int RatePlan { get; set; }
    }
}
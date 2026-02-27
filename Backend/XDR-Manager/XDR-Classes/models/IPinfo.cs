namespace XDR.Manager.IpInfoNamespace
{
    public class IpInfo
    {
        public int Version { get; set; }
        public int HeaderLength { get; set; }

        // DSCP / ECN
        public int Dscp { get; set; }
        public int Ecn { get; set; }

        // Lunghezza del pacchetto IP
        public int TotalLength { get; set; }

        // ID di frammentazione
        public ushort Identification { get; set; }

        // Flags
        public bool ReservedBit { get; set; }
        public bool DontFragment { get; set; }
        public bool MoreFragments { get; set; }

        public int FragmentOffset { get; set; }

        // Time To Live
        public int Ttl { get; set; }

        // Protocollo di livello 4 (TCP=6, UDP=17, ICMP=1)
        public int Protocol { get; set; }

        // Checksum
        public string Checksum { get; set; } = string.Empty;
        public string ChecksumStatus { get; set; } = string.Empty;

        // IP sorgente / destinazione
        public string SrcIp { get; set; } = string.Empty;
        public string DstIp { get; set; } = string.Empty;
    }
}

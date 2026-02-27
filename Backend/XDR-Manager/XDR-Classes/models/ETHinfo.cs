using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace XDR.Manager.EthInfoNamespace
{
    public class EthInfo
    {
        // MAC address sorgente e destinazione
        public string SrcMac { get; set; } = string.Empty;
        public string DstMac { get; set; } = string.Empty;

        // OUI (identificativo vendor)
        public string SrcOUI { get; set; } = string.Empty;
        public string DstOUI { get; set; } = string.Empty;

        // Informazioni Local/Individual (bit LG e IG)
        public bool SrcIsLocal { get; set; }
        public bool SrcIsGroup { get; set; }
        public bool DstIsLocal { get; set; }
        public bool DstIsGroup { get; set; }

        // Tipo livello 3 (tipico: 0x0800 per IPv4)
        public int EthType { get; set; }
    }
}

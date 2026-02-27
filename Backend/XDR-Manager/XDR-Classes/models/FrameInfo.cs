using System;

namespace XDR.Manager.FrameInfoNamespace
{
    public class FrameInfo
    {
        // Tipo di incapsulamento (1 = Ethernet)
        public int EncapType { get; set; }

        // Timestamp come DateTime
        public DateTime Time { get; set; }

        // Timestamp epoch in double (secondi dal 1970)
        public long TimeEpoch { get; set; }

        // Delta rispetto al frame precedente
        public double TimeDelta { get; set; }

        // Tempo relativo dall'inizio della cattura
        public double TimeRelative { get; set; }

        // Numero del frame nella cattura
        public int Number { get; set; }

        // Lunghezza effettiva del frame sulla rete
        public int Length { get; set; }

        // Lunghezza catturata (snaplen)
        public int CapturedLength { get; set; }

        // Marcato / ignorato (Wireshark)
        public bool Marked { get; set; }
        public bool Ignored { get; set; }

        // Stack di protocolli (es: "eth:ethertype:ip:tcp")
        public string Protocols { get; set; } = string.Empty;
    }
}

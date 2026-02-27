namespace XDR.Manager.TcpInfoNamespace
{
	public class TcpInfo
	{
		// Porte
		public int SrcPort { get; set; }
		public int DstPort { get; set; }

		public int Length { get; set; }
		public int Stream { get; set; }
		public int Completeness { get; set; }

		// Sequenze
		public uint Seq { get; set; }
		public uint SeqRaw { get; set; }
		public uint NextSeq { get; set; }

		// Ack
		public uint Ack { get; set; }
		public uint AckRaw { get; set; }

		// Header
		public int HeaderLength { get; set; }

		public bool Syn { get; set; }
		public bool AckFlag { get; set; }
		public bool Fin { get; set; }
		public bool Rst { get; set; }
		public bool Psh { get; set; }
		public bool Urg { get; set; }

		public string FlagsHex { get; set; }

		// Window
		public int WindowSize { get; set; }
		public int WindowSizeValue { get; set; }

		// Checksum
		public string Checksum { get; set; }
		public string ChecksumStatus { get; set; }

		public int UrgentPointer { get; set; }

		public double TimeRelative { get; set; }
		public double TimeDelta { get; set; }
	}
}

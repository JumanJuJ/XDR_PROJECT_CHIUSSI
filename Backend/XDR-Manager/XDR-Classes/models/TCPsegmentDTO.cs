// Root myDeserializedClass = JsonConvert.DeserializeObject<Root>(myJsonResponse);
using Newtonsoft.Json;

namespace XDR.Manager.TcpDtoNamespace;
public class Root
{
	public TcpDto tcp { get; set; }
}

public class TcpDto
{
	[JsonProperty("tcp.srcport")]
	public string tcpsrcport { get; set; }

	[JsonProperty("tcp.dstport")]
	public string tcpdstport { get; set; }

	[JsonProperty("tcp.port")]
	public string tcpport { get; set; }

	[JsonProperty("tcp.stream")]
	public string tcpstream { get; set; }

	[JsonProperty("tcp.completeness")]
	public string tcpcompleteness { get; set; }

	[JsonProperty("tcp.len")]
	public string tcplen { get; set; }

	[JsonProperty("tcp.seq")]
	public string tcpseq { get; set; }

	[JsonProperty("tcp.seq_raw")]
	public string tcpseq_raw { get; set; }

	[JsonProperty("tcp.nxtseq")]
	public string tcpnxtseq { get; set; }

	[JsonProperty("tcp.ack")]
	public string tcpack { get; set; }

	[JsonProperty("tcp.ack_tree")]
	public TcpAckTree tcpack_tree { get; set; }

	[JsonProperty("tcp.ack_raw")]
	public string tcpack_raw { get; set; }

	[JsonProperty("tcp.hdr_len")]
	public string tcphdr_len { get; set; }

	[JsonProperty("tcp.flags")]
	public string tcpflags { get; set; }

	[JsonProperty("tcp.flags_tree")]
	public TcpFlagsTree tcpflags_tree { get; set; }

	[JsonProperty("tcp.window_size_value")]
	public string tcpwindow_size_value { get; set; }

	[JsonProperty("tcp.window_size")]
	public string tcpwindow_size { get; set; }

	[JsonProperty("tcp.checksum")]
	public string tcpchecksum { get; set; }

	[JsonProperty("tcp.checksum.status")]
	public string tcpchecksumstatus { get; set; }

	[JsonProperty("tcp.urgent_pointer")]
	public string tcpurgent_pointer { get; set; }
	public Timestamps Timestamps { get; set; }
}

public class TcpAckTree
{
	[JsonProperty("_ws.expert")]
	public WsExpert _wsexpert { get; set; }
}

public class TcpFlagsSynTree
{
	[JsonProperty("_ws.expert")]
	public WsExpert _wsexpert { get; set; }
}

public class TcpFlagsTree
{
	[JsonProperty("tcp.flags.res")]
	public string tcpflagsres { get; set; }

	[JsonProperty("tcp.flags.ae")]
	public string tcpflagsae { get; set; }

	[JsonProperty("tcp.flags.cwr")]
	public string tcpflagscwr { get; set; }

	[JsonProperty("tcp.flags.ece")]
	public string tcpflagsece { get; set; }

	[JsonProperty("tcp.flags.urg")]
	public string tcpflagsurg { get; set; }

	[JsonProperty("tcp.flags.ack")]
	public string tcpflagsack { get; set; }

	[JsonProperty("tcp.flags.push")]
	public string tcpflagspush { get; set; }

	[JsonProperty("tcp.flags.reset")]
	public string tcpflagsreset { get; set; }

	[JsonProperty("tcp.flags.syn")]
	public string tcpflagssyn { get; set; }

	[JsonProperty("tcp.flags.syn_tree")]
	public TcpFlagsSynTree tcpflagssyn_tree { get; set; }

	[JsonProperty("tcp.flags.fin")]
	public string tcpflagsfin { get; set; }

	[JsonProperty("tcp.flags.str")]
	public string tcpflagsstr { get; set; }
}

public class Timestamps
{
	[JsonProperty("tcp.time_relative")]
	public string tcptime_relative { get; set; }

	[JsonProperty("tcp.time_delta")]
	public string tcptime_delta { get; set; }
}

public class WsExpert
{
	[JsonProperty("tcp.ack.nonzero")]
	public string tcpacknonzero { get; set; }

	[JsonProperty("_ws.expert.message")]
	public string _wsexpertmessage { get; set; }

	[JsonProperty("_ws.expert.severity")]
	public string _wsexpertseverity { get; set; }

	[JsonProperty("_ws.expert.group")]
	public string _wsexpertgroup { get; set; }

	[JsonProperty("tcp.connection.syn")]
	public string tcpconnectionsyn { get; set; }
}


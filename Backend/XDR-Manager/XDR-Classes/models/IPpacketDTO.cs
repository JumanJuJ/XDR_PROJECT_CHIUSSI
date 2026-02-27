// Root myDeserializedClass = JsonConvert.DeserializeObject<Root>(myJsonResponse);
using Newtonsoft.Json;
namespace XDR.Manager.IpDtoNamespace
{
	public class IpDto
	{
		[JsonProperty("ip.version")]
		public string ipversion { get; set; }

		[JsonProperty("ip.hdr_len")]
		public string iphdr_len { get; set; }

		[JsonProperty("ip.dsfield")]
		public string ipdsfield { get; set; }

		[JsonProperty("ip.dsfield_tree")]
		public IpDsfieldTree ipdsfield_tree { get; set; }

		[JsonProperty("ip.len")]
		public string iplen { get; set; }

		[JsonProperty("ip.id")]
		public string ipid { get; set; }

		[JsonProperty("ip.flags")]
		public string ipflags { get; set; }

		[JsonProperty("ip.flags_tree")]
		public IpFlagsTree ipflags_tree { get; set; }

		[JsonProperty("ip.frag_offset")]
		public string ipfrag_offset { get; set; }

		[JsonProperty("ip.ttl")]
		public string ipttl { get; set; }

		[JsonProperty("ip.proto")]
		public string ipproto { get; set; }

		[JsonProperty("ip.checksum")]
		public string ipchecksum { get; set; }

		[JsonProperty("ip.checksum.status")]
		public string ipchecksumstatus { get; set; }

		[JsonProperty("ip.src")]
		public string ipsrc { get; set; }

		[JsonProperty("ip.addr")]
		public string ipaddr { get; set; }

		[JsonProperty("ip.src_host")]
		public string ipsrc_host { get; set; }

		[JsonProperty("ip.host")]
		public string iphost { get; set; }

		[JsonProperty("ip.dst")]
		public string ipdst { get; set; }

		[JsonProperty("ip.dst_host")]
		public string ipdst_host { get; set; }
	}

	public class IpDsfieldTree
	{
		[JsonProperty("ip.dsfield.dscp")]
		public string ipdsfielddscp { get; set; }

		[JsonProperty("ip.dsfield.ecn")]
		public string ipdsfieldecn { get; set; }
	}

	public class IpFlagsTree
	{
		[JsonProperty("ip.flags.rb")]
		public string ipflagsrb { get; set; }

		[JsonProperty("ip.flags.df")]
		public string ipflagsdf { get; set; }

		[JsonProperty("ip.flags.mf")]
		public string ipflagsmf { get; set; }
	}

	public class Root
	{
		public IpDto ip { get; set; }
	}

}
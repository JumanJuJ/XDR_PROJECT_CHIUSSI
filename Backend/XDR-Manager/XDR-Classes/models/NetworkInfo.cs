using Newtonsoft.Json;
using XDR.Manager.EthDtoNamespace;
using XDR.Manager.EthInfoNamespace;
using XDR.Manager.FrameInfoNamespace;
using XDR.Manager.IpDtoNamespace;
using XDR.Manager.IpInfoNamespace;
using XDR.Manager.TcpDtoNamespace;
using XDR.Manager.TcpInfoNamespace;
using XDR.Manager.ArpDtoNamespace;
using XDR_Classes.ARPinfo;

namespace XDR.Manager.NetworkInfoNamespace
{
    public class NetworkPacketInfo
    {
        public EthInfo? Eth { get; set; }
        public FrameInfo? Frame { get; set; }
        public IpInfo? Ip { get; set; }
        public TcpInfo? Tcp { get; set; }
        public ARPInfo? Arp { get; set; }

    }


    public class PacketSource
        {
            [JsonProperty("_index")]
            public string? Index { get; set; }

            [JsonProperty("_type")]
            public string? Type { get; set; }

            [JsonProperty("_score")]
            public double? Score { get; set; }

            [JsonProperty("_source")]
            public PacketSource? Source { get; set; }

            [JsonProperty("layers")]
            public PacketLayers? Layers { get; set; }
        }

        public class PacketLayers
        {
            [JsonProperty("root")]
            public  PacketRootDto? Root { get; set; }
    }



    public class PacketRootDto
        {
            [JsonProperty("eth")]
            public EthDto? Eth { get; set; }

            [JsonProperty("frame")]
            public Frame? Frame { get; set; }

            [JsonProperty("ip")]
            public IpDto? Ip { get; set; }

            [JsonProperty("tcp")]
            public TcpDto? Tcp { get; set; }

        [JsonProperty("arp")]
        public ArpDto? Arp { get; set; }

    }
    


}

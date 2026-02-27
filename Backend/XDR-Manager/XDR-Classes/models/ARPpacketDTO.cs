using Newtonsoft.Json;

namespace XDR.Manager.ArpDtoNamespace
{
    public sealed class ArpDto
    {
        [JsonProperty("arp.src.proto_ipv4")]
        public string? SenderIp { get; set; }

        [JsonProperty("arp.dst.proto_ipv4")]
        public string? TargetIp { get; set; }

        [JsonProperty("arp.opcode")]
        public string? Opcode { get; set; }
    }
}

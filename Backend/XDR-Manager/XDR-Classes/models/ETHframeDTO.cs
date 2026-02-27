// Root myDeserializedClass = JsonConvert.DeserializeObject<Root>(myJsonResponse);
using Newtonsoft.Json;
namespace XDR.Manager.EthDtoNamespace
{
    public class EthDto
    {
        [JsonProperty("eth.dst")]
        public string ethdst { get; set; }

        [JsonProperty("eth.dst_tree")]
        public EthDstTree ethdst_tree { get; set; }

        [JsonProperty("eth.src")]
        public string ethsrc { get; set; }

        [JsonProperty("eth.src_tree")]
        public EthSrcTree ethsrc_tree { get; set; }

        [JsonProperty("eth.type")]
        public string ethtype { get; set; }
    }

    public class EthDstTree
    {
        [JsonProperty("eth.dst_resolved")]
        public string ethdst_resolved { get; set; }

        [JsonProperty("eth.dst.oui")]
        public string ethdstoui { get; set; }

        [JsonProperty("eth.addr")]
        public string ethaddr { get; set; }

        [JsonProperty("eth.addr_resolved")]
        public string ethaddr_resolved { get; set; }

        [JsonProperty("eth.addr.oui")]
        public string ethaddroui { get; set; }

        [JsonProperty("eth.dst.lg")]
        public string ethdstlg { get; set; }

        [JsonProperty("eth.lg")]
        public string ethlg { get; set; }

        [JsonProperty("eth.dst.ig")]
        public string ethdstig { get; set; }

        [JsonProperty("eth.ig")]
        public string ethig { get; set; }
    }

    public class EthSrcTree
    {
        [JsonProperty("eth.src_resolved")]
        public string ethsrc_resolved { get; set; }

        [JsonProperty("eth.src.oui")]
        public string ethsrcoui { get; set; }

        [JsonProperty("eth.addr")]
        public string ethaddr { get; set; }

        [JsonProperty("eth.addr_resolved")]
        public string ethaddr_resolved { get; set; }

        [JsonProperty("eth.addr.oui")]
        public string ethaddroui { get; set; }

        [JsonProperty("eth.src.lg")]
        public string ethsrclg { get; set; }

        [JsonProperty("eth.lg")]
        public string ethlg { get; set; }

        [JsonProperty("eth.src.ig")]
        public string ethsrcig { get; set; }

        [JsonProperty("eth.ig")]
        public string ethig { get; set; }
    }

    public class Frame
    {
        [JsonProperty("frame.encap_type")]
        public string frameencap_type { get; set; }

        [JsonProperty("frame.time")]
        public string frametime { get; set; }

        [JsonProperty("frame.offset_shift")]
        public string frameoffset_shift { get; set; }

        [JsonProperty("frame.time_epoch")]
        public string frametime_epoch { get; set; }

        [JsonProperty("frame.time_delta")]
        public string frametime_delta { get; set; }

        [JsonProperty("frame.time_delta_displayed")]
        public string frametime_delta_displayed { get; set; }

        [JsonProperty("frame.time_relative")]
        public string frametime_relative { get; set; }

        [JsonProperty("frame.number")]
        public string framenumber { get; set; }

        [JsonProperty("frame.len")]
        public string framelen { get; set; }

        [JsonProperty("frame.cap_len")]
        public string framecap_len { get; set; }

        [JsonProperty("frame.marked")]
        public string framemarked { get; set; }

        [JsonProperty("frame.ignored")]
        public string frameignored { get; set; }

        [JsonProperty("frame.protocols")]
        public string frameprotocols { get; set; }
    }

    public class Root
    {
        public Frame frame { get; set; }
        public EthDto eth { get; set; }
    }

}
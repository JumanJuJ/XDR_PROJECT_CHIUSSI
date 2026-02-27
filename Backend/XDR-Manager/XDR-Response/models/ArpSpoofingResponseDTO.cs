using System;

using Newtonsoft.Json;

namespace XDR_Response.models
{

   
        public sealed class ArpSpoofingResponseDto
        {
            [JsonProperty("menaceType")]
            public string MenaceType { get; init; } = "arp_spoofing";

            [JsonProperty("level")]
            public string Level { get; init; } = default!; // BASE | HARD

            [JsonProperty("action")]
            public string Action { get; init; } = default!; // FLUSH_ARP_CACHE

        [JsonProperty("date")]
        public DateTime Date { get; init; } = default!;


        [JsonProperty("message")]
            public string? Message { get; init; }
        }
    

}

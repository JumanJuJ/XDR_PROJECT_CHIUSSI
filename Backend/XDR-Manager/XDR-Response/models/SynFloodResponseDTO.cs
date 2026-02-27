
using Newtonsoft.Json;
using System.Text.Json.Serialization;

namespace XDR_Response.models
    {
        public sealed class SynFlodResponseDTO
        {
            [JsonProperty("menaceType")]
            public string MenaceType { get; init; } = default!;

            [JsonProperty("level")]
            public string Level { get; init; } = default!;

        [JsonProperty("action")]
        public string Action { get; init; } = default!;

        [JsonProperty("date")]
            public DateTime Date { get; init; }

            [JsonProperty("message")]
            public string? Message { get; init; }
        }
  

}

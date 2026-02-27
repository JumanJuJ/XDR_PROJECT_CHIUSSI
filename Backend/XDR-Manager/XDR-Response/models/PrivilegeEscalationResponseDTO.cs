using Newtonsoft.Json;

namespace XDR_Response.models
{
    public sealed class PrivilegeEscalationDTO
    {
        [JsonProperty("menaceType")]
        public string MenaceType { get; init; } = default!; 

        [JsonProperty("level")]
        public string Level { get; init; } = default!; 

        [JsonProperty("action")]
        public string Action { get; init; } = default!;

        [JsonProperty("date")]
        public DateTime Date { get; init; } = default!;

        [JsonProperty("message")]
        public string? Message { get; init; }

        [JsonProperty("path")]
        public string? Path { get; init; }

        [JsonProperty("sha256")]
        public string? Sha256 { get; init; }

        [JsonProperty("inode")]
        public long? Inode { get; init; }
    }
}

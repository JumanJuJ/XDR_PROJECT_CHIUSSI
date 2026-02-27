
namespace XDR_Detection.models.WarningLocal
{

    public sealed class WarningLocalReport
    {
        [JsonPropertyName("path")]
        public string? Path { get; set; }

        [JsonPropertyName("type")]
        public string? Type { get; set; }

        [JsonPropertyName("message")]
        public string? Message { get; set; }

        [JsonPropertyName("timestampUtc")]
        public DateTime? TimestampUtc { get; set; }
    }

    public class dbWarningLocalReport
    {
        public DateTime TimestampUtc;
        public string warningType = "chmod_exec";
        public List<WarningLocalReport>? reportList;


    }
}

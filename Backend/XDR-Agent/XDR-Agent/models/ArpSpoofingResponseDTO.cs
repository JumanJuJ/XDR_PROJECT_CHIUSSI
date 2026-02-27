
namespace XDR_Agent.models
{
    public sealed class ArpSpoofingResponseDto
    {
        public string MenaceType { get; init; } = default!;
        public string Level { get; init; } = default!;
        public string Action { get; init; } = default!;
        public string? Message { get; init; }
    }
}

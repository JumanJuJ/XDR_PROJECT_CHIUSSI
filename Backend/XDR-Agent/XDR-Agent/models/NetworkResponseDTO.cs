
namespace XDR_Agent.models
{
    public sealed class NetworkResponseDto
    {
        public string MenaceType { get; init; } = default!; 
        public string Level { get; init; } = default!;    
        public string Action { get; init; } = default!;     
        public string? Message { get; init; }
    }

}

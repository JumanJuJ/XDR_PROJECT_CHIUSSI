namespace Agent.Response;


public sealed class SynFloodresponseDTO
{
    public string MenaceType { get; init; } = default!;
    public string Level { get; init; } = default!;
    public string? Message { get; init; }
}

using MongoDB.Bson;

public sealed class ArpSpoofAlertDoc
{
    public int stixId { get; set; }
    public string srcIp { get; set; } = "";
    public string srcMac { get; set; } = "";

    public long windowStart { get; set; }
    public long windowEnd { get; set; }
    public bool malicious { get; set; }
    public string? message { get; set; }
    public DateTime detectedAtUtc { get; set; }
}

public sealed class IncidentArpSpoofLite
{
    public ObjectId _id { get; set; }
    public long incidentId { get; set; }
    public DateTime date { get; set; }
    public ArpSpoofAlertDoc alert { get; set; } = new();
}

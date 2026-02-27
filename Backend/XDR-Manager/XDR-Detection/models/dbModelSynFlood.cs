using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

public class SynFloodAlertDoc
{
    public int stixId { get; set; }

    public string srcIp { get; set; } = "";
    public string dstIp { get; set; } = "";

    public int srcPort { get; set; }
    public int dstPort { get; set; }

    public int synCount { get; set; }

    public long windowStart { get; set; }
    public long windowEnd { get; set; }

    public bool malicious { get; set; }
    public string? attackType { get; set; } 
    public string? message { get; set; }


    public DateTime detectedAtUtc { get; set; }
}

public class IncidentSynFloodLite
{
    [BsonId]
    public ObjectId _id { get; set; }

    public int incidentId { get; set; }
    public DateTime date { get; set; }

    public string type { get; set; } = "SYN_FLOOD";

    public SynFloodAlertDoc alert { get; set; } = null!;
}

using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace XdrDashboard.Models;

public class WarningEvent
{
    [BsonId]
    [BsonRepresentation(BsonType.ObjectId)]
    public string? Id { get; set; }

    [BsonElement("TimestampUtc")]
    public DateTime TimestampUtc { get; set; }

    [BsonElement("warningType")]
    public string WarningType { get; set; } = string.Empty;

    [BsonElement("reportList")]
    public List<WarningReport> ReportList { get; set; } = new();
}
public class WarningReport
{
    [BsonElement("Type")]
    public string Type { get; set; } = string.Empty;

    [BsonElement("Path")]
    public string Path { get; set; } = string.Empty;

    [BsonElement("Message")]
    public string Message { get; set; } = string.Empty;

    [BsonElement("TimestampUtc")]
    public DateTime TimestampUtc { get; set; }
}

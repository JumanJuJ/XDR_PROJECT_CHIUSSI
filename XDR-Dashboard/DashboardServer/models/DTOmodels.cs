using System.Text.Json;

namespace XdrDashboard.Models;

using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using System.Text.Json;
public record TimelineDto(
    DateTime ts,
    string kind,
    string title,
    string message,
    string? src,
    string? dst,
    int? stixId,          
    string? mitreId,      
    string? mitreUrl,     
    bool? malicious,      
    ConfidenceLevel confidence,
    ThreatLevel threatLevel,
    JsonElement payload
);

public enum ThreatLevel
{
    Unknown = 0,
    Low = 1,
    Medium = 2,
    High = 3
}

public enum ConfidenceLevel
{
    Unknown = 0,
    Low = 1,
    Medium = 2,
    High = 3
}



public class LocalFileEventDto
{
    [BsonId]
    [BsonRepresentation(BsonType.ObjectId)]
    public string? Id { get; set; }

    [BsonElement("path")]
    public string? Path { get; set; }

    [BsonElement("inode")]
    public long? Inode { get; set; }

    [BsonElement("size")]
    public long? Size { get; set; }

    [BsonElement("mode")]
    public string? Mode { get; set; }

    [BsonElement("mtime")]
    public long? Mtime { get; set; }

    [BsonElement("uid")]
    public long? Uid { get; set; }

    [BsonElement("gid")]
    public long? Gid { get; set; }

    [BsonElement("sha")]
    public string? Sha { get; set; }
}


public class LocalProcessEventDto
{
    [BsonId]
    [BsonRepresentation(BsonType.ObjectId)]
    public string? Id { get; set; }

    [BsonElement("ts")]
    public long? Ts { get; set; }

    [BsonElement("pid")]
    public int? Pid { get; set; }

    [BsonElement("ppid")]
    public int? Ppid { get; set; }

    [BsonElement("state")]
    public string? State { get; set; }

    [BsonElement("uid")]
    public long? Uid { get; set; }

    [BsonElement("gid")]
    public long? Gid { get; set; }

    [BsonElement("start")]
    public long? Start { get; set; }

    [BsonElement("comm")]
    public string? Comm { get; set; }

    [BsonElement("exe")]
    public string? Exe { get; set; }

    [BsonElement("cwd")]
    public string? Cwd { get; set; }

    [BsonElement("cmdline")]
    public string? Cmdline { get; set; }

    [BsonElement("vmrss_kb")]
    public long? VmRssKb { get; set; }

    [BsonElement("vmsize_kb")]
    public long? VmSizeKb { get; set; }
}

using System;
using System.Collections.Generic;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

public class IncidentPrivilegeEscalationLite
{
    [BsonId]
    public ObjectId _id { get; set; }

    public int incidentId { get; set; }

    public string type { get; set; } = "PRIVILEGE_ESCALATION";

    public string status { get; set; }
    public bool active { get; set; }

    public DateTime detectedAtUtc { get; set; }
    public DateTime? updatedAtUtc { get; set; }

    public AlertPrivilegeEscalationReport alert { get; set; } = null!;
}

public class AlertPrivilegeEscalationReport
{
    public int stixId { get; set; }
    public bool malicious { get; set; }
    public string? message { get; set; }


    public string? path { get; set; }
    public string? mode { get; set; }
    public long inode { get; set; }

    public string? sha { get; set; }

}


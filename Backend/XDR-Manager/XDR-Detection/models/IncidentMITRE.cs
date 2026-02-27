
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace XDR_Detection.Models.incidentMITRE
{
    public class Analytic
    {
        [BsonElement("id")]
        public string Id { get; set; } = null!;

        [BsonElement("description")]
        public string Description { get; set; } = null!;
    }

    public class AttackPattern
    {
        [BsonElement("id")]
        public string Id { get; set; } = null!;

        [BsonElement("name")]
        public string Name { get; set; } = null!;

        [BsonElement("upper_technique")]
        public string UpperTechnique { get; set; } = null!;

        [BsonElement("tactic")]
        public string Tactic { get; set; } = null!;

        [BsonElement("platforms")]
        public List<string> Platforms { get; set; } = new();

        [BsonElement("description")]
        public string Description { get; set; } = null!;
    }

    public class DetectionMITRE
    {
        [BsonElement("id")]
        public string Id { get; set; } = null!;

        [BsonElement("name")]
        public string Name { get; set; } = null!;

        [BsonElement("analytics")]
        public List<Analytic> Analytics { get; set; } = new();
    }

    public class Mitigation
    {
        [BsonElement("id")]
        public string Id { get; set; } = null!;

        [BsonElement("name")]
        public string Name { get; set; } = null!;

        [BsonElement("description")]
        public string Description { get; set; } = null!;
    }

    public class Procedures
    {
        [BsonElement("id")]
        public string Id { get; set; } = null!;

        [BsonElement("name")]
        public string Name { get; set; } = null!;

        [BsonElement("description")]
        public string Description { get; set; } = null!;
    }

    public class IncidentSynFlood
    {
        [BsonId]
        [BsonRepresentation(BsonType.String)]
        public string Id { get; set; } = null!;

        [BsonElement("stix_object_id")]
        public int StixObjectId { get; set; }

        [BsonElement("date")]
        public DateTime? date { get; set; }

        [BsonElement("incident_id")]
        public int? incidentId { get; set; }

        [BsonElement("mitre_url")]
        public string MitreUrl { get; set; } = null!;

        [BsonElement("procedures")]
        public Procedures Procedures { get; set; } = null!;

        [BsonElement("attack_pattern")]
        public AttackPattern AttackPattern { get; set; } = null!;

        [BsonElement("mitigations")]
        public List<Mitigation> Mitigations { get; set; } = new();

        [BsonElement("detection")]
        public DetectionMITRE detection { get; set; } = null!;
    }
}

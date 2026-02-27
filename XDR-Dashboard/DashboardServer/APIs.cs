using DashboardServer.Components;
using MongoDB.Bson;
using MongoDB.Bson.IO;
using MongoDB.Driver;
using System.Text.Json;
using System.Text.Json.Serialization;
using XdrDashboard.Models;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

builder.Services.AddHttpClient();

builder.Services.ConfigureHttpJsonOptions(opts =>
{
    opts.SerializerOptions.Converters.Add(new JsonStringEnumConverter());
});

var mongoConn = builder.Configuration["Mongo:ConnectionString"];
var mongoDbName = builder.Configuration["Mongo:Database"];

if (string.IsNullOrWhiteSpace(mongoConn))
    throw new InvalidOperationException("Missing config: Mongo:ConnectionString");

if (string.IsNullOrWhiteSpace(mongoDbName))
    throw new InvalidOperationException("Missing config: Mongo:Database");

// Mongo services
builder.Services.AddSingleton<IMongoClient>(_ => new MongoClient(mongoConn));
builder.Services.AddSingleton(sp => sp.GetRequiredService<IMongoClient>().GetDatabase(mongoDbName));

var app = builder.Build();

// Pipeline
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseAntiforgery();

app.MapRazorComponents<App>()
   .AddInteractiveServerRenderMode();

// Health
app.MapGet("/api/health", () => Results.Ok(new { ok = true }));




app.MapGet("/api/alerts/last7days", async (
    IMongoDatabase db,
    int limit = 200,
    CancellationToken ct = default) =>
{
    limit = Math.Clamp(limit, 1, 2000);
    var perSource = limit;

    var since = DateTime.UtcNow.AddDays(-7);

    var incidentsColl = db.GetCollection<BsonDocument>("incidentReport");
    var warningsColl = db.GetCollection<BsonDocument>("localWarning");
    var localIncidentColl = db.GetCollection<BsonDocument>("localIncidentReport");
    var incidentARPColl = db.GetCollection<BsonDocument>("incidentReportArpSpoof");
    var malwareColl = db.GetCollection<BsonDocument>("malwareReport");

    var stixColl = db.GetCollection<BsonDocument>("stix_objects");

    var incidentDocs = await incidentsColl
        .Find(SinceDate(since, "detectedAtUtc"))
        .Sort(Builders<BsonDocument>.Sort.Descending("detectedAtUtc"))
        .Limit(perSource)
        .ToListAsync(ct);

    var warningDocs = await warningsColl
        .Find(SinceDate(since, "TimestampUtc"))
        .Sort(Builders<BsonDocument>.Sort.Descending("TimestampUtc"))
        .Limit(perSource)
        .ToListAsync(ct);

    var localIncidentDocs = await localIncidentColl
        .Find(SinceDate(since, "detectedAtUtc"))
        .Sort(Builders<BsonDocument>.Sort.Descending("detectedAtUtc"))
        .Limit(perSource)
        .ToListAsync(ct);

    var arpDocs = await incidentARPColl
        .Find(SinceDate(since, "date"))
        .Sort(Builders<BsonDocument>.Sort.Descending("date"))
        .Limit(perSource)
        .ToListAsync(ct);

    var malwareDocs = await malwareColl
        .Find(SinceDate(since, "timestampUtc"))
        .Sort(Builders<BsonDocument>.Sort.Descending("timestampUtc"))
        .Limit(perSource)
        .ToListAsync(ct);

    // ---------------------- mappers ----------------------

    var incidentItems = incidentDocs.Select(d =>
    {
        var ts = GetDateTime(d, "detectedAtUtc")
              ?? GetDateTime(d, "date")
              ?? GetDateTime(d, "ts")
              ?? DateTime.UtcNow;

        var stixId = GetInt(d, "stixId") ?? GetInt(d, "alert", "stixId");

        var type = GetString(d, "type") ?? GetString(d, "kind") ?? "INCIDENT";
        var title = GetString(d, "title") ?? type;
        var message = GetString(d, "message") ?? GetString(d, "alert", "message") ?? "incident";

        var src = GetString(d, "src") ?? GetString(d, "alert", "srcIp") ?? GetString(d, "alert", "srcMac");
        var dst = GetString(d, "dst") ?? GetString(d, "alert", "dstIp");

        var malicious = GetBool(d, "malicious") ?? GetBool(d, "alert", "malicious");

        var confidence = ConfidenceLevel.High;
        var threatLevel = (malicious == true) ? ThreatLevel.High : ThreatLevel.Low;

        return new TimelineDto(
            ts, "incident", title, message, src, dst,
            stixId, null, null,
            malicious,
            confidence,
            threatLevel,
            BsonToJsonElement(d)
        );
    });

    var warningItems = warningDocs.Select(d =>
    {
        var ts = GetDateTime(d, "TimestampUtc")
              ?? GetDateTime(d, "ts")
              ?? DateTime.UtcNow;

        var stixId = GetInt(d, "stixId") ?? GetInt(d, "alert", "stixId");

        var wtype = GetString(d, "warningType") ?? GetString(d, "type") ?? "LOCAL_WARNING";
        var title = $"Warning: {wtype}";
        var message = GetString(d, "message") ?? "warning";

        var malicious = GetBool(d, "malicious") ?? GetBool(d, "alert", "malicious");

        var confidence = ConfidenceLevel.High;
        var threatLevel = (malicious == true) ? ThreatLevel.High : ThreatLevel.Low;

        return new TimelineDto(
            ts, "warning", title, message, GetString(d, "src"), GetString(d, "dst"),
            stixId, null, null,
            malicious,
            confidence,
            threatLevel,
            BsonToJsonElement(d)
        );
    });

    var localIncidentItems = localIncidentDocs.Select(d =>
    {
        var ts = GetDateTime(d, "detectedAtUtc") ?? DateTime.UtcNow;

        var stixId = GetInt(d, "stixId") ?? GetInt(d, "alert", "stixId");

        var type = GetString(d, "type") ?? "LOCAL_INCIDENT";
        var title = type;
        var message = GetString(d, "alert", "message") ?? GetString(d, "status") ?? "local incident";

        var path = GetString(d, "alert", "path");
        var src = !string.IsNullOrWhiteSpace(path) ? $"path={path}" : null;

        var malicious = GetBool(d, "alert", "malicious");

        var confidence = ConfidenceLevel.High;
        var threatLevel = (malicious == true) ? ThreatLevel.High : ThreatLevel.Low;

        return new TimelineDto(
            ts, "local_incident", title, message, src, null,
            stixId, null, null,
            malicious,
            confidence,
            threatLevel,
            BsonToJsonElement(d)
        );
    });

    var arpItems = arpDocs.Select(d =>
    {
        var ts = GetDateTime(d, "date")
              ?? GetDateTime(d, "alert", "detectedAtUtc")
              ?? DateTime.UtcNow;

        var stixId = GetInt(d, "stixId") ?? GetInt(d, "alert", "stixId");

        var title = "ARP_SPOOFING";
        var message = GetString(d, "alert", "message") ?? "arp incident";

        var srcMac = GetString(d, "alert", "srcMac");
        var srcIp = GetString(d, "alert", "srcIp");

        string? src = null;
        if (!string.IsNullOrWhiteSpace(srcMac) && !string.IsNullOrWhiteSpace(srcIp))
            src = $"mac={srcMac} ip={srcIp}";
        else if (!string.IsNullOrWhiteSpace(srcMac))
            src = $"mac={srcMac}";
        else if (!string.IsNullOrWhiteSpace(srcIp))
            src = $"ip={srcIp}";

        var malicious = GetBool(d, "alert", "malicious");

        var confidence = ConfidenceLevel.High;
        var threatLevel = (malicious == true) ? ThreatLevel.High : ThreatLevel.Low;

        return new TimelineDto(
            ts, "network_incident", title, message, src, null,
            stixId, null, null,
            malicious,
            confidence,
            threatLevel,
            BsonToJsonElement(d)
        );
    });

    var malwareItems = malwareDocs.Select(d =>
    {
        var ts = GetDateTime(d, "timestampUtc")
              ?? GetDateTime(d, "detectedAtUtc")
              ?? GetDateTime(d, "date")
              ?? DateTime.UtcNow;

        var stixId = GetInt(d, "stixId") ?? GetInt(d, "alert", "stixId");

        var name = GetString(d, "name") ?? GetString(d, "Name") ?? GetString(d, "fileName") ?? "file";
        var title = "MALWARE_ANALYSIS";
        var message = GetString(d, "message") ?? $"Analysis: {name}";

        var malicious = GetBool(d, "malicious") ?? GetBool(d, "alert", "malicious");

        var confidence = ConfidenceLevel.Medium;

        var score =
            GetDouble(d, "score") ??
            GetDouble(d, "alert", "score") ??
            GetDouble(d, "analysis", "score");

        var threatLevel = MapMalwareScoreToThreatLevel(score);

        return new TimelineDto(
            ts: ts,
            kind: "malware",
            title: title,
            message: message,
            src: null,
            dst: null,
            stixId: stixId,
            mitreId: null,
            mitreUrl: null,
            malicious: malicious,
            confidence: confidence,
            threatLevel: threatLevel,
            payload: BsonToJsonElement(d)
        );
    });


    // ---------------------- merge ----------------------
    var merged = incidentItems
        .Concat(warningItems)
        .Concat(localIncidentItems)
        .Concat(arpItems)
        .Concat(malwareItems)
        .OrderByDescending(x => x.ts)
        .Take(limit)
        .ToList();

    // ====== MITRE JOIN ======
    var stixIds = merged
        .Where(x => x.stixId.HasValue)
        .Select(x => x.stixId!.Value)
        .Distinct()
        .ToList();

    var mitreMap = new Dictionary<int, (string mitreId, string mitreUrl)>();

    if (stixIds.Count > 0)
    {
        var f = Builders<BsonDocument>.Filter.In("stix_object_id", stixIds);

        var stixDocs = await stixColl
            .Find(f)
            .Project(Builders<BsonDocument>.Projection
                .Include("stix_object_id")
                .Include("mitre_url")
                .Include("attack_pattern.id"))
            .ToListAsync(ct);

        foreach (var sd in stixDocs)
        {
            if (!sd.TryGetValue("stix_object_id", out var sidVal)) continue;

            int sid;
            try
            {
                sid = sidVal.BsonType == BsonType.Int32 ? sidVal.AsInt32 :
                      sidVal.BsonType == BsonType.Int64 ? (int)sidVal.AsInt64 :
                      int.Parse(sidVal.ToString());
            }
            catch { continue; }

            var mitreUrl = sd.TryGetValue("mitre_url", out var urlVal) ? urlVal.ToString() : "";

            string? mitreId = null;
            if (sd.TryGetValue("attack_pattern", out var apVal) && apVal is BsonDocument apDoc)
            {
                if (apDoc.TryGetValue("id", out var idVal))
                    mitreId = idVal.ToString();
            }

            if (!string.IsNullOrWhiteSpace(mitreId))
                mitreMap[sid] = (mitreId!, mitreUrl);
        }
    }

    merged = merged
        .Select(x =>
        {
            if (x.stixId.HasValue && mitreMap.TryGetValue(x.stixId.Value, out var m))
                return x with { mitreId = m.mitreId, mitreUrl = m.mitreUrl };

            return x;
        })
        .ToList();

    return Results.Ok(merged);
});


app.MapGet("/api/localFiles", async (
    IMongoDatabase db,
    int limit = 500,
    int skip = 0,
    CancellationToken ct = default) =>
{
    limit = Math.Clamp(limit, 1, 5000);
    skip = Math.Max(0, skip);

    var coll = db.GetCollection<LocalFileEventDto>("localFileEvents");

    var list = await coll.Find(FilterDefinition<LocalFileEventDto>.Empty)
                         .SortByDescending(x => x.Mtime)
                         .Skip(skip)
                         .Limit(limit)
                         .ToListAsync(ct);

    return Results.Ok(list);
});

app.MapGet("/api/localProcesses", async (
    IMongoDatabase db,
    int limit = 500,
    int skip = 0,
    CancellationToken ct = default) =>
{
    limit = Math.Clamp(limit, 1, 5000);
    skip = Math.Max(0, skip);

    var coll = db.GetCollection<LocalProcessEventDto>("localProcessEvents");

    var list = await coll.Find(FilterDefinition<LocalProcessEventDto>.Empty)
                         .SortByDescending(x => x.Ts)
                         .Skip(skip)
                         .Limit(limit)
                         .ToListAsync(ct);

    return Results.Ok(list);
});



app.MapGet("/api/alerts/all", async (
    IMongoDatabase db,
    int limit = 200,
    DateTime? before = null,
    CancellationToken ct = default) =>
{
    limit = Math.Clamp(limit, 1, 2000);
    var perSource = limit;

    var incidentsColl = db.GetCollection<BsonDocument>("incidentReport");
    var warningsColl = db.GetCollection<BsonDocument>("localWarning");
    var localIncidentColl = db.GetCollection<BsonDocument>("localIncidentReport");
    var incidentARPColl = db.GetCollection<BsonDocument>("incidentReportArpSpoof");
    var malwareColl = db.GetCollection<BsonDocument>("malwareReport");

    var stixColl = db.GetCollection<BsonDocument>("stix_objects"); // <-- (era stix_objects)

    var incidentDocs = await incidentsColl
        .Find(BeforeDate(before, "detectedAtUtc"))
        .Sort(Builders<BsonDocument>.Sort.Descending("detectedAtUtc"))
        .Limit(perSource)
        .ToListAsync(ct);

    var warningDocs = await warningsColl
        .Find(BeforeDate(before, "TimestampUtc"))
        .Sort(Builders<BsonDocument>.Sort.Descending("TimestampUtc"))
        .Limit(perSource)
        .ToListAsync(ct);

    var localIncidentDocs = await localIncidentColl
        .Find(BeforeDate(before, "detectedAtUtc"))
        .Sort(Builders<BsonDocument>.Sort.Descending("detectedAtUtc"))
        .Limit(perSource)
        .ToListAsync(ct);

    var arpDocs = await incidentARPColl
        .Find(BeforeDate(before, "date"))
        .Sort(Builders<BsonDocument>.Sort.Descending("date"))
        .Limit(perSource)
        .ToListAsync(ct);

    var malwareDocs = await malwareColl
        .Find(BeforeDate(before, "timestampUtc"))
        .Sort(Builders<BsonDocument>.Sort.Descending("timestampUtc"))
        .Limit(perSource)
        .ToListAsync(ct);

    // ---------------------- mappers ----------------------

    var incidentItems = incidentDocs.Select(d =>
    {
        var ts = GetDateTime(d, "detectedAtUtc")
              ?? GetDateTime(d, "date")
              ?? GetDateTime(d, "ts")
              ?? DateTime.UtcNow;

        var stixId = GetInt(d, "stixId") ?? GetInt(d, "alert", "stixId");

        var type = GetString(d, "type") ?? GetString(d, "kind") ?? "INCIDENT";
        var title = GetString(d, "title") ?? type;
        var message = GetString(d, "message") ?? GetString(d, "alert", "message") ?? "incident";

        var src = GetString(d, "src") ?? GetString(d, "alert", "srcIp") ?? GetString(d, "alert", "srcMac");
        var dst = GetString(d, "dst") ?? GetString(d, "alert", "dstIp");

        var malicious = GetBool(d, "malicious") ?? GetBool(d, "alert", "malicious");

        var confidence = ConfidenceLevel.High;
        var threatLevel = (malicious == true) ? ThreatLevel.High : ThreatLevel.Low;

        return new TimelineDto(
            ts: ts,
            kind: "incident",
            title: title,
            message: message,
            src: src,
            dst: dst,
            stixId: stixId,
            mitreId: null,
            mitreUrl: null,
            malicious: malicious,
            confidence: confidence,
            threatLevel: threatLevel,
            payload: BsonToJsonElement(d)
        );
    });

    var warningItems = warningDocs.Select(d =>
    {
        var ts = GetDateTime(d, "TimestampUtc")
              ?? GetDateTime(d, "ts")
              ?? DateTime.UtcNow;

        var stixId = GetInt(d, "stixId") ?? GetInt(d, "alert", "stixId");

        var wtype = GetString(d, "warningType") ?? GetString(d, "type") ?? "LOCAL_WARNING";
        var title = $"Warning: {wtype}";
        var message = GetString(d, "message") ?? "warning";

        var malicious = GetBool(d, "malicious") ?? GetBool(d, "alert", "malicious");

        var confidence = ConfidenceLevel.High;
        var threatLevel = (malicious == true) ? ThreatLevel.High : ThreatLevel.Low;

        return new TimelineDto(
            ts: ts,
            kind: "warning",
            title: title,
            message: message,
            src: GetString(d, "src"),
            dst: GetString(d, "dst"),
            stixId: stixId,
            mitreId: null,
            mitreUrl: null,
            malicious: malicious,
            confidence: confidence,
            threatLevel: threatLevel,
            payload: BsonToJsonElement(d)
        );
    });

    var localIncidentItems = localIncidentDocs.Select(d =>
    {
        var ts = GetDateTime(d, "detectedAtUtc") ?? DateTime.UtcNow;

        var stixId = GetInt(d, "stixId") ?? GetInt(d, "alert", "stixId");

        var type = GetString(d, "type") ?? "LOCAL_INCIDENT";
        var title = type;
        var message = GetString(d, "alert", "message") ?? GetString(d, "status") ?? "local incident";

        var path = GetString(d, "alert", "path");
        var src = !string.IsNullOrWhiteSpace(path) ? $"path={path}" : null;

        var malicious = GetBool(d, "alert", "malicious");

        var confidence = ConfidenceLevel.High;
        var threatLevel = (malicious == true) ? ThreatLevel.High : ThreatLevel.Low;

        return new TimelineDto(
            ts: ts,
            kind: "local_incident",
            title: title,
            message: message,
            src: src,
            dst: null,
            stixId: stixId,
            mitreId: null,
            mitreUrl: null,
            malicious: malicious,
            confidence: confidence,
            threatLevel: threatLevel,
            payload: BsonToJsonElement(d)
        );
    });

    var arpItems = arpDocs.Select(d =>
    {
        var ts = GetDateTime(d, "date")
              ?? GetDateTime(d, "alert", "detectedAtUtc")
              ?? DateTime.UtcNow;

        var stixId = GetInt(d, "stixId") ?? GetInt(d, "alert", "stixId");

        var title = "ARP_SPOOFING";
        var message = GetString(d, "alert", "message") ?? "arp incident";

        var srcMac = GetString(d, "alert", "srcMac");
        var srcIp = GetString(d, "alert", "srcIp");

        string? src = null;
        if (!string.IsNullOrWhiteSpace(srcMac) && !string.IsNullOrWhiteSpace(srcIp))
            src = $"mac={srcMac} ip={srcIp}";
        else if (!string.IsNullOrWhiteSpace(srcMac))
            src = $"mac={srcMac}";
        else if (!string.IsNullOrWhiteSpace(srcIp))
            src = $"ip={srcIp}";

        var malicious = GetBool(d, "alert", "malicious");

        var confidence = ConfidenceLevel.High;
        var threatLevel = (malicious == true) ? ThreatLevel.High : ThreatLevel.Low;

        return new TimelineDto(
            ts: ts,
            kind: "network_incident",
            title: title,
            message: message,
            src: src,
            dst: null,
            stixId: stixId,
            mitreId: null,
            mitreUrl: null,
            malicious: malicious,
            confidence: confidence,
            threatLevel: threatLevel,
            payload: BsonToJsonElement(d)
        );
    });

    var malwareItems = malwareDocs.Select(d =>
    {
        var ts = GetDateTime(d, "timestampUtc")
              ?? GetDateTime(d, "detectedAtUtc")
              ?? GetDateTime(d, "date")
              ?? DateTime.UtcNow;

        var stixId = GetInt(d, "stixId") ?? GetInt(d, "alert", "stixId");

        var name = GetString(d, "name") ?? GetString(d, "Name") ?? GetString(d, "fileName") ?? "file";
        var title = "MALWARE_ANALYSIS";
        var message = GetString(d, "message") ?? $"Analysis: {name}";

        var malicious = GetBool(d, "malicious") ?? GetBool(d, "alert", "malicious");

        var confidence = ConfidenceLevel.Medium;

        var score =
            GetDouble(d, "score") ??
            GetDouble(d, "alert", "score") ??
            GetDouble(d, "analysis", "score");

        var threatLevel = MapMalwareScoreToThreatLevel(score);

        return new TimelineDto(
            ts: ts,
            kind: "malware",
            title: title,
            message: message,
            src: null,
            dst: null,
            stixId: stixId,
            mitreId: null,
            mitreUrl: null,
            malicious: malicious,
            confidence: confidence,
            threatLevel: threatLevel,
            payload: BsonToJsonElement(d)
        );
    });

    // ---------------------- merge ----------------------
    var merged = incidentItems
        .Concat(warningItems)
        .Concat(localIncidentItems)
        .Concat(arpItems)
        .Concat(malwareItems)
        .OrderByDescending(x => x.ts)
        .Take(limit)
        .ToList();

    var stixIds = merged
        .Where(x => x.stixId.HasValue)
        .Select(x => x.stixId!.Value)
        .Distinct()
        .ToList();

    var mitreMap = new Dictionary<int, (string mitreId, string mitreUrl)>();

    if (stixIds.Count > 0)
    {
        var f = Builders<BsonDocument>.Filter.In("stix_object_id", stixIds);

        var stixDocs = await stixColl
            .Find(f)
            .Project(Builders<BsonDocument>.Projection
                .Include("stix_object_id")
                .Include("mitre_url")
                .Include("attack_pattern.id"))
            .ToListAsync(ct);

        foreach (var sd in stixDocs)
        {
            if (!sd.TryGetValue("stix_object_id", out var sidVal)) continue;

            int sid;
            try
            {
                sid = sidVal.BsonType == BsonType.Int32 ? sidVal.AsInt32 :
                      sidVal.BsonType == BsonType.Int64 ? (int)sidVal.AsInt64 :
                      int.Parse(sidVal.ToString());
            }
            catch { continue; }

            var mitreUrl = sd.TryGetValue("mitre_url", out var urlVal) ? urlVal.ToString() : "";

            string? mitreId = null;
            if (sd.TryGetValue("attack_pattern", out var apVal) && apVal is BsonDocument apDoc)
            {
                if (apDoc.TryGetValue("id", out var idVal))
                    mitreId = idVal.ToString();
            }

            if (!string.IsNullOrWhiteSpace(mitreId))
                mitreMap[sid] = (mitreId!, mitreUrl);
        }
    }

    merged = merged
        .Select(x =>
        {
            if (x.stixId.HasValue && mitreMap.TryGetValue(x.stixId.Value, out var m))
                return x with { mitreId = m.mitreId, mitreUrl = m.mitreUrl };

            return x;
        })
        .ToList();

    DateTime? nextBefore = merged.Count > 0 ? merged[^1].ts : null;

    return Results.Ok(new
    {
        items = merged,
        nextBefore
    });
});


app.MapGet("/api/responses", async (
    IMongoDatabase db,
    int limit = 500,
    int skip = 0,
    CancellationToken ct = default) =>
{
    limit = Math.Clamp(limit, 1, 5000);
    skip = Math.Max(skip, 0);

    var coll = db.GetCollection<BsonDocument>("Response");

    var sort = Builders<BsonDocument>.Sort
        .Descending("date")
        .Descending("_id");

    var projection = Builders<BsonDocument>.Projection
        .Include("_id")
        .Include("menaceType")
        .Include("level")
        .Include("action")
        .Include("date")
        .Include("message")
        .Include("path")
        .Include("sha256")
        .Include("inode");

    var docs = await coll
        .Find(Builders<BsonDocument>.Filter.Empty)
        .Sort(sort)
        .Skip(skip)
        .Limit(limit)
        .Project(projection)
        .ToListAsync(ct);

    static string? GetString(BsonDocument d, string key)
    {
        if (!d.TryGetValue(key, out var v) || v.IsBsonNull) return null;
        return v.IsString ? v.AsString : v.ToString();
    }

    static long? GetLong(BsonDocument d, string key)
    {
        if (!d.TryGetValue(key, out var v) || v.IsBsonNull) return null;

        if (v.IsInt64) return v.AsInt64;
        if (v.IsInt32) return v.AsInt32;
        if (long.TryParse(v.ToString(), out var x)) return x;

        return null;
    }

    var outList = docs.Select(d => new
    {
        _id = d.TryGetValue("_id", out var id) ? id.ToString() : "",
        menaceType = GetString(d, "menaceType") ?? "",
        level = GetString(d, "level") ?? "",
        action = GetString(d, "action") ?? "",
        date = GetString(d, "date") ?? "",
        message = GetString(d, "message") ?? "",
        path = GetString(d, "path"),     
        sha256 = GetString(d, "sha256"), 
        inode = GetLong(d, "inode")       
    }).ToList();

    return Results.Ok(outList);
});



app.Run();


// ================== HELPERS ==================

static FilterDefinition<BsonDocument> SinceDate(DateTime sinceUtc, string field)
{
    return Builders<BsonDocument>.Filter.Gte(field, sinceUtc);
}

static JsonElement BsonToJsonElement(BsonValue? bson)
{
    try
    {
        if (bson == null || bson.IsBsonNull)
            return JsonSerializer.SerializeToElement(new { });

        var dotnet = MongoDB.Bson.BsonTypeMapper.MapToDotNetValue(bson);
        return JsonSerializer.SerializeToElement(dotnet, new JsonSerializerOptions { WriteIndented = false });
    }
    catch
    {
        return JsonSerializer.SerializeToElement(bson?.ToJson() ?? "{}");
    }
}

static string? GetString(BsonDocument d, params string[] path)
{
    BsonValue? cur = d;
    foreach (var p in path)
    {
        if (cur is BsonDocument bd && bd.TryGetValue(p, out var next))
            cur = next;
        else
            return null;
    }
    if (cur == null || cur.IsBsonNull) return null;
    return cur.BsonType == BsonType.String ? cur.AsString : cur.ToString();
}

static bool? GetBool(BsonDocument d, params string[] path)
{
    BsonValue? cur = d;
    foreach (var p in path)
    {
        if (cur is BsonDocument bd && bd.TryGetValue(p, out var next))
            cur = next;
        else
            return null;
    }
    if (cur == null || cur.IsBsonNull) return null;
    return cur.BsonType == BsonType.Boolean ? cur.AsBoolean : (bool?)null;
}

static int? GetInt(BsonDocument d, params string[] path)
{
    BsonValue? cur = d;
    foreach (var p in path)
    {
        if (cur is BsonDocument bd && bd.TryGetValue(p, out var next))
            cur = next;
        else
            return null;
    }
    if (cur == null || cur.IsBsonNull) return null;

    if (cur.BsonType == BsonType.Int32) return cur.AsInt32;
    if (cur.BsonType == BsonType.Int64) return (int)cur.AsInt64;
    if (cur.BsonType == BsonType.Double) return (int)cur.AsDouble;
    if (cur.BsonType == BsonType.String && int.TryParse(cur.AsString, out var v)) return v;
    return null;
}

static double? GetDouble(BsonDocument d, params string[] path)
{
    BsonValue? cur = d;
    foreach (var p in path)
    {
        if (cur is BsonDocument bd && bd.TryGetValue(p, out var next))
            cur = next;
        else
            return null;
    }
    if (cur == null || cur.IsBsonNull) return null;

    if (cur.BsonType == BsonType.Double) return cur.AsDouble;
    if (cur.BsonType == BsonType.Int32) return cur.AsInt32;
    if (cur.BsonType == BsonType.Int64) return cur.AsInt64;
    if (cur.BsonType == BsonType.String && double.TryParse(cur.AsString, out var v)) return v;
    return null;
}

static ThreatLevel MapMalwareScoreToThreatLevel(double? score)
{
    // soglie 0..100
    if (score is null) return ThreatLevel.Medium;
    if (score >= 80) return ThreatLevel.High;
    if (score >= 50) return ThreatLevel.Medium;
    return ThreatLevel.Low;
}

static long? GetLong(BsonDocument d, params string[] path)
{
    BsonValue? cur = d;
    foreach (var p in path)
    {
        if (cur is BsonDocument bd && bd.TryGetValue(p, out var next))
            cur = next;
        else
            return null;
    }
    if (cur == null || cur.IsBsonNull) return null;

    if (cur.BsonType == BsonType.Int64) return cur.AsInt64;
    if (cur.BsonType == BsonType.Int32) return cur.AsInt32;
    if (cur.BsonType == BsonType.String && long.TryParse(cur.AsString, out var v)) return v;
    return null;
}

static DateTime? GetDateTime(BsonDocument d, params string[] path)
{
    BsonValue? cur = d;
    foreach (var p in path)
    {
        if (cur is BsonDocument bd && bd.TryGetValue(p, out var next))
            cur = next;
        else
            return null;
    }
    if (cur == null || cur.IsBsonNull) return null;

    if (cur.BsonType == BsonType.DateTime)
        return cur.ToUniversalTime();

    if (cur.BsonType == BsonType.String && DateTime.TryParse(cur.AsString, out var dt))
        return dt.ToUniversalTime();

    return null;
}

static DateTime? FromUnixSeconds(long? s)
{
    if (s is null || s <= 0) return null;
    try { return DateTimeOffset.FromUnixTimeSeconds(s.Value).UtcDateTime; }
    catch { return null; }
}

static FilterDefinition<BsonDocument> BeforeDate(DateTime? beforeUtc, string field)
{
    if (beforeUtc is null) return Builders<BsonDocument>.Filter.Empty;
    return Builders<BsonDocument>.Filter.Lt(field, beforeUtc.Value);
}

static string PrettyType(string raw)
{
    raw = raw.Replace("_", " ").Replace("-", " ");
    return System.Globalization.CultureInfo.InvariantCulture.TextInfo.ToTitleCase(raw.ToLowerInvariant());
}

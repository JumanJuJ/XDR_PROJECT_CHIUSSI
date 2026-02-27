
var builder = WebApplication.CreateBuilder(args);

var mongoConn = Environment.GetEnvironmentVariable("MONGO_DB_CONNECTION");
var mongoDbName = Environment.GetEnvironmentVariable("MONGO_DB");

var fileCache = new List<fileModel>();
var processCache = new List<processModel>();
var cacheLock = new object();

if (string.IsNullOrWhiteSpace(mongoConn))
    throw new InvalidOperationException("MONGO_DB_CONNECTION is missing");

if (string.IsNullOrWhiteSpace(mongoDbName))
    throw new InvalidOperationException("MONGO_DB is missing");

builder.Services.AddSingleton<IMongoClient>(_ =>
{
    var settings = MongoClientSettings.FromConnectionString(mongoConn);
    settings.ServerApi = new ServerApi(ServerApiVersion.V1);
    return new MongoClient(settings);
});

builder.Services.AddSingleton<IMongoDatabase>(sp =>
{
    var client = sp.GetRequiredService<IMongoClient>();
    return client.GetDatabase(mongoDbName);
});

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();
ILogger logger = app.Services.GetRequiredService<ILogger<Program>>();

app.UseSwagger();
app.UseSwaggerUI();

// ============================
// Helper: salva batch in Mongo
// ============================

static async Task SaveFilesBatchAsync(
    IMongoDatabase db,
    List<fileModel> files,
    string batchId,
    ILogger logger,
    CancellationToken ct)
{
    try
    {
        await ErrorManager.Handle(
            action: async () =>
            {
                ct.ThrowIfCancellationRequested();

                var coll = db.GetCollection<BsonDocument>("localFileEvents");

                if (files == null || files.Count == 0)
                {
                    logger.LogInformation("[DB] Files batch {BatchId}: 0 docs (skip)", batchId);
                    return;
                }

                var docs = new List<BsonDocument>(files.Count);

                foreach (var f in files)
                {
                    docs.Add(new BsonDocument
                    {
                        ["path"] = f.path,
                        ["inode"] = f.inode,
                        ["size"] = f.size,
                        ["mode"] = f.mode,
                        ["mtime"] = f.mtime,
                        ["uid"] = f.uid.HasValue ? (BsonValue)f.uid.Value : BsonNull.Value,
                        ["gid"] = f.gid.HasValue ? (BsonValue)f.gid.Value : BsonNull.Value,
                        ["sha"] = f.sha
                    });
                }

                if (docs.Count > 0)
                    await coll.InsertManyAsync(docs, cancellationToken: ct);

                logger.LogInformation(
                    "[DB] Saved files batch {BatchId} -> {Count} docs (localFileEvents)",
                    batchId,
                    docs.Count);
            },
            context: $"SaveFilesBatch batchId={batchId}");
    }
    catch (AppException ex) when (ex.Code == ErrorCode.DatabaseError)
    {
        logger.LogWarning(ex, "[DB] Non-fatal DB error saving files batch {BatchId}", batchId);
    }
}

static async Task SaveProcessesBatchAsync(
    IMongoDatabase db,
    List<processModel> procs,
    string batchId,
    ILogger logger,
    CancellationToken ct)
{
    try
    {
        await ErrorManager.Handle(
            action: async () =>
            {
                ct.ThrowIfCancellationRequested();

                var coll = db.GetCollection<BsonDocument>("localProcessEvents");

                if (procs == null || procs.Count == 0)
                {
                    logger.LogInformation("[DB] Processes batch {BatchId}: 0 docs (skip)", batchId);
                    return;
                }

                var docs = new List<BsonDocument>(procs.Count);

                foreach (var p in procs)
                {
                    docs.Add(new BsonDocument
                    {
                        ["ts"] = p.Timestamp,
                        ["pid"] = p.Pid,
                        ["ppid"] = p.Ppid,
                        ["state"] = p.State ?? string.Empty,
                        ["uid"] = p.Uid,
                        ["gid"] = p.Gid,
                        ["start"] = p.StartEpoch,

                        ["comm"] = p.Comm ?? string.Empty,
                        ["exe"] = p.Exe ?? string.Empty,
                        ["cwd"] = p.Cwd ?? string.Empty,
                        ["cmdline"] = p.Cmdline ?? string.Empty,

                        ["vmrss_kb"] = p.VmRssKb,
                        ["vmsize_kb"] = p.VmSizeKb
                    });
                }

                if (docs.Count > 0)
                    await coll.InsertManyAsync(docs, cancellationToken: ct);

                logger.LogInformation(
                    "[DB] Saved processes batch {BatchId} -> {Count} docs (localProcessEvents)",
                    batchId,
                    docs.Count);
            },
            context: $"SaveProcessesBatch batchId={batchId}");
    }
    catch (AppException ex) when (ex.Code == ErrorCode.DatabaseError)
    {
        logger.LogWarning(ex, "[DB] Non-fatal DB error saving processes batch {BatchId}", batchId);
    }
}

// ============================
// /events
// ============================


app.MapPost("/events", async (
    [FromBody] string jsonString,
    IMongoDatabase db,
    ILogger<Detector> detLogger,
    CancellationToken ct) =>
{
    // 1) input validation
    if (string.IsNullOrWhiteSpace(jsonString))
        return Results.BadRequest("Empty body");

    JArray rawDocs;
    try
    {
        rawDocs = JArray.Parse(jsonString);
    }
    catch (Exception ex)
    {
        detLogger.LogWarning(ex, "Invalid JSON body");
        return Results.BadRequest("Invalid JSON");
    }

    // 2) parse -> PacketSource
    var packets = new List<PacketSource>(rawDocs.Count);

    foreach (var doc in rawDocs)
    {
        var layers = doc["_source"]?["layers"];
        if (layers == null) continue;

        var packet = new PacketSource
        {
            Index = (string?)doc["_index"],
            Type = (string?)doc["_type"],
            Score = doc["_score"]?.ToObject<int?>() ?? 0,
            Layers = new PacketLayers
            {
                Root = new PacketRootDto
                {
                    Eth = layers["eth"]?.ToObject<EthDto>(),
                    Frame = layers["frame"]?.ToObject<Frame>(),
                    Ip = layers["ip"]?.ToObject<IpDto>(),
                    Tcp = layers["tcp"]?.ToObject<TcpDto>(),
                    Arp = layers["arp"]?.ToObject<ArpDto>()
                }
            }
        };

        packets.Add(packet);
    }

    if (packets.Count == 0)
        return Results.Ok(new { status = "ok", found = Array.Empty<object>(), note = "No packets parsed" });

    // 3) map -> NetworkPacketInfo (sanitization)
    var packetList = new List<NetworkPacketInfo>(packets.Count);

    foreach (var p in packets)
    {
        var info = NetworkPacketMapper.ToModel(p);
        if (info == null) continue;

        packetList.Add(info);

      
        // Log.WriteLog($"DATA: {info?.Ip?.SrcIp}, {info?.Ip?.DstIp}, {info?.Tcp?.Syn}, {info?.Frame?.Time}, {info?.Eth?.EthType}");
    }

    if (packetList.Count == 0)
        return Results.Ok(new { status = "ok", found = Array.Empty<object>(), note = "No packets mapped" });

    // 4) detection in parallelo
    var detector = new Detector(db);

    var synTask = detector.SynFloodDetectionAsync(packetList);
    var arpTask = detector.ArpSpoofingDetectionAsync(packetList);

    await Task.WhenAll(synTask, arpTask);

    var synAlert = await synTask;
    var arpAlert = await arpTask;

    // 5) aggregate results
    var found = new List<object>(capacity: 2);
// var responseCollection = db.GetCollection<BsonDocument>("Response");

    if (synAlert is not null && synAlert.Malicious)
    {
        Console.WriteLine("MENACE FOUND: SYN FLOOD");
        var jsonResponse = ResponseFactory.SynFloodResponse(); // enqueue response lato server
        LogServer.WriteLog(jsonResponse);

        found.Add(new { menace = "syn_flood", alert = synAlert });
    }

    if (arpAlert is not null && arpAlert.Malicious)
    {
        Console.WriteLine("MENACE FOUND: ARP SPOOFING");
        var jsonResponse = ResponseFactory.ArpSpoofingResponse();
        LogServer.WriteLog(jsonResponse);

        found.Add(new { menace = "arp_spoofing", alert = arpAlert });
    }

    // 6) single response
    return Results.Ok(new
    {
        status = "ok",
        packetsReceived = rawDocs.Count,
        packetsParsed = packets.Count,
        packetsMapped = packetList.Count,
        found
    });
});


// ============================
// /localEvents/files
// ============================
app.MapPost("/localEvents/files", async (
    HttpRequest request,
    IMongoDatabase db,
    ILogger<Detector> detLogger,
    CancellationToken ct) =>
{
    Console.WriteLine("Starting the parsing");

    using var reader = new StreamReader(request.Body);
    var fileList = new List<fileModel>();

    while (true)
    {
        var line = await reader.ReadLineAsync();
        if (line is null) break;
        if (string.IsNullOrWhiteSpace(line)) continue;

        JObject doc;
        try { doc = JObject.Parse(line); }
        catch { continue; }

        fileList.Add(new fileModel
        {
            path = (string?)doc["path"],
            inode = (long)doc["inode"],
            size = doc["size"]?.Value<long>() ?? 0,
            mode = (string?)doc["mode"],
            mtime = doc["mtime"]?.Value<long>() ?? 0,
            uid = (long?)doc["uid"],
            gid = (long?)doc["gid"],
            sha = (string?)doc["sha"]
        });
    }

    var filesBatchId = ObjectId.GenerateNewId().ToString();
    await SaveFilesBatchAsync(db, fileList, filesBatchId, logger, ct);

    var detector = new LocalDetector(db);

    var alert = await detector.PrivilegeEscalationDetectionAsync(fileList, ct);

    lock (cacheLock)
    {
        fileCache.Clear();
        fileCache.AddRange(fileList);
    }
    await TryRunLocalWarningAsync(db, detLogger, ct);

    foreach (var file in fileList)
    {
        LogServer.WriteLog($"{file.path},{file.inode}, {file.mode}, {file.sha}");
        //Console.WriteLine($"{file.path},{file.inode}, {file.mode}, {file.sha}");
    }

    if (alert is not null)
    {
        foreach (var item in alert)
        {
            ResponseFactory.PrivilegeEscalationResponse(
            inode: item.inode,
            path: item.path,
            sha256: item.sha,
            message: item.message

);
        }
        Console.WriteLine("LOCAL MENACE FOUND!!!!!!!!");
        LogServer.WriteLog("LOCAL MENACE FOUND !!!!!!!!!");

        return Results.Ok(new { status = "ok", menace = "Privilege Escalation", alert, batchId = filesBatchId });
    }

    LogServer.WriteLog("No menace found");
    Console.WriteLine("No menace found");

    return Results.Ok(new { status = "ok", batchId = filesBatchId });
});

// ============================
// /localEvents/processes
// ============================
app.MapPost("/localEvents/processes", async (
    HttpRequest request,
    IMongoDatabase db,
    ILogger<Detector> detLogger,
    CancellationToken ct) =>
{
    Console.WriteLine("Starting the parsing");

    using var reader = new StreamReader(request.Body);
    var processList = new List<processModel>();

    while (true)
    {
        var line = await reader.ReadLineAsync();
        if (line is null) break;
        if (string.IsNullOrWhiteSpace(line)) continue;

        JObject doc;
        try { doc = JObject.Parse(line); }
        catch { continue; }

        processList.Add(new processModel
        {
            Timestamp = doc["ts"]?.Value<long>() ?? 0,

            Pid = doc["pid"]?.Value<int>() ?? 0,
            Ppid = doc["ppid"]?.Value<int>() ?? 0,

            State = (string?)doc["state"] ?? string.Empty,

            Uid = doc["uid"]?.Value<int>() ?? 0,
            Gid = doc["gid"]?.Value<int>() ?? 0,

            StartEpoch = doc["start"]?.Value<long>() ?? 0,

            Comm = (string?)doc["comm"] ?? string.Empty,
            Exe = (string?)doc["exe"] ?? string.Empty,
            Cwd = (string?)doc["cwd"] ?? string.Empty,
            Cmdline = (string?)doc["cmdline"] ?? string.Empty,

            VmRssKb = doc["vmrss_kb"]?.Value<long>() ?? 0,
            VmSizeKb = doc["vmsize_kb"]?.Value<long>() ?? 0
        });

        Console.WriteLine("adding processes");
    }

    var procsBatchId = ObjectId.GenerateNewId().ToString();
    await SaveProcessesBatchAsync(db, processList, procsBatchId, logger, ct);

    lock (cacheLock)
    {
        processCache.Clear();
        processCache.AddRange(processList);
    }
    await TryRunLocalWarningAsync(db, detLogger, ct);

    foreach (var process in processList)
    {
        LogServer.WriteLog($"{process.Pid},{process.Ppid},{process.Uid},{process.Exe},{process.Cmdline}");
        Console.WriteLine($"{process.Pid},{process.Ppid},{process.Uid},{process.Exe},{process.Cmdline}");
    }

    return Results.Ok(new { status = "ok", batchId = procsBatchId });
});


app.MapPost("/localEvents/malwareAnalysis", async (HttpRequest request, IMongoDatabase db, CancellationToken ct) =>
{
    Console.WriteLine("Starting MALWARE ANALYSIS ingest...");

    const int BATCH_SIZE = 500;

    static int GetEnvInt(string name, int fallback)
    {
        var s = Environment.GetEnvironmentVariable(name);
        return int.TryParse(s, out var v) ? v : fallback;
    }

    var maxParallel = GetEnvInt("MALWARE_PARALLELISM", Math.Min(Environment.ProcessorCount, 8));
    maxParallel = Math.Clamp(maxParallel, 1, 32);

    int readLines = 0;
    int parsedOk = 0;
    int skipped = 0;
    int rawSaved = 0;
    int incidentsCreated = 0;

    var lastIncidentIds = new System.Collections.Concurrent.ConcurrentQueue<string>();
    var seenKeys = new System.Collections.Concurrent.ConcurrentDictionary<string, byte>();

    static List<string> ToStringList(Newtonsoft.Json.Linq.JToken? tok)
    {
        if (tok == null || tok.Type == JTokenType.Null) return new List<string>();

        if (tok.Type == JTokenType.Array)
        {
            var list = new List<string>();
            foreach (var el in tok)
            {
                var s = el?.ToString();
                if (!string.IsNullOrWhiteSpace(s)) list.Add(s);
            }
            return list;
        }

        if (tok.Type == JTokenType.String)
        {
            var s = tok.ToString();
            return string.IsNullOrWhiteSpace(s) ? new List<string>() : new List<string> { s };
        }

        try { return tok.ToObject<List<string>>() ?? new List<string>(); }
        catch { return new List<string>(); }
    }

    static int ToInt(JToken? tok, int def = 0)
    {
        if (tok == null || tok.Type == JTokenType.Null) return def;

        try
        {
            if (tok.Type == JTokenType.Integer) return tok.Value<int>();
            if (tok.Type == JTokenType.Float) return (int)tok.Value<double>();
            if (tok.Type == JTokenType.String && int.TryParse(tok.ToString(), out var v)) return v;
        }
        catch { }

        return def;
    }

    static DateTime ToUtcTimestamp(JToken? tok)
    {
        if (tok == null || tok.Type == JTokenType.Null) return DateTime.UtcNow;

        var s = tok.ToString();
        if (!string.IsNullOrWhiteSpace(s) && DateTime.TryParse(s, out var parsed))
            return parsed.ToUniversalTime();

        return DateTime.UtcNow;
    }

    var batch = new List<XDR.Models.StaticAnalysis.malwareAnalysisModel>(BATCH_SIZE);

    async Task FlushBatchAsync(List<XDR.Models.StaticAnalysis.malwareAnalysisModel> localBatch)
    {
        if (localBatch.Count == 0) return;

        await Parallel.ForEachAsync(
            localBatch,
            new ParallelOptions { MaxDegreeOfParallelism = maxParallel, CancellationToken = ct },
            async (m, token) =>
            {
                try
                {
                    var incident = await StaticAnalysisIngestService.ProcessStaticAnalysisAsync(db, m, token);

                    Interlocked.Increment(ref rawSaved);

                    if (incident != null)
                    {
                        Interlocked.Increment(ref incidentsCreated);

                        lastIncidentIds.Enqueue(incident.Id.ToString());
                        while (lastIncidentIds.Count > 20 && lastIncidentIds.TryDequeue(out _)) { }
                    }
                }
                catch (OperationCanceledException) when (token.IsCancellationRequested) { }
                catch (Exception ex)
                {
                    Console.WriteLine($"[malwareAnalysis] error processing item '{m?.Name}': {ex.Message}");
                }
            });

        localBatch.Clear();
    }

    using var reader = new StreamReader(request.Body);

    while (true)
    {
        ct.ThrowIfCancellationRequested();

        var line = await reader.ReadLineAsync();
        if (line is null) break;

        readLines++;

        if (string.IsNullOrWhiteSpace(line))
            continue;

       JObject doc;
        try
        {
            doc = JObject.Parse(line);
        }
        catch (Exception ex)
        {
            skipped++;
            Console.WriteLine($"[malwareAnalysis] skip bad JSON line {readLines}: {ex.Message}");
            continue;
        }

        var path = doc["path"]?.ToString();
        if (string.IsNullOrWhiteSpace(path))
        {
            skipped++;
            continue;
        }

        var sha = doc["sha256"]?.ToString();
        var dedupKey = !string.IsNullOrWhiteSpace(sha) ? $"sha:{sha}" : $"path:{path}";

        if (!seenKeys.TryAdd(dedupKey, 0))
            continue;

        var model = new XDR.Models.StaticAnalysis.malwareAnalysisModel
        {
            EventType = doc["event_type"]?.ToString() ?? "static_full",
            Path = path,
            Name = doc["name"]?.ToString() ?? string.Empty,
            FileType = doc["file_type"]?.ToString() ?? string.Empty,
            StringsCount = ToInt(doc["strings_count"]),
            Sha256 = sha,
            Urls = ToStringList(doc["urls"]),
            Ips = ToStringList(doc["ips"]),
            Timestamp = ToUtcTimestamp(doc["timestamp"])
        };

        batch.Add(model);
        parsedOk++;

        if (batch.Count >= BATCH_SIZE)
            await FlushBatchAsync(batch);
    }

    await FlushBatchAsync(batch);

    Console.WriteLine($"[malwareAnalysis] read={readLines} parsed={parsedOk} skipped={skipped} rawSaved={rawSaved} incidents={incidentsCreated} parallelism={maxParallel}");

    return Results.Ok(new
    {
        status = "ok",
        read = readLines,
        parsed = parsedOk,
        skipped,
        rawSaved,
        incidentsCreated,
        lastIncidentIds = lastIncidentIds.ToArray(),
        parallelism = maxParallel
    });
});

async Task TryRunLocalWarningAsync(IMongoDatabase db, ILogger<Detector> detLogger, CancellationToken ct)
{
    List<fileModel> filesCopy;
    List<processModel> procsCopy;

    lock (cacheLock)
    {
        if (fileCache.Count == 0 || processCache.Count == 0)
        {
            Console.WriteLine("[LW] Missing cache: files or processes not ready");
            return;
        }

        filesCopy = fileCache.ToList();
        procsCopy = processCache.ToList();
    }

    var detector = new LocalDetector(db);

    var warnings = await detector.LocalWarningDetectionAsync(filesCopy, procsCopy, ct);

    Console.WriteLine($"[LW] LocalWarningDetectionAsync returned: {(warnings?.Count ?? 0)} warnings");
}

app.MapGet("/response", (IMongoDatabase db) =>
{
    if (!ResponseFactory.Queue.TryDequeue(out var responseJson))
    {
        Console.WriteLine("No response given");
        LogServer.WriteLog("No response given");
        return Results.NoContent(); // 204
    }

    Console.WriteLine($"Response given: {responseJson}");
    LogServer.WriteLog($"Response given: {responseJson}");

    try
    {
        var collection = db.GetCollection<BsonDocument>("Response");

        BsonDocument doc;
        try
        {
            doc = BsonDocument.Parse(responseJson);
        }
        catch
        {
            doc = new BsonDocument
            {
                { "raw", responseJson }
            };
        }

        collection.InsertOne(doc);
    }
    catch (Exception ex)
    {
        Console.WriteLine($"[Mongo] Insert failed: {ex.Message}");
        LogServer.WriteLog($"[Mongo] Insert failed: {ex}");
    }

    return Results.Text(responseJson, "application/json");
});


app.MapGet("/getWarnings", () =>
{
    if (!LocalDetector.warningQueue.TryDequeue(out var item))
        return Results.NoContent();

    Console.WriteLine($"ITEM: {item.Path}");

    return Results.Json(item);
});


app.Run();

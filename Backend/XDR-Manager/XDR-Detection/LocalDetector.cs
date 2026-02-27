
using XDR_Detection.utils.warnings;

namespace XDR.Detection.Detector
{
    public class LocalDetector
    {
        private readonly IMongoDatabase _db;

        public static List<AlertPrivilegeEscalationReport?>? reportList;
        public static readonly ConcurrentQueue<WarningLocalReport> warningQueue = new();

        public LocalDetector(IMongoDatabase db)
        {
            _db = db;
        }

        public static int incidentCounter = 0;


        public async Task<List<AlertPrivilegeEscalationReport>?> PrivilegeEscalationDetectionAsync(
            List<fileModel> fileList,
            CancellationToken ct = default)
        {
            var reportList = new List<AlertPrivilegeEscalationReport>();

            if (fileList == null || fileList.Count == 0)
                return null;

            if (!PrivilegeEscalationUtils.baselineInitialized)
            {
                Console.WriteLine("FIRST INITIALIZATION (baseline only)");
                PrivilegeEscalationUtils.CreateFileSystem(fileList);
                return null;
            }

            var coll = _db.GetCollection<IncidentPrivilegeEscalationLite>("localIncidentReport");

            foreach (var file in fileList)
            {
                if (file == null) continue;
                if (!PrivilegeEscalationUtils.IsNewSuidOrSgid(file))
                    continue;

                Console.WriteLine($"ALERT: new SUID/SGID on {file.path} mode={file.mode}");

                try
                {
                    await ErrorManager.Handle(async () =>
                    {
                        var filter = Builders<IncidentPrivilegeEscalationLite>.Filter.And(
                            Builders<IncidentPrivilegeEscalationLite>.Filter.Eq("active", true),
                            Builders<IncidentPrivilegeEscalationLite>.Filter.Eq("alert.path", file.path),
                            Builders<IncidentPrivilegeEscalationLite>.Filter.Eq("alert.inode", file.inode)
                        );

                        var existing = await coll.Find(filter).FirstOrDefaultAsync(ct);

                        Log.WriteLog("ENTRO NEL TRY");
                        Log.WriteLog($"{file.path}, {file.inode}");

                        var now = DateTime.UtcNow;

                        var alertDoc = new AlertPrivilegeEscalationReport
                        {
                            stixId = 2,
                            path = file.path,
                            mode = file.mode,
                            inode = file.inode,
                            sha = file.sha,
                            malicious = true,
                            message = $"A possibile privilege escalation has been found." +
                                      $"File details: path: {file.path}, mode:{file.mode}, inode: {file.inode}, sha: {file.sha}",
                        };

                        if (existing == null)
                        {
                            var nextIncidentId = await Counters.NextAsync(_db, "localIncidentReport", ct);

                            var incident = new IncidentPrivilegeEscalationLite
                            {
                                _id = ObjectId.GenerateNewId(),
                                incidentId = nextIncidentId,
                                status = "NEW",
                                active = true,
                                detectedAtUtc = now,
                                updatedAtUtc = now,
                                alert = alertDoc
                            };

                            await coll.InsertOneAsync(incident, cancellationToken: ct);
                            Console.WriteLine($"[MONGO] PrivEsc incident INSERT (NEW): {nextIncidentId}");

                            reportList.Add(alertDoc);
                            Log.WriteLog("[DEBUG] existing = NULL (no active incident found)");
                        }
                        else
                        {
                            var update = Builders<IncidentPrivilegeEscalationLite>.Update
                                .Set(x => x.status, "UPDATE")
                                .Set(x => x.updatedAtUtc, now)
                                .Set(x => x.alert, alertDoc);

                            await coll.UpdateOneAsync(
                                filter: Builders<IncidentPrivilegeEscalationLite>.Filter.Eq(x => x._id, existing._id),
                                update: update,
                                cancellationToken: ct);

                            Console.WriteLine($"[MONGO] PrivEsc incident UPDATE: {existing.incidentId}");

                            reportList.Add(alertDoc);
                            Log.WriteLog("[DEBUG] existing != NULL (active incident found)");
                        }

                    }, context: "PrivilegeEscalationDetectionAsync/MongoUpsert");
                }
                catch (AppException ex) when (ex.Code == ErrorCode.DatabaseError)
                {
                    Log.WriteLog($"PrivEsc Mongo upsert fallito: {ex}", "ERROR");
                }
            }

            return reportList.Count > 0 ? reportList : null;
        }


        public async Task<List<WarningLocalReport>?> LocalWarningDetectionAsync(
            List<fileModel> fileList,
            List<processModel> processes,
            CancellationToken ct = default)
        {
            Console.WriteLine("Scanning warnings file");
            var coll = _db.GetCollection<dbWarningLocalReport>("localWarning");

            var reportList = new List<WarningLocalReport>();

            if (fileList == null || fileList.Count == 0)
                return null;

            WarningLocalExecChmod.TrackChmodTransitions(fileList);
            var chmodExecAlerts = WarningLocalExecChmod.DetectExecAfterChmod(processes);


            foreach (var path in chmodExecAlerts)
            {
                reportList.Add(new WarningLocalReport
                {
                    Type = "chmod_exec",
                    Path = path,
                    Message = "File became executable and was executed shortly after",
                    TimestampUtc = DateTime.UtcNow
                });
                Console.WriteLine($"PATH: {path}");
            }

            Console.WriteLine($"[WARN] chmodExecAlerts={chmodExecAlerts.Count}, reportList={reportList.Count}");
            Console.WriteLine($"[WARN] queueCount(before)={LocalDetector.warningQueue.Count}");

            if (reportList.Count > 0)
            {
                Console.WriteLine("INSERISCO NEL DB");
                try
                {
                    var doc = new dbWarningLocalReport
                    {
                        TimestampUtc = DateTime.UtcNow,
                        reportList = reportList
                    };

                    await ErrorManager.Handle(async () =>
                    {
                        await coll.InsertOneAsync(doc, cancellationToken: ct);
                    }, context: "LocalWarningDetectionAsync/MongoInsert");
                }
                catch (AppException ex) when (ex.Code == ErrorCode.DatabaseError)
                {
                    Log.WriteLog($"LocalWarning Mongo insert fallito: {ex}", "ERROR");
                }

                foreach (var w in reportList)
                {
                    LocalDetector.warningQueue.Enqueue(w);
                    Console.WriteLine($"[WARN] ENQUEUE {w.Type} {w.Path}");
                }

                Console.WriteLine($"[WARN] queueCount(after)={LocalDetector.warningQueue.Count}");
            }

            return reportList.Count > 0 ? reportList : null;
        }


    }
}

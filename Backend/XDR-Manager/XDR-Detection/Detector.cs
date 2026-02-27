
using XDR_Detection.utils.warnings;

namespace XDR.Detection.Detector
{
    public class Detector
    {
        private readonly IMongoDatabase _db;



        public Detector(IMongoDatabase db)
        {
            _db = db;
        }

        public static int incidentCounter = 0;

public async Task<AlertResult?> SynFloodDetectionAsync(
    List<NetworkPacketInfo> packetList,
    CancellationToken ct = default)
{
    var normalizedList = new List<NetworkPacketInfo>(packetList.Count);

    foreach (var packet in packetList)
        normalizedList.Add(Sanitizer.SynFloodSanitizer(packet));

    var logList = new List<Result>();

    var sliding = new SynFloodSlidingWindow(
        windowLengthSec: 30,
        synThreshold: 5,
        uniqueSrcThreshold: 3,
        topSrcRatioMax: 0.90
    );

    var alert = sliding.Detect(normalizedList, logList);

    if (alert is null || !alert.Malicious)
        return null;

    Interlocked.Increment(ref incidentCounter);

    try
    {
        await ErrorManager.Handle(async () =>
        {
            var collectionIncidents = _db.GetCollection<IncidentSynFloodLite>("incidentReport");
            var nextIncidentId = await Counters.NextAsync(_db, "incidentReport", ct);

            var alertDoc = new SynFloodAlertDoc
            {
                stixId = alert.StixId,
                srcIp = alert.SrcIp,
                dstIp = alert.DstIp,
                srcPort = alert.SrcPort,
                dstPort = alert.DstPort,
                synCount = alert.SynCount,
                windowStart = alert.WindowStart,
                windowEnd = alert.WindowEnd,
                malicious = alert.Malicious,
                attackType = alert.AttackType,
                message = alert.Message,
                detectedAtUtc = DateTime.UtcNow
            };

            var incident = new IncidentSynFloodLite 
            {
                _id = ObjectId.GenerateNewId(),
                incidentId = nextIncidentId,
                date = DateTime.UtcNow,
                alert = alertDoc
            };

            await collectionIncidents.InsertOneAsync(incident, cancellationToken: ct);
        }, context: "SynFloodDetectionAsync/MongoInsert");
    }
    catch (AppException ex) when (ex.Code == ErrorCode.DatabaseError)
    {
        Log.WriteLog($"Insert Mongo fallito: {ex}", "ERROR");
    }

    Log.WriteLog($"SYN FLOOD DETECTED: {alert.Message}", "ERROR");

    return alert;
}
        public async Task<ARPSpoofingWindow.AlertResultARP?> ArpSpoofingDetectionAsync(
            List<NetworkPacketInfo> packetList,
            CancellationToken ct = default)
        {
            if (packetList == null || packetList.Count == 0)
                return null;

            var normalizedList = new List<NetworkPacketInfo>(packetList.Count);

            foreach (var packet in packetList)
            {
                ct.ThrowIfCancellationRequested();
                if (packet == null) continue;

                var cleanPacket = Sanitizer.ArpSpoofSanitizer(packet);
                if (cleanPacket != null)
                    normalizedList.Add(cleanPacket);
            }

            if (normalizedList.Count == 0)
                return null;

            var logList = new List<ARPSpoofingWindow.ResultARP>();

            var detector = new ARPSpoofingWindow(
                windowSeconds: 15,
                uniqueMacsPerIpThreshold: 2,
                arpPacketsPerMacThreshold: 5
            );

            var alert = detector.Detect(normalizedList, logList);

            if (alert is null || !alert.Malicious)
                return null;

            Console.WriteLine($"[ARP] ALERT: {alert.Message}");
            Log.WriteLog($"[ARP] ALERT: {alert.Message}");
            Interlocked.Increment(ref incidentCounter);

            try
            {
                ct.ThrowIfCancellationRequested();

                await ErrorManager.Handle(async () =>
                {
                    var collectionIncidents =
                        _db.GetCollection<IncidentArpSpoofLite>("incidentReportArpSpoof");

                    var nextIncidentId =
                        await Counters.NextAsync(_db, "incidentReportArpSpoof", ct);

                    var alertDoc = new ArpSpoofAlertDoc
                    {
                        stixId = alert.StixId,
                        srcIp = alert.SrcIp,
                        srcMac = alert.SrcMac,
                        windowStart = alert.WindowStart,
                        windowEnd = alert.WindowEnd,
                        malicious = alert.Malicious,
                        message = alert.Message,
                        detectedAtUtc = DateTime.UtcNow
                    };

                    var incident = new IncidentArpSpoofLite
                    {
                        _id = ObjectId.GenerateNewId(),
                        incidentId = nextIncidentId,
                        date = DateTime.UtcNow,
                        alert = alertDoc
                    };

                    await collectionIncidents.InsertOneAsync(incident, cancellationToken: ct);

                }, context: "ArpSpoofingDetectionAsync/MongoInsert");
            }
            catch (OperationCanceledException)
            {
                Log.WriteLog("[ARP] Insert incident cancelled.", "WARN");
                throw;
            }
            catch (AppException ex) when (ex.Code == ErrorCode.DatabaseError)
            {
                Log.WriteLog($"[ARP] Mongo insert failed: {ex}", "ERROR");
                Console.WriteLine("[ARP] Mongo insert exception");
            }

            return alert;
        }

    }
}

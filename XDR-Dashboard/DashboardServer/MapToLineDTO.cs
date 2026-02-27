using System.Text.Json;
using XdrDashboard.Models;

class Mapper
{
    public static TimelineDto MapToTimelineDto(DateTime ts, string kind, JsonElement payload)
    {
        static string? S(JsonElement o, string p)
            => o.ValueKind == JsonValueKind.Object &&
               o.TryGetProperty(p, out var v) &&
               v.ValueKind == JsonValueKind.String
                ? v.GetString()
                : null;

        static int? I(JsonElement o, string p)
            => o.ValueKind == JsonValueKind.Object &&
               o.TryGetProperty(p, out var v) &&
               v.ValueKind == JsonValueKind.Number &&
               v.TryGetInt32(out var n)
                ? n
                : null;

        static bool? B(JsonElement o, string p)
            => o.ValueKind == JsonValueKind.Object &&
               o.TryGetProperty(p, out var v) &&
               (v.ValueKind == JsonValueKind.True || v.ValueKind == JsonValueKind.False)
                ? v.GetBoolean()
                : null;

        string title = kind;
        string message = "-";
        string? src = null;
        string? dst = null;

        bool? malicious = null;

        int? stixId = null;
        string? mitreId = null;
        string? mitreUrl = null;

        if (payload.ValueKind == JsonValueKind.Object)
        {
            stixId = I(payload, "stixId");
        }


        var confidence = ConfidenceLevel.High;
        var threatLevel = ThreatLevel.Low;


        if (payload.ValueKind == JsonValueKind.Object &&
            payload.TryGetProperty("alert", out var alert) &&
            alert.ValueKind == JsonValueKind.Object)
        {
            malicious = B(alert, "malicious");
            message = S(alert, "message") ?? "-";

            stixId ??= I(alert, "stixId");

            var type = S(payload, "type");
            if (!string.IsNullOrWhiteSpace(type))
                title = PrettyType(type);

            // src / dst
            var srcIp = S(alert, "srcIp");
            var dstIp = S(alert, "dstIp");
            var srcPort = I(alert, "srcPort");
            var dstPort = I(alert, "dstPort");

            if (!string.IsNullOrWhiteSpace(srcIp) || srcPort is not null)
                src = $"{srcIp ?? "?"}{(srcPort is null ? "" : $":{srcPort}")}";

            if (!string.IsNullOrWhiteSpace(dstIp) || dstPort is not null)
                dst = $"{dstIp ?? "?"}{(dstPort is null ? "" : $":{dstPort}")}";

            // ARP spoof special case
            var srcMac = S(alert, "srcMac");
            if (!string.IsNullOrWhiteSpace(srcMac))
            {
                title = "ARP Spoofing";
                src = $"mac={srcMac}" + (!string.IsNullOrWhiteSpace(srcIp) ? $" ip={srcIp}" : "");
            }

            threatLevel = malicious == true
                ? ThreatLevel.High      // MENACE
                : ThreatLevel.Low;      // MOSTLY SAFE

            confidence = ConfidenceLevel.High;

            return new TimelineDto(
                ts,
                kind,
                title,
                message,
                src,
                dst,
                stixId,
                mitreId,
                mitreUrl,
                malicious,
                confidence,
                threatLevel,
                payload
            );
        }

        // =====================================================
        // LOCAL WARNING
        // =====================================================
        var warningType = payload.ValueKind == JsonValueKind.Object
            ? S(payload, "warningType")
            : null;

        if (!string.IsNullOrWhiteSpace(warningType))
        {
            title = PrettyType(warningType);
            message = "File became executable and was executed shortly after";
            confidence = ConfidenceLevel.High;
            threatLevel = ThreatLevel.Medium; // WARNING

            stixId ??= I(payload, "stixId");

            if (payload.TryGetProperty("reportList", out var rl) &&
                rl.ValueKind == JsonValueKind.Array &&
                rl.GetArrayLength() > 0)
            {
                var first = rl[0];
                if (first.ValueKind == JsonValueKind.Object)
                {
                    var m = S(first, "Message");
                    var path = S(first, "Path");
                    if (!string.IsNullOrWhiteSpace(m)) message = m!;
                    if (!string.IsNullOrWhiteSpace(path)) src = path;
                }
            }

            return new TimelineDto(
                ts,
                kind,
                title,
                message,
                src,
                dst,
                stixId,
                mitreId,
                mitreUrl,
                null,
                confidence,
                threatLevel,
                payload
            );
        }

        // =====================================================
        // FALLBACK
        // =====================================================
        return new TimelineDto(
            ts,
            kind,
            title,
            message,
            src,
            dst,
            stixId,
            mitreId,
            mitreUrl,
            malicious,
            confidence,
            threatLevel,
            payload
        );
    }

    static string PrettyType(string raw)
    {
        raw = raw.Replace("_", " ").Replace("-", " ");
        return System.Globalization.CultureInfo.InvariantCulture
            .TextInfo
            .ToTitleCase(raw.ToLowerInvariant());
    }
}

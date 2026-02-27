using Newtonsoft.Json;
using System.Collections.Concurrent;
using XDR_Response.models;

namespace XDR.Manager.Response
{

    public static class ResponseFactory
    {
        // QUEUE CENTRALIZZATA
        public static readonly ConcurrentQueue<string> Queue = new();

        public static string SynFloodResponse(string? message = null)
        {
            var dto = new SynFlodResponseDTO
            {
                MenaceType = "syn_flood",
                Level = "BASE",
                Action = "SYN_COOKIES ",
                Date = DateTime.UtcNow,
                Message = message ?? "SynFloodResponse flood mitigation: syn cookies"
            };

            var json = JsonConvert.SerializeObject(dto);

            Queue.Enqueue(json);

            return json;
        }
    

            public static string PrivilegeEscalationResponse(
            long inode,
            string path,
            string? sha256,
            string? message = null)
        {
            var dto = new PrivilegeEscalationDTO
            {
                MenaceType = "privilege_escalation",
                Level = "HARD",
                Action = "REMOVE_SUID",
                Inode = inode,
                Path = path,
                Sha256 = sha256,
                Date = DateTime.UtcNow,
                Message = message ?? "Privilege escalation mitigation: remove SUID bit"
            };

            var json = JsonConvert.SerializeObject(dto);
            Queue.Enqueue(json);
            return json;
        }

        public static string ArpSpoofingResponse(
           string? message = null)
        {
            var dto = new ArpSpoofingResponseDto
            {
                Level = "HARD",
                Action = "FLUSH_ARP_CACHE",
                Date = DateTime.UtcNow,
                Message = message ?? "ARP spoofing detected. Flushing ARP cache."
            };

            var json = JsonConvert.SerializeObject(dto);
            Queue.Enqueue(json);
            return json;
        }
    }


}

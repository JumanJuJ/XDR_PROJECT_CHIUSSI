using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;


namespace XDR_Agent.models
{

    namespace XDR.Agent.Responses
    {
        public static class FileHashUtils
        {
            public static string ComputeSha256Hex(string filePath)
            {
                using var sha = SHA256.Create();
                using var fs = File.OpenRead(filePath);
                var hash = sha.ComputeHash(fs);
                return Convert.ToHexString(hash).ToLowerInvariant();
            }
        }

        public sealed class PrivilegeEscalationResponseDTO
        {
            public string MenaceType { get; init; } = default!;
            public string Level { get; init; } = default!;
            public string Action { get; init; } = default!;
            public string? Message { get; init; }

            public string? Path { get; init; }
            public string? Sha256 { get; init; }
            public int? IncidentId { get; init; }
        }
    }

}

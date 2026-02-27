using XDR_Agent.models.XDR.Agent.Responses;

namespace XDR.Agent.Responses
{
    public static class ResponseDispatcher
    {
        public static void Apply(PrivilegeEscalationResponseDTO dto)
        {
            if (dto == null) return;

            if (!dto.MenaceType.Equals("privilege_escalation", StringComparison.OrdinalIgnoreCase))
                return;

            if (!dto.Action.Equals("REMOVE_SUID", StringComparison.OrdinalIgnoreCase))
                return;

            if (string.IsNullOrWhiteSpace(dto.Path))
                return;

            RemoveSuidBitSafely(dto.Path!, dto.Sha256);
        }

        private static void RemoveSuidBitSafely(string path, string? expectedSha256)
        {
            if (!IsSafeAbsolutePath(path))
                throw new InvalidOperationException($"Unsafe path: {path}");

            if (!File.Exists(path))
                throw new FileNotFoundException($"File not found: {path}", path);

            if (!string.IsNullOrWhiteSpace(expectedSha256))
            {
                var actual = FileHashUtils.ComputeSha256Hex(path);
                if (!actual.Equals(expectedSha256.Trim().ToLowerInvariant(), StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException($"SHA256 mismatch for {path}");
            }

            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                throw new PlatformNotSupportedException("REMOVE_SUID is supported only on Linux");

            var mode = File.GetUnixFileMode(path);

            if ((mode & UnixFileMode.SetUser) == 0)
                return;

            var newMode = mode & ~UnixFileMode.SetUser;
            File.SetUnixFileMode(path, newMode);
        }

        private static bool IsSafeAbsolutePath(string path)
        {
            if (!Path.IsPathRooted(path)) return false;

            if (path.Contains('\0')) return false;

            if (path.Contains(' ')) return false;

            var full = Path.GetFullPath(path);
            if (!full.Equals(path, StringComparison.Ordinal)) return false;

            return true;
        }
    }
}

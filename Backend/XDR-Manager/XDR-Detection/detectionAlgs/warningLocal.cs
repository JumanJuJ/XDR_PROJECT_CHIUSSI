
namespace XDR_Detection.utils.warnings
{
    public static class WarningLocalExecChmod
    {
        private static readonly Dictionary<string, int> lastModeByPath =
            new(StringComparer.Ordinal);

        private static readonly Dictionary<string, DateTime> becameExecutableAt =
            new(StringComparer.Ordinal);

        private static readonly object _lock = new();

        // Permission bits (octal): user/group/other execute
        private const int XUSR = 0x40; // 0100
        private const int XGRP = 0x08; // 0010
        private const int XOTH = 0x01; // 0001

        private static bool IsExecutable(int mode) => (mode & (XUSR | XGRP | XOTH)) != 0;


        private static string NormalizePath(string? p)
        {
            if (string.IsNullOrWhiteSpace(p)) return string.Empty;

            p = p.Trim();

            if (p.StartsWith("./", StringComparison.Ordinal))
                p = p.Substring(2);

            try
            {

                return Path.GetFullPath(p);
            }
            catch
            {
                return p;
            }
        }

        public static void TrackChmodTransitions(List<fileModel> fileList)
        {
            if (fileList == null || fileList.Count == 0) return;

            var now = DateTime.UtcNow;

            lock (_lock)
            {
                foreach (var f in fileList)
                {
                    if (f == null) continue;

                    var rawPath = f.path;
                    if (string.IsNullOrWhiteSpace(rawPath)) continue;

                    var path = NormalizePath(rawPath);
                    if (string.IsNullOrEmpty(path)) continue;

                    int newMode;
                    try
                    {
                        newMode = PrivilegeEscalationUtils.ParseModeBits(f.mode);
                    }
                    catch
                    {
                        continue;
                    }

                    bool newExec = IsExecutable(newMode);

                    if (!lastModeByPath.TryGetValue(path, out int oldMode))
                    {
                        
                        lastModeByPath[path] = newMode;
                        continue;
                    }

                    bool oldExec = IsExecutable(oldMode);

                    if (!oldExec && newExec)
                    {
                        becameExecutableAt[path] = now;
                    }

                    lastModeByPath[path] = newMode;
                }
            }
        }

        public static List<string> DetectExecAfterChmod(List<processModel> processes, int windowSeconds = 60)
        {
            var alerts = new List<string>();
            if (processes == null || processes.Count == 0) return alerts;

            var now = DateTime.UtcNow;

            lock (_lock)
            {
                if (becameExecutableAt.Count > 0)
                {
                    var expiredKeys = becameExecutableAt
                        .Where(kv => (now - kv.Value).TotalSeconds > windowSeconds)
                        .Select(kv => kv.Key)
                        .ToList();

                    foreach (var k in expiredKeys)
                        becameExecutableAt.Remove(k);
                }

                foreach (var p in processes)
                {
                    if (p == null) continue;

                    var rawExe = p.Exe;
                    if (string.IsNullOrWhiteSpace(rawExe)) continue;

                    var exe = NormalizePath(rawExe);
                    if (string.IsNullOrEmpty(exe)) continue;

                    if (becameExecutableAt.TryGetValue(exe, out _))
                    {
                        alerts.Add(exe);
                        becameExecutableAt.Remove(exe); 
                        continue;
                    }

                    var exeName = Path.GetFileName(exe);
                    if (string.IsNullOrWhiteSpace(exeName)) continue;

                    var match = becameExecutableAt.Keys
                        .FirstOrDefault(k => string.Equals(Path.GetFileName(k), exeName, StringComparison.Ordinal));

                    if (!string.IsNullOrEmpty(match))
                    {
                        alerts.Add(match);
                        becameExecutableAt.Remove(match); 
                    }
                }
            }

            return alerts;
        }

  
        public static (int baselineCount, int pendingExecCount) GetStateCounts()
        {
            lock (_lock)
            {
                return (lastModeByPath.Count, becameExecutableAt.Count);
            }
        }
    }
}

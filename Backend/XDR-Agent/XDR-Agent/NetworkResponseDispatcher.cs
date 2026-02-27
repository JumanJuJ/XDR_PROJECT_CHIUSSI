using XDR_Agent.models;

public static class NetworkResponseDispatcher
{
    public static void Apply(NetworkResponseDto dto)
    {
        if (dto == null) return;

        var menace = dto.MenaceType?.Trim().ToLowerInvariant();
        var level = dto.Level?.Trim().ToUpperInvariant();
        var action = dto.Action?.Trim().ToUpperInvariant();

        switch (menace)
        {
            case "synflood":
                if (level == "BASE" || level == "HARD")
                {
                    if (string.IsNullOrEmpty(action) || action == "ENABLE_SYNCOOKIES")
                        EnableSyncookies();
                }
                break;

            case "arp_spoofing":
                if (level == "HARD" && action == "FLUSH_ARP_CACHE")
                    FlushArpCache();
                break;

            default:
                break;
        }
    }

    private static void EnableSyncookies()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            throw new PlatformNotSupportedException("Syncookies supported only on Linux");

        var psi = new ProcessStartInfo
        {
            FileName = "/sbin/sysctl",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        psi.ArgumentList.Add("-w");
        psi.ArgumentList.Add("net.ipv4.tcp_syncookies=1");

        using var p = Process.Start(psi);
        if (p == null) throw new InvalidOperationException("Failed to start sysctl");
        if (!p.WaitForExit(3000))
        {
            try { p.Kill(entireProcessTree: true); } catch { }
            throw new TimeoutException("sysctl timed out");
        }
        if (p.ExitCode != 0)
            throw new Exception($"sysctl failed: {p.StandardError.ReadToEnd()}");
    }

    private static void FlushArpCache()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            throw new PlatformNotSupportedException("ARP flush supported only on Linux");

        var psi = new ProcessStartInfo
        {
            FileName = "/sbin/ip",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        psi.ArgumentList.Add("neigh");
        psi.ArgumentList.Add("flush");
        psi.ArgumentList.Add("all");

        using var p = Process.Start(psi);
        if (p == null) throw new InvalidOperationException("Failed to start ip neigh flush");
        if (!p.WaitForExit(3000))
        {
            try { p.Kill(entireProcessTree: true); } catch { }
            throw new TimeoutException("ip neigh flush timed out");
        }
        if (p.ExitCode != 0)
            throw new Exception($"ARP flush failed: {p.StandardError.ReadToEnd()}");
    }
}

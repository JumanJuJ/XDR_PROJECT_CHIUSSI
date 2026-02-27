using CreatingCaptureFile;

public static class ShellHelper
{
    public static async Task<int> Bash(this string cmd)
    {
        var escapedArgs = cmd.Replace("\"", "\\\"");

        var startInfo = new ProcessStartInfo
        {
            FileName = "bash",
            Arguments = $"-c \"{escapedArgs}\"",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using var process = new Process
        {
            StartInfo = startInfo
        };

        var stdoutBuilder = new StringBuilder();
        var stderrBuilder = new StringBuilder();

        process.OutputDataReceived += (_, e) =>
        {
            if (e.Data != null)
                stdoutBuilder.AppendLine(e.Data);
        };

        process.ErrorDataReceived += (_, e) =>
        {
            if (e.Data != null)
                stderrBuilder.AppendLine(e.Data);
        };

        try
        {
            process.Start();
        }
        catch (Exception ex)
        {
            Log.WriteLog($"Failed to start bash command `{cmd}`: {ex}");
            throw;
        }

        process.BeginOutputReadLine();
        process.BeginErrorReadLine();

        await process.WaitForExitAsync();

        var stdout = stdoutBuilder.ToString();
        var stderr = stderrBuilder.ToString();

        Log.WriteLog($"COMMAND `{cmd}` EXIT CODE: {process.ExitCode}");
        Log.WriteLog($"COMMAND STDOUT: {stdout}");
        Log.WriteLog($"COMMAND STDERR: {stderr}");

        if (process.ExitCode != 0)
        {
            throw new Exception(
                $"Command `{cmd}` failed with exit code `{process.ExitCode}`. Stderr: {stderr}"
            );
        }

        return process.ExitCode;
    }
}




public static class ShellHelperLocal
{
    public sealed class CmdResult
    {
        public int ExitCode { get; init; }
        public string StdOut { get; init; } = "";
        public string StdErr { get; init; } = "";
    }

    public static async Task<CmdResult> BashAsync(string cmd, CancellationToken ct)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "/bin/bash",
            Arguments = $"-lc \"{cmd.Replace("\"", "\\\"")}\"",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using var p = new Process { StartInfo = psi };

        var stdout = new StringBuilder();
        var stderr = new StringBuilder();

        p.OutputDataReceived += (_, e) => { if (e.Data != null) stdout.AppendLine(e.Data); };
        p.ErrorDataReceived += (_, e) => { if (e.Data != null) stderr.AppendLine(e.Data); };

        p.Start();
        p.BeginOutputReadLine();
        p.BeginErrorReadLine();

        await p.WaitForExitAsync(ct);

        return new CmdResult
        {
            ExitCode = p.ExitCode,
            StdOut = stdout.ToString(),
            StdErr = stderr.ToString()
        };
    }
}


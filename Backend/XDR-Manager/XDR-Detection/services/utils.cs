using CreatingCaptureFile;
using System.Diagnostics;
using System.Text;

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

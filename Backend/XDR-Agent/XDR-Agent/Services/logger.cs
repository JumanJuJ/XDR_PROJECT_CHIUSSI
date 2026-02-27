
namespace CreatingCaptureFile
{
    public static class Log
    {
        public static void WriteLog(string msg, string type = "INFO", string agentType = "NETWORK")
        {
            var pathFile = "";

            if (agentType == "LOCAL")
            {
                pathFile = "localAgent.log";
            }
            else
            {
                pathFile = "networkAgent.log";
            }
            var logBase = Environment.GetEnvironmentVariable("XDR_LOG_PATH") ?? "/app/XDR-AgentData/logs";
            var logFile = Path.Combine(logBase, pathFile);

            string timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");

            string logMsg = $"[{type}] {timestamp} {msg}{Environment.NewLine}";

            File.AppendAllText(logFile, logMsg);
        }
    }
}


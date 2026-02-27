
namespace CreatingCaptureFile
{
    public static class Log
    {
        public static void WriteLog(string msg, string type = "INFO")
        {
            var pathFile = "detection.log";
            var logBase = Environment.GetEnvironmentVariable("DETECTION_LOG_PATH") ?? "/app/detectionData/logs";
            var logFile = Path.Combine(logBase, pathFile);

            string timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");

            string logMsg = $"[{type}] {timestamp} {msg}{Environment.NewLine}";

            File.AppendAllText(logFile, logMsg);
        }
    }
}


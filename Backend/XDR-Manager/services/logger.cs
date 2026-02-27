namespace CreatingCaptureFile
{
    public static class LogServer
    {

        public static void WriteLog(
            string msg,
            string type = "INFO",
            string target = "detection")
        {
            string fileName;
            string basePath;

            if (string.Equals(target, "server", StringComparison.OrdinalIgnoreCase))
            {
                fileName = "server.log";
                basePath = Environment.GetEnvironmentVariable("SERVER_LOG_PATH")
                           ?? "/app/log";
            }
            else
            {
                // default = detection
                fileName = "detection.log";
                basePath = Environment.GetEnvironmentVariable("DETECTION_LOG_PATH")
                           ?? "/app/detectionData/logs";
            }

            Directory.CreateDirectory(basePath);

            var logFile = Path.Combine(basePath, fileName);
            var timestamp = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss");

            var logMsg = $"[{type}] {timestamp} {msg}{Environment.NewLine}";

            // atomic append, thread-safe
            File.AppendAllText(logFile, logMsg);
        }
    }
}


using XDR_Agent.models.XDR.Agent.Responses;
using XDR_Detection.MalwareStaticAnalysis;
namespace XDR_Agent.Local
{
    public sealed class LocalAgentWorker : BackgroundService
    {
        public static readonly HttpClient httpClient = new HttpClient(new SocketsHttpHandler
        {
            PooledConnectionLifetime = TimeSpan.FromMinutes(10),
            PooledConnectionIdleTimeout = TimeSpan.FromMinutes(2),
            MaxConnectionsPerServer = 32,
            AutomaticDecompression = DecompressionMethods.All
        })
        {
            Timeout = TimeSpan.FromSeconds(30)
        };

        private readonly Channel<WarningLocalReport> _warningQueue =
            Channel.CreateBounded<WarningLocalReport>(new BoundedChannelOptions(256)
            {
                FullMode = BoundedChannelFullMode.DropOldest,
                SingleReader = true,
                SingleWriter = true
            });

        private readonly SemaphoreSlim _analysisGate = new SemaphoreSlim(1, 1);

        protected override Task ExecuteAsync(CancellationToken stoppingToken)
        {
            Console.WriteLine("XDR Agent (Worker) started...");
            return RunAsync(stoppingToken);
        }

        private async Task RunAsync(CancellationToken ct)
        {
            var consumer = ConsumeWarningsAsync(ct);
            var producer = ProcessLoopAsync(ct);
            await Task.WhenAll(consumer, producer);
        }

        private async Task ProcessLoopAsync(CancellationToken ct)
        {
            var scriptPath = Environment.GetEnvironmentVariable("XDR_SCRIPT_PATH") ?? "/app/XDR-AgentData/bashScripts";
            var managerUrl = Environment.GetEnvironmentVariable("MANAGER_URL") ?? "http://manager:8080";

            var intervalSeconds = GetEnvInt("XDR_LOOP_SECONDS", 30);
            var interval = TimeSpan.FromSeconds(Math.Clamp(intervalSeconds, 5, 3600));

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await RunBashScriptAsync(Path.Combine(scriptPath, "fileCollection.sh"), ct);
                    await RunBashScriptAsync(Path.Combine(scriptPath, "processCollection.sh"), ct);

                    await SendNdjsonToManagerAsync(
                        httpClient,
                        $"{managerUrl}/localEvents/files",
                        "/app/XDR-AgentData/captures/filesystem.json",
                        ct);

                    await SendNdjsonToManagerAsync(
                        httpClient,
                        $"{managerUrl}/localEvents/processes",
                        "/app/XDR-AgentData/captures/processes.json",
                        ct);

                    await GetResponseAsync(ct);
                    await PollWarningsAndEnqueueAsync(managerUrl, ct);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Agent loop error: {ex}");
                }

                await Task.Delay(interval, ct);
            }
        }

        private static readonly JsonSerializerOptions _jsonOpt = new()
        {
            PropertyNameCaseInsensitive = true
        };

        private async Task PollWarningsAndEnqueueAsync(string managerUrl, CancellationToken ct)
        {
            var url = $"{managerUrl.TrimEnd('/')}/getWarnings";

            using var response = await httpClient.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct);
            if (response.StatusCode == HttpStatusCode.NoContent)
                return;

            response.EnsureSuccessStatusCode();

            await using var stream = await response.Content.ReadAsStreamAsync(ct);
            using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: ct);

            JsonElement root = doc.RootElement;

            if (root.ValueKind == JsonValueKind.Array)
            {
                using var en = root.EnumerateArray();
                if (!en.MoveNext()) return;
                root = en.Current;
            }

            if (root.ValueKind != JsonValueKind.Object)
                return;

            var dto = root.Deserialize<WarningLocalReport>(_jsonOpt);
            if (dto == null || string.IsNullOrWhiteSpace(dto.Path))
                return;

            _warningQueue.Writer.TryWrite(dto);
        }

        private async Task ConsumeWarningsAsync(CancellationToken ct)
        {
            while (await _warningQueue.Reader.WaitToReadAsync(ct))
            {
                while (_warningQueue.Reader.TryRead(out var w))
                {
                    await _analysisGate.WaitAsync(ct);
                    try
                    {
                        Console.WriteLine($"[WARN] {w.Type} {w.Path}");

                        await MalwareStaticAnalysis.FullAnalysisAsync(w.Path, ct);

                        var managerUrl = Environment.GetEnvironmentVariable("MANAGER_URL") ?? "http://manager:8080";
                        await SendNdjsonToManagerAsync(
                            httpClient,
                            $"{managerUrl}/localEvents/malwareAnalysis",
                            "/app/XDR-AgentData/captures/static_results.json",
                            ct);

                        Console.WriteLine("Static analysis completed + sent");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Static analysis error: {ex}");
                    }
                    finally
                    {
                        _analysisGate.Release();
                    }
                }
            }
        }

        private async Task GetResponseAsync(CancellationToken ct)
        {
            var managerUrl = Environment.GetEnvironmentVariable("MANAGER_URL") ?? "http://manager:8080";
            using var resp = await httpClient.GetAsync($"{managerUrl}/response", ct);

            if (!resp.IsSuccessStatusCode)
                return;

            var json = await resp.Content.ReadAsStringAsync(ct);
            if (string.IsNullOrWhiteSpace(json))
                return;

            var dto = JsonConvert.DeserializeObject<PrivilegeEscalationResponseDTO>(json);
            if (dto == null)
                return;

            ResponseDispatcher.Apply(dto);
        }

        public static async Task SendNdjsonToManagerAsync(
            HttpClient client,
            string url,
            string ndjsonPath,
            CancellationToken ct)
        {
            if (!File.Exists(ndjsonPath))
                return;

            await using var fs = new FileStream(
                ndjsonPath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite,
                1024 * 128,
                FileOptions.Asynchronous | FileOptions.SequentialScan);

            using var content = new StreamContent(fs);
            content.Headers.ContentType = new MediaTypeHeaderValue("application/x-ndjson");

            using var req = new HttpRequestMessage(HttpMethod.Post, url)
            {
                Content = content
            };

            using var resp = await client.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);
            resp.EnsureSuccessStatusCode();
        }

        private static async Task RunBashScriptAsync(string scriptFile, CancellationToken ct)
        {
            if (!File.Exists(scriptFile))
                return;

            var psi = new ProcessStartInfo
            {
                FileName = "/bin/bash",
                ArgumentList = { scriptFile },
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var p = new Process { StartInfo = psi };
            p.Start();
            await p.WaitForExitAsync(ct);
        }

        private static int GetEnvInt(string name, int fallback)
        {
            var s = Environment.GetEnvironmentVariable(name);
            return int.TryParse(s, out var v) ? v : fallback;
        }
    }
}

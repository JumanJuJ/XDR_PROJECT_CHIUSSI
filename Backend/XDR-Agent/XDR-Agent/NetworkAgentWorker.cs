using CreatingCaptureFile;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;

using XDR_Agent.models;

namespace XDR_Agent.Network
{
    public class NetworkAgentWorker : BackgroundService
    {
        private CaptureFileWriterDevice? captureWriter;
        private LibPcapLiveDevice? globalDevice;

        private static readonly HttpClient httpClient = new HttpClient();
        private static readonly object writerLock = new object();
        private readonly BlockingCollection<string> pcapCollection = new();

        private int packetIndex = 0;
        private int windowIndex = 0;
        private DateTime windowStart;
        private readonly int windowSeconds = 60;
        private string? currentPcapPath;

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            Console.WriteLine("XDR LocalAgent (Worker) started...");
            Log.WriteLog("XDR LocalAgent (Worker) started");

            var basePath = Environment.GetEnvironmentVariable("XDR_PCAP_PATH") ?? "/app/XDR-AgentData/captures";
            Directory.CreateDirectory(basePath);

            var captureTask = Task.Run(() => StartContinuousCapture(basePath, stoppingToken), stoppingToken);
            var processTask = Task.Run(() => ProcessLoop(stoppingToken), stoppingToken);

            await Task.WhenAll(captureTask, processTask);
        }

        private async Task ProcessLoop(CancellationToken ct)
        {
            foreach (var pcapPath in pcapCollection.GetConsumingEnumerable(ct))
            {
                try
                {
                    Log.WriteLog($"Processing pcap: {pcapPath}");

                    Converter(pcapPath);

                    string json = File.ReadAllText("/app/XDR-AgentData/captures/out.json");

                    await SendToManagerAsync(json, ct);

                    await GetResponseAsync(ct);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    Log.WriteLog($"Error processing pcap {pcapPath}: {ex}", "ERROR");
                }
            }
        }

        private void StartContinuousCapture(string basePath, CancellationToken ct)
        {
            var devices = LibPcapLiveDeviceList.Instance;
            if (devices.Count == 0)
                throw new InvalidOperationException("No capture devices found");

            var device = devices.FirstOrDefault(d => d.Name.Contains("eth0")) ?? devices[0];
            globalDevice = device;

            device.OnPacketArrival += device_OnPacketArrival;
            device.Open();

            windowStart = DateTime.UtcNow;
            windowIndex = 0;
            OpenNewPcapFile(basePath);

            device.StartCapture();
            Log.WriteLog($"Continuous capture started on {device.Name}");

            ct.WaitHandle.WaitOne();

            try
            {
                device.StopCapture();
                device.Close();
            }
            catch { }

            lock (writerLock)
            {
                captureWriter?.Close();
            }

            pcapCollection.CompleteAdding();
        }

        private void OpenNewPcapFile(string basePath)
        {
            lock (writerLock)
            {
                if (captureWriter != null && currentPcapPath != null)
                {
                    captureWriter.Close();
                    pcapCollection.Add(currentPcapPath);
                    Log.WriteLog($"Closed pcap file and enqueued: {currentPcapPath}");
                }

                currentPcapPath = Path.Combine(basePath, $"out_{windowIndex}.pcap");
                CreateEthernetPcap(currentPcapPath);

                captureWriter = new CaptureFileWriterDevice(currentPcapPath);
                captureWriter.Open();

                Log.WriteLog($"Opened new pcap file: {currentPcapPath}");
            }
        }

        private void device_OnPacketArrival(object sender, PacketCapture e)
        {
            var rawPacket = e.GetPacket();
            var now = DateTime.UtcNow;

            lock (writerLock)
                captureWriter?.Write(rawPacket);

            if ((now - windowStart).TotalSeconds >= windowSeconds)
            {
                windowStart = now;
                windowIndex++;

                var basePath = Environment.GetEnvironmentVariable("XDR_PCAP_PATH") ?? "/app/XDR-AgentData/captures";
                OpenNewPcapFile(basePath);
            }

            if (rawPacket.LinkLayerType == LinkLayers.Ethernet)
            {
                var packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
                var ethernetPacket = (EthernetPacket)packet;

                packetIndex++;
                Log.WriteLog(
                    $"{packetIndex} At: {rawPacket.Timeval.Date:yyyy-MM-dd HH:mm:ss}:{rawPacket.Timeval.Date.Millisecond} " +
                    $"MAC:{ethernetPacket.SourceHardwareAddress} -> MAC:{ethernetPacket.DestinationHardwareAddress}"
                );
                Console.WriteLine($"packet {packetIndex} dumped");
            
    
            }
        }

        private static void Converter(string pcapPath)
        {
            Environment.SetEnvironmentVariable("PCAP_FILE_PATH", pcapPath);

            var scriptPath = Environment.GetEnvironmentVariable("XDR_SCRIPT_PATH") ?? "/app/XDR-AgentData/bashScripts";
            var scriptFile = Path.Combine(scriptPath, "jsonConverter.sh");
            string scriptCommand = File.ReadAllText(scriptFile);

            var task = scriptCommand.Bash();
            task.GetAwaiter().GetResult();

            Log.WriteLog($"Conversion pcap -> json completed for {pcapPath}");
        }

        private static void CreateEthernetPcap(string path)
        {
            using (var fs = new FileStream(path, FileMode.Create))
            using (var bw = new BinaryWriter(fs))
            {
                bw.Write(0xa1b2c3d4);    // magic number
                bw.Write((ushort)2);    // major version
                bw.Write((ushort)4);    // minor version
                bw.Write(0);            // timezone
                bw.Write(0);            // accuracy
                bw.Write(65535);        // snapshot length
                bw.Write((uint)1);      // LINKTYPE_ETHERNET (1)
            }
        }

        private async Task SendToManagerAsync(string data, CancellationToken ct)
        {
            var managerUrl = Environment.GetEnvironmentVariable("MANAGER_URL") ?? "http://manager:8080";
            var response = await httpClient.PostAsJsonAsync($"{managerUrl}/events", data, ct);
            if (!response.IsSuccessStatusCode)
                Log.WriteLog($"Errore POST: {response.StatusCode}");
        }


private async Task GetResponseAsync(CancellationToken ct)
    {
        var managerUrl = Environment.GetEnvironmentVariable("MANAGER_URL") ?? "http://manager:8080";

        using var response = await httpClient.GetAsync($"{managerUrl}/response", ct);

        if (response.StatusCode == HttpStatusCode.NoContent)
            return;

        if (!response.IsSuccessStatusCode)
            return;

        var json = await response.Content.ReadAsStringAsync(ct);
        if (string.IsNullOrWhiteSpace(json))
            return;

        NetworkResponseDto? dto;
        try
        {
            dto = JsonConvert.DeserializeObject<NetworkResponseDto>(json);
        }
        catch (Exception ex)
        {
            Log.WriteLog($"Invalid response JSON: {ex.Message}");
            return;
        }

        if (dto == null || string.IsNullOrWhiteSpace(dto.MenaceType) || string.IsNullOrWhiteSpace(dto.Level))
            return;

        try
        {
            NetworkResponseDispatcher.Apply(dto);

            Log.WriteLog($"Response applied: menaceType={dto.MenaceType} level={dto.Level} action={dto.Action} msg={dto.Message}");
            Console.WriteLine($"RESPONSE APPLIED: menaceType={dto.MenaceType} level={dto.Level} action={dto.Action}");
        }
        catch (Exception ex)
        {
            Log.WriteLog($"Response apply failed: menaceType={dto.MenaceType} level={dto.Level} action={dto.Action} err={ex.Message}");
        }
    }

}
}

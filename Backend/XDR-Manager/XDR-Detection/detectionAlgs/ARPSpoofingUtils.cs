

namespace XDR.Detection.ARPSpoofing
{
    public sealed class ARPSpoofingWindow
    {
        private static string? TryGetAnyIp(NetworkPacketInfo p)
        {
            return p.Arp?.SenderIp ?? p.Ip?.SrcIp;
        }

        private readonly double _windowSeconds;
        private readonly int _uniqueMacsPerIpThreshold;
        private readonly int _arpPacketsPerMacThreshold;

        public ARPSpoofingWindow(
            double windowSeconds = 10,
            int uniqueMacsPerIpThreshold = 2,
            int arpPacketsPerMacThreshold = 20)
        {
            _windowSeconds = windowSeconds;
            _uniqueMacsPerIpThreshold = uniqueMacsPerIpThreshold;
            _arpPacketsPerMacThreshold = arpPacketsPerMacThreshold;
        }

        public AlertResultARP? Detect(
            List<NetworkPacketInfo> normalizedList,
            List<ResultARP> resultList)
        {
            Console.WriteLine($"[ARP-DEBUG] Detect() called. packets={normalizedList?.Count ?? 0}");

            if (normalizedList == null || normalizedList.Count == 0)
            {
                Console.WriteLine("[ARP-DEBUG] Empty packet list");
                return null;
            }

            var stateByIp = new Dictionary<string, IpState>(StringComparer.OrdinalIgnoreCase);
            var stateByMac = new Dictionary<string, MacRateState>(StringComparer.OrdinalIgnoreCase);

            var ordered = normalizedList
                .Where(p => p?.Frame != null && p.Eth != null)
                .OrderBy(p => p!.Frame.TimeEpoch)
                .ToList();

            Console.WriteLine($"[ARP-DEBUG] After Frame/Eth filter: {ordered.Count}");

            int arpSeen = 0;

            foreach (var packet in ordered)
            {
                var proto = packet.Frame.Protocols;

                if (!IsArp(proto))
                    continue;

                arpSeen++;

                var now = (double)packet.Frame.TimeEpoch;
                var srcMac = packet.Eth?.SrcMac;
                var srcIp = TryGetAnyIp(packet);

                Console.WriteLine(
                    $"[ARP-DEBUG] ARP pkt t={now} mac={srcMac ?? "NULL"} ip={srcIp ?? "NULL"} proto={proto}");

                if (string.IsNullOrWhiteSpace(srcMac))
                {
                    Console.WriteLine("[ARP-DEBUG] -> skipped: empty srcMac");
                    continue;
                }
                Console.WriteLine(
    $"[DEBUG-IP] ArpSender={packet.Arp?.SenderIp} IpSrc={packet.Arp?.SenderIp} Chosen={srcIp}");


                // Telemetria
                resultList.Add(new ResultARP(
                    stixId: 3,
                    srcIp: srcIp ?? "unknown",
                    srcMac: srcMac,
                    date: DateTime.UtcNow,
                    timeEpoch: (long)now
                ));

                // =========================
                // B) High ARP rate per MAC
                // =========================
                if (!stateByMac.TryGetValue(srcMac, out var macState))
                {
                    macState = new MacRateState(_windowSeconds);
                    stateByMac[srcMac] = macState;
                    Console.WriteLine($"[ARP-DEBUG] New MAC state created for {srcMac}");
                }

                macState.Add(now);

                Console.WriteLine(
                    $"[ARP-DEBUG] MAC={srcMac} ARP-count-in-window={macState.Count}");

                if (macState.Count >= _arpPacketsPerMacThreshold)
                {
                    Console.WriteLine(
                        $"[ARP-DEBUG] !!! HIGH ARP RATE TRIGGERED mac={srcMac} count={macState.Count}");

                    return new AlertResultARP(
                        stixId: 3,
                        srcIp:  srcIp,
                        //"172.25.0.21",
                        srcMac: srcMac,
                        date: DateTime.UtcNow,
                        windowStart: (long)macState.WindowStart,
                        windowEnd: (long)macState.WindowEnd,
                        malicious: true,
                        message:
                            $"IP->MAC Flapping detected ip: {"172.25.0.21"}, mac:{srcMac} and High ARP rate detected"
                    );
                }

                // =========================
                // A) IP -> MAC flapping
                // =========================
                if (!string.IsNullOrWhiteSpace(srcIp))
                {
                    if (!stateByIp.TryGetValue(srcIp, out var ipState))
                    {
                        ipState = new IpState(_windowSeconds);
                        stateByIp[srcIp] = ipState;
                        Console.WriteLine($"[ARP-DEBUG] New IP state created for {srcIp}");
                    }

                    ipState.Add(now, srcMac);

                    Console.WriteLine(
                        $"[ARP-DEBUG] IP={srcIp} uniqueMacs={ipState.UniqueMacs.Count}");

                    if (ipState.UniqueMacs.Count >= _uniqueMacsPerIpThreshold)
                    {
                        Console.WriteLine(
                            $"[ARP-DEBUG] !!! IP->MAC FLAPPING TRIGGERED ip={srcIp}");

                        return new AlertResultARP(
                            stixId: 3,
                            srcIp: srcIp,
                            srcMac: srcMac,
                            date: DateTime.UtcNow,
                            windowStart: (long)ipState.WindowStart,
                            windowEnd: (long)ipState.WindowEnd,
                            malicious: true,
                            message:
                                $"IP->MAC flapping detected: ip={srcIp}, macs=[{string.Join(",", ipState.UniqueMacs)}]"
                        );
                    }
                }
            }

            Console.WriteLine($"[ARP-DEBUG] End of loop. Total ARP packets seen={arpSeen}");
            Console.WriteLine($"[ARP-DEBUG] States: MACs={stateByMac.Count}, IPs={stateByIp.Count}");

            return null;
        }

        private static bool IsArp(string? protocols)
            => !string.IsNullOrWhiteSpace(protocols)
               && protocols.Contains("arp", StringComparison.OrdinalIgnoreCase);

        /*
        private static string? TryGetAnyIp(NetworkPacketInfo p)
        {
            return p.Ip?.SrcIp;
        }
        */

        // ===== Per-IP =====
        private sealed class IpState
        {
            private readonly double _windowSeconds;
            private readonly Queue<(double t, string mac)> _q = new();

            public double WindowStart { get; private set; }
            public double WindowEnd { get; private set; }
            public HashSet<string> UniqueMacs { get; } =
                new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            public IpState(double windowSeconds) => _windowSeconds = windowSeconds;

            public void Add(double time, string mac)
            {
                WindowEnd = time;
                _q.Enqueue((time, mac));

                while (_q.Count > 0 && (time - _q.Peek().t) > _windowSeconds)
                    _q.Dequeue();

                UniqueMacs.Clear();
                foreach (var x in _q) UniqueMacs.Add(x.mac);

                WindowStart = _q.Count > 0 ? _q.Peek().t : time;
            }
        }

        // ===== Per-MAC =====
        private sealed class MacRateState
        {
            private readonly double _windowSeconds;
            private readonly Queue<double> _q = new();

            public double WindowStart { get; private set; }
            public double WindowEnd { get; private set; }
            public int Count => _q.Count;

            public MacRateState(double windowSeconds) => _windowSeconds = windowSeconds;

            public void Add(double time)
            {
                WindowEnd = time;
                _q.Enqueue(time);

                while (_q.Count > 0 && (time - _q.Peek()) > _windowSeconds)
                    _q.Dequeue();

                WindowStart = _q.Count > 0 ? _q.Peek() : time;
            }
        }

        // ===== Output =====
        public class ResultARP
        {
            public int StixId { get; }
            public string SrcIp { get; }
            public string SrcMac { get; }
            public DateTime Date { get; }
            public long TimeEpoch { get; }

            public ResultARP(int stixId, string srcIp, string srcMac, DateTime date, long timeEpoch)
            {
                StixId = stixId;
                SrcIp = srcIp;
                SrcMac = srcMac;
                Date = date;
                TimeEpoch = timeEpoch;
            }
        }

        public class AlertResultARP : ResultARP
        {
            public long WindowStart { get; }
            public long WindowEnd { get; }
            public bool Malicious { get; }
            public string? Message { get; }

            public AlertResultARP(
                int stixId,
                string srcIp,
                string srcMac,
                DateTime date,
                long windowStart,
                long windowEnd,
                bool malicious,
                string? message)
                : base(stixId, srcIp, srcMac, date, timeEpoch: windowEnd)
            {
                WindowStart = windowStart;
                WindowEnd = windowEnd;
                Malicious = malicious;
                Message = message;
            }
        }
    }
}

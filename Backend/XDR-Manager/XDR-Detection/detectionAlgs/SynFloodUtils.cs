using System;
using System.Collections.Generic;
using System.Linq;
using XDR.Manager.NetworkInfoNamespace;

namespace XDR.Detection.Utils.SynFlood
{
    public sealed class SynFloodSlidingWindow
    {
        private readonly long _windowLengthSec;
        private readonly int _synThreshold;        // totale SYN nella finestra per target
        private readonly int _uniqueSrcThreshold;  // sorgenti uniche per target
        private readonly double _topSrcRatioMax;   // se troppo alto => più DoS che DDoS

        public SynFloodSlidingWindow(
            long windowLengthSec,
            int synThreshold,
            int uniqueSrcThreshold = 4,
            double topSrcRatioMax = 0.90)
        {
            if (windowLengthSec <= 0) throw new ArgumentOutOfRangeException(nameof(windowLengthSec));
            if (synThreshold <= 0) throw new ArgumentOutOfRangeException(nameof(synThreshold));
            if (uniqueSrcThreshold < 1) throw new ArgumentOutOfRangeException(nameof(uniqueSrcThreshold));
            if (topSrcRatioMax <= 0 || topSrcRatioMax > 1.0) throw new ArgumentOutOfRangeException(nameof(topSrcRatioMax));

            _windowLengthSec = windowLengthSec;
            _synThreshold = synThreshold;
            _uniqueSrcThreshold = uniqueSrcThreshold;
            _topSrcRatioMax = topSrcRatioMax;
        }

        public AlertResult? Detect(
            List<NetworkPacketInfo> normalizedList,
            List<Result> resultList)
        {
            var windows = new Dictionary<(string dstIp, int dstPort), TargetWindow>();

            var ordered = normalizedList
                .Where(p => p?.Frame != null && p.Tcp != null && p.Ip != null)
                .Where(p => IsTcp(p?.Frame?.Protocols) && p.Tcp?.Syn == true)
                .OrderBy(p => p.Frame?.TimeEpoch);

            foreach (var packet in ordered)
            {
                var t = packet.Frame.TimeEpoch;

                var key = (packet.Ip.DstIp, packet.Tcp.DstPort);

                if (!windows.TryGetValue(key, out var tw))
                {
                    tw = new TargetWindow();
                    windows[key] = tw;
                }

                tw.Enqueue(packet.Ip.SrcIp, t);

                var expireBefore = t - _windowLengthSec;
                tw.Expire(expireBefore);

                var windowStart = tw.WindowStartEpoch;
                var windowEnd = tw.WindowEndEpoch;
                var synCount = tw.TotalCount;
                var uniqueSrc = tw.UniqueSrcCount;
                var topSrcRatio = tw.TopSrcRatio;

                resultList.Add(new Result(
                    stixId: 1,
                    srcIp: packet.Ip.SrcIp,
                    dstIp: packet.Ip.DstIp,
                    srcPort: packet.Tcp.SrcPort,
                    dstPort: packet.Tcp.DstPort,
                    synCount: synCount,
                    windowStart: windowStart,
                    windowEnd: windowEnd
                ));

                if (synCount < _synThreshold)
                    continue;


                var isDdos =
                    uniqueSrc >= _uniqueSrcThreshold &&
                    topSrcRatio <= _topSrcRatioMax;

                var attackType = isDdos ? "DDoS" : "DoS";

                return new AlertResult(
                    stixId: 1,
                    srcIp: packet.Ip.SrcIp,
                    dstIp: packet.Ip.DstIp,
                    srcPort: packet.Tcp.SrcPort,
                    dstPort: packet.Tcp.DstPort,
                    synCount: synCount,
                    windowStart: windowStart,
                    windowEnd: windowEnd,

                    malicious: true,
                    attackType: attackType,
                    message:
                        $"{attackType} SYN flood on {key.DstIp}:{key.DstPort}. " +
                        $"SYN={synCount} in {windowEnd - windowStart}s, "                );
            }

            return null;
        }

        private static bool IsTcp(string protocols)
            => !string.IsNullOrEmpty(protocols)
               && protocols.Contains("tcp", StringComparison.OrdinalIgnoreCase);

        private sealed class TargetWindow
        {
            private readonly Queue<(string srcIp, long t)> _q = new();
            private readonly Dictionary<string, int> _srcCounts = new();

            public int TotalCount => _q.Count;
            public int UniqueSrcCount => _srcCounts.Count;

            public long WindowStartEpoch => _q.Count == 0 ? 0 : _q.Peek().t;
            public long WindowEndEpoch { get; private set; } = 0;

            public double TopSrcRatio
            {
                get
                {
                    if (_q.Count == 0) return 0;
                    var max = 0;
                    foreach (var kv in _srcCounts)
                        if (kv.Value > max) max = kv.Value;
                    return (double)max / _q.Count;
                }
            }

            public void Enqueue(string srcIp, long t)
            {
                _q.Enqueue((srcIp, t));
                WindowEndEpoch = t;

                if (_srcCounts.TryGetValue(srcIp, out var c))
                    _srcCounts[srcIp] = c + 1;
                else
                    _srcCounts[srcIp] = 1;
            }

            public void Expire(long expireBefore)
            {
                while (_q.Count > 0 && _q.Peek().t < expireBefore)
                {
                    var (srcIp, _) = _q.Dequeue();
                    if (_srcCounts.TryGetValue(srcIp, out var c))
                    {
                        if (c <= 1) _srcCounts.Remove(srcIp);
                        else _srcCounts[srcIp] = c - 1;
                    }
                }
            }
        }
    }

    public class Result
    {
        public int StixId { get; }
        public string SrcIp { get; }
        public string DstIp { get; }
        public int SrcPort { get; }
        public int DstPort { get; }

        public int SynCount { get; }
        public long WindowStart { get; }
        public long WindowEnd { get; }



        public Result(
            int stixId, string srcIp, string dstIp, int srcPort, int dstPort,
            int synCount, long windowStart, long windowEnd)
        {
            StixId = stixId;
            SrcIp = srcIp;
            DstIp = dstIp;
            SrcPort = srcPort;
            DstPort = dstPort;
            SynCount = synCount;
            WindowStart = windowStart;
            WindowEnd = windowEnd;

        }
    }

    public class AlertResult : Result
    {
        public bool Malicious { get; }
        public string AttackType { get; }
        public string? Message { get; }

        public AlertResult(
            int stixId, string srcIp, string dstIp, int srcPort, int dstPort,
            int synCount, long windowStart, long windowEnd,
            bool malicious, string? attackType, string? message)
            : base(stixId, srcIp, dstIp, srcPort, dstPort, synCount, windowStart, windowEnd)
        {
            Malicious = malicious;
            AttackType = attackType;
            Message = message;
        }
    }
}

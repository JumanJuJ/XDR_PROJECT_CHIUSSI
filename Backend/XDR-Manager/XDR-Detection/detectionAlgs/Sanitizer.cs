using XDR.Manager.FrameInfoNamespace;
using XDR.Manager.IpInfoNamespace;
using XDR.Manager.NetworkInfoNamespace;
using XDR.Manager.TcpInfoNamespace;
  namespace XDR.Detection.Utils.Sanitizer
    {
    public static class Sanitizer
    {
        public static NetworkPacketInfo? SynFloodSanitizer(NetworkPacketInfo? packet)
        {
            if (packet is null) return null;

            return new NetworkPacketInfo
            {
                Frame = new FrameInfo
                {
                    Protocols = packet.Frame?.Protocols,
                    TimeEpoch = packet.Frame?.TimeEpoch ?? 0
                },

                Ip = new IpInfo
                {
                    SrcIp = packet.Ip?.SrcIp,
                    DstIp = packet.Ip?.DstIp
                },

                Tcp = new TcpInfo
                {
                    SrcPort = packet.Tcp?.SrcPort ?? 0,
                    DstPort = packet.Tcp?.DstPort ?? 0,

                    // FLAG TCP USATI PER DETECTION
                    Syn = packet.Tcp?.Syn ?? false,
                    AckFlag = packet.Tcp?.AckFlag ?? false,
                    Fin = packet.Tcp?.Fin ?? false,
                    Rst = packet.Tcp?.Rst ?? false,
                    Psh = packet.Tcp?.Psh ?? false,
                    Urg = packet.Tcp?.Urg ?? false,

                    // Timing
                    TimeDelta = packet.Tcp?.TimeDelta ?? 0
                }
            };
        }

        

    public static NetworkPacketInfo ArpSpoofSanitizer(NetworkPacketInfo p)
        {
            if (p == null)
                return p;

            // --- IP ---
            if (p.Ip != null)
            {
                p.Ip.SrcIp = p.Ip.SrcIp?.Trim();
                p.Ip.DstIp = p.Ip.DstIp?.Trim();
            }

            // --- ETH ---
            if (p.Eth != null)
            {
                p.Eth.SrcMac = p.Eth.SrcMac?.Trim();
            }

            if (p.Frame != null)
            {
                if (p.Frame.TimeEpoch <= 0)
                {
                    p.Frame.TimeEpoch =
                        (long)(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() / 1000.0);
                }
            }

            return p;
        }
    }






    }
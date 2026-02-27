using System;
using System.ComponentModel.Design;
using System.Globalization;
using System.Net.Sockets;
using System.Reflection.Metadata.Ecma335;
using XDR.Manager.ArpDtoNamespace;
using XDR.Manager.EthDtoNamespace;
using XDR.Manager.EthInfoNamespace;
using XDR.Manager.FrameInfoNamespace;
using XDR.Manager.IpDtoNamespace;
using XDR.Manager.IpInfoNamespace;
using XDR.Manager.NetworkInfoNamespace;
using XDR.Manager.TcpDtoNamespace;
using XDR.Manager.TcpInfoNamespace;
using static XDR.Manager.NetworkInfoNamespace.NetworkPacketInfo;
using static XDR_Classes.localModels.virusTotalIp;
using XDR_Classes.ARPinfo;


namespace XDR.Manager.MapperNamespace {


public static class TcpMapper
    {
        public static TcpInfo ToModel(TcpDto dto)
        {
            if (dto is null)
                return null ;

            return new TcpInfo
            {
                SrcPort = ParseInt(dto.tcpsrcport),
                DstPort = ParseInt(dto.tcpdstport),
                Stream = ParseInt(dto.tcpstream),
                Completeness = ParseInt(dto.tcpcompleteness),
                Length = ParseInt(dto.tcplen),

                Seq = ParseUInt(dto.tcpseq),
                SeqRaw = ParseUInt(dto.tcpseq_raw),
                NextSeq = ParseUInt(dto.tcpnxtseq),

                Ack = ParseUInt(dto.tcpack),
                AckRaw = ParseUInt(dto.tcpack_raw),

                HeaderLength = ParseInt(dto.tcphdr_len),

                // Flags (null-safe)
                FlagsHex = dto.tcpflags,
                Syn = dto.tcpflags_tree?.tcpflagssyn == "1",
                AckFlag = dto.tcpflags_tree?.tcpflagsack == "1",
                Fin = dto.tcpflags_tree?.tcpflagsfin == "1",
                Rst = dto.tcpflags_tree?.tcpflagsreset == "1",
                Psh = dto.tcpflags_tree?.tcpflagspush == "1",
                Urg = dto.tcpflags_tree?.tcpflagsurg == "1",

                WindowSize = ParseInt(dto.tcpwindow_size),
                WindowSizeValue = ParseInt(dto.tcpwindow_size_value),

                Checksum = dto.tcpchecksum,
                ChecksumStatus = dto.tcpchecksumstatus,
                UrgentPointer = ParseInt(dto.tcpurgent_pointer),

                // Timestamps (null-safe)
                TimeRelative = ParseDouble(dto.Timestamps?.tcptime_relative),
                TimeDelta = ParseDouble(dto.Timestamps?.tcptime_delta)
            };
        }

        private static int ParseInt(string? s, int fallback = 0)
            => int.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out var v) ? v : fallback;

        private static uint ParseUInt(string? s, uint fallback = 0)
            => uint.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out var v) ? v : fallback;

        private static double ParseDouble(string? s, double fallback = 0)
            => double.TryParse(s, NumberStyles.Float, CultureInfo.InvariantCulture, out var v) ? v : fallback;
    }


    public static class IpMapper
    {
        public static IpInfo ToModel(IpDto dto)
        {
            if (dto == null)
                return new IpInfo();

            var model = new IpInfo();

            // Version
            if (dto.ipversion != null)
            {
                int.TryParse(dto.ipversion, out int version);
                model.Version = version;
            }

            // Header length
            if (dto.iphdr_len != null)
            {
                int.TryParse(dto.iphdr_len, out int hdrLen);
                model.HeaderLength = hdrLen;
            }

            // DSCP / ECN
            if (dto.ipdsfield_tree != null)
            {
                int.TryParse(dto.ipdsfield_tree.ipdsfielddscp, out int dscp);
                int.TryParse(dto.ipdsfield_tree.ipdsfieldecn, out int ecn);

                model.Dscp = dscp;
                model.Ecn = ecn;
            }

            // Total length
            if (dto.iplen != null)
            {
                int.TryParse(dto.iplen, out int length);
                model.TotalLength = length;
            }

            // Identification (hex or decimal)
            if (dto.ipid != null)
            {
                model.Identification = ParseHexOrDecimal(dto.ipid);
            }

            // Flags
            if (dto.ipflags_tree != null)
            {
                model.ReservedBit = dto.ipflags_tree.ipflagsrb == "1";
                model.DontFragment = dto.ipflags_tree.ipflagsdf == "1";
                model.MoreFragments = dto.ipflags_tree.ipflagsmf == "1";
            }

            // Fragment offset
            if (dto.ipfrag_offset != null)
            {
                int.TryParse(dto.ipfrag_offset, out int frag);
                model.FragmentOffset = frag;
            }
            // TTL
            if (dto.ipttl != null)
            {
                int.TryParse(dto.ipttl, out int ttl);
                model.Ttl = ttl;
            }

            // Protocol
            if (dto.ipproto != null)
            {
                int.TryParse(dto.ipproto, out int proto);
                model.Protocol = proto;
            }

            // Checksum
            if (dto.ipchecksum != null)
            {
                model.Checksum = dto.ipchecksum ?? string.Empty;
            }
            if (dto.ipchecksumstatus != null)
            {
                model.ChecksumStatus = dto.ipchecksumstatus ?? string.Empty;
            }

            // Sorgente / Destinazione
            if (dto.ipsrc != null)
            {
                model.SrcIp = dto.ipsrc ?? string.Empty;

            }
            if (dto.ipdst != null)
            {
                model.DstIp = dto.ipdst ?? string.Empty;
            }
            return model;
        }

        private static ushort ParseHexOrDecimal(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return 0;

            // formato 0xe1c0 → hex
            if (value.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            {
                string hex = value.Substring(2);
                if (ushort.TryParse(hex, System.Globalization.NumberStyles.HexNumber, null, out ushort result))
                    return result;
            }

            // formato decimale
            if (ushort.TryParse(value, out ushort decimalResult))
                return decimalResult;

            return 0;
        }
    }



    public static class FrameMapper
    {
        public static FrameInfo ToModel(Frame dto)
        {
            if (dto == null)
                return new FrameInfo();
            var model = new FrameInfo();
            
            // Encap type
            if (int.TryParse(dto.frameencap_type, out var encap))
                model.EncapType = encap;

            // Time
            if (DateTime.TryParse(dto.frametime, CultureInfo.InvariantCulture,
                                  DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                                  out var time))
            {
                model.Time = time;
            }

            // Epoch
            if (long.TryParse(dto.frametime_epoch, NumberStyles.Float, CultureInfo.InvariantCulture, out var epoch))
                model.TimeEpoch = epoch;

            // Time delta
            if (double.TryParse(dto.frametime_delta, NumberStyles.Float, CultureInfo.InvariantCulture, out var delta))
                model.TimeDelta = delta;

            // Time relative
            if (double.TryParse(dto.frametime_relative, NumberStyles.Float, CultureInfo.InvariantCulture, out var rel))
                model.TimeRelative = rel;

            // Number
            if (int.TryParse(dto.framenumber, out var num))
                model.Number = num;

            // Lengths
            if (int.TryParse(dto.framelen, out var len))
                model.Length = len;

            if (int.TryParse(dto.framecap_len, out var capLen))
                model.CapturedLength = capLen;

            model.Marked = dto.framemarked == "1";
            model.Ignored = dto.frameignored == "1";

            model.Protocols = dto.frameprotocols ?? string.Empty;

            return model;
        }
    }
    public static class EthMapper
    {
        public static EthInfo ToModel(EthDto dto)
        {
            if (dto == null)
                return new EthInfo();

            return new EthInfo
            {
                SrcMac = dto.ethsrc,
                DstMac = dto.ethdst,

                SrcOUI = dto.ethsrc_tree?.ethsrcoui,
                DstOUI = dto.ethdst_tree?.ethdstoui,

                SrcIsLocal = dto.ethsrc_tree?.ethsrclg == "1",
                SrcIsGroup = dto.ethsrc_tree?.ethsrcig == "1",

                DstIsLocal = dto.ethdst_tree?.ethdstlg == "1",
                DstIsGroup = dto.ethdst_tree?.ethdstig == "1",

                EthType = ParseHex(dto.ethtype)
            };
        }

        private static int ParseHex(string hex)
        {
            if (hex != null && hex.StartsWith("0x"))
                return int.Parse(hex.Substring(2),
                                 System.Globalization.NumberStyles.HexNumber);

            return 0;
        }
    }

        public static class ArpMapper
        {
            public static ARPInfo? ToModel(ArpDto? dto)
            {
                if (dto == null) return null;

                return new ARPInfo
                {
                    SenderIp = dto.SenderIp?.Trim(),
                    TargetIp = dto.TargetIp?.Trim(),
                    Opcode = dto.Opcode?.Trim()
                };
            }
        }
    


    public static class NetworkPacketMapper
    {
        public static NetworkPacketInfo ToModel(PacketSource? source)
        {
            var result = new NetworkPacketInfo();

            if (source?.Layers == null)
                return result;

            var layers = source?.Layers;
            result.Eth = EthMapper.ToModel(layers?.Root?.Eth);
            result.Frame = FrameMapper.ToModel(layers?.Root?.Frame);
            result.Ip = IpMapper.ToModel(layers?.Root?.Ip);
            result.Tcp = TcpMapper.ToModel(layers?.Root?.Tcp);
            result.Arp = ArpMapper.ToModel(layers?.Root?.Arp);

            return result;
        }
    }



}






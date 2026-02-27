using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace XDR_Classes.processModel
{

    public class processModel
    {

        public long Timestamp { get; set; }


        public int Pid { get; set; }

        public int Ppid { get; set; }

        // Stato processo 

        public string State { get; set; } = string.Empty;

        // Identity
        public int Uid { get; set; }

        public int Gid { get; set; }

        // Epoch start time del processo
        public long StartEpoch { get; set; }

        public string Comm { get; set; } = string.Empty;

        // Percorso eseguibile
        public string Exe { get; set; } = string.Empty;

        // Working directory
        public string Cwd { get; set; } = string.Empty;

        // Command line completa
        public string Cmdline { get; set; } = string.Empty;

        // Memoria
        public long VmRssKb { get; set; }

        public long VmSizeKb { get; set; }
    }
}

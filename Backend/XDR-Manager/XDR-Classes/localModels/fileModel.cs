namespace XDR.Manager.fileModel
{
    public class fileModel
    {
        public string? path { get; set; }
        public long inode { get; set; }

        public long? size { get; set; }
        public string? mode { get; set; }
        public long? uid { get; set; }
        public long? gid { get; set; }
        public long? mtime { get; set; }

        public string? sha { get; set; }



    }
    }
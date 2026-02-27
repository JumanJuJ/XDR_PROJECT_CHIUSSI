
namespace XDR.Detection.utils.PrivilegeEscalation
{
    public static class PrivilegeEscalationUtils
    {
        private static readonly Dictionary<string, int> fileSys = new(capacity: 200_000);
        public static bool baselineInitialized = false;

        public static int ParseModeBits(string? mode)
        {
            if (string.IsNullOrWhiteSpace(mode)) return 0;
            return Convert.ToInt32(mode.Trim(), 8); 
        }

        public static string? MakeKey(fileModel f)
        {
            var path = f.path;
            var inode = f.inode;

            if (string.IsNullOrWhiteSpace(path)) return null;
            if (inode <= 0) return null;

            return $"{path}|{inode}";
        }

        public static void CreateFileSystem(List<fileModel> fileList)
        {
            if (fileList == null || fileList.Count == 0) return;

            baselineInitialized = true;

            foreach (var f in fileList)
            {
                if (f == null) continue;

                var key = MakeKey(f);
                if (key == null) continue;

                int modeBits = ParseModeBits(f.mode);
                fileSys[key] = modeBits;
            }
        }


        public static bool IsNewSuidOrSgid(fileModel f)
        {
            const int SUID = 0x800; // 04000
            const int SGID = 0x400; // 02000

            if (f == null) return false;

            var key = MakeKey(f);
            if (key == null) return false;

            int newMode = ParseModeBits(f.mode);
            bool newHasPrivBits = (newMode & (SUID | SGID)) != 0;

            if (!fileSys.TryGetValue(key, out int oldMode))
            {
                fileSys[key] = newMode;
                return newHasPrivBits;
            }

            bool oldHasPrivBits = (oldMode & (SUID | SGID)) != 0;

            if (!oldHasPrivBits && newHasPrivBits)
            {
                fileSys[key] = newMode; 
                return true;
            }

            fileSys[key] = newMode;
            return false;
        }

        public static bool HasSuidOrSgidNow(fileModel f)
        {
            const int SUID = 0x800; // 04000
            const int SGID = 0x400; // 02000

            if (f == null) return false;
            int modeBits = ParseModeBits(f.mode);
            return (modeBits & (SUID | SGID)) != 0;
        }



    }
}

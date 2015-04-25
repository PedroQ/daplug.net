using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace daplug.net
{
    public static class DaplugConstants
    {
        public static readonly ushort MasterFileId = 0x3f00;
        public static readonly ushort InternalConfigDirId = 0xc00f;
        public static readonly ushort ApplicationStatesDirId = 0xd00d;
        public static readonly ushort SecretCodesDirId = 0xc0de;
        public static readonly ushort LicensingFileId = 0xa1ba;
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace daplug.net
{
    public class DaplugSessionKeys
    {
        public byte[] SEncKey { get; set; }
        public byte[] REncKey { get; set; }
        public byte[] CMacKey { get; set; }
        public byte[] RMacKey { get; set; }
        public byte[] SKEKey { get; set; }

        public DaplugSecurityLevel SecurityLevel { get; set; }

        public byte[] CMac { get; set; }
        public byte[] RMac { get; set; }

        public DaplugSessionKeys()
        {
            CMac = new byte[8];
            RMac = new byte[8];
        }
    }
}

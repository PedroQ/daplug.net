using daplug.net.Dongle.APDU;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace daplug.net.Dongle
{
    public interface IDaplugDongle : IDisposable
    {
        Task<APDUResponse> ExchangeAPDU(APDUCommand apdu);
        APDUResponse[] ExchangeAPDUs(ICollection<APDUCommand> apduCollection);
    }
}

using daplug.net.Dongle.WinUSB;
using System.Collections.Generic;
using System.Linq;

namespace daplug.net.Dongle
{
    public class DaplugEnumerator
    {
        private DaplugDongleWinUSB winUSBDongle = new DaplugDongleWinUSB();
        private List<string> listDaplugWinusbDevice()
        {

            var dongles = winUSBDongle.GetDaplugDongles();
            return dongles;
        }

        public List<string> ListAllDongles()
        {
            return listDaplugWinusbDevice();
        }

        public IDaplugDongle OpenFirstDongle()
        {
            if (ListAllDongles().Any())
                return winUSBDongle.OpenFirstDongle();
            else
                throw new DaplugAPIException("No Plugup devices were found!");
        }
    }
}

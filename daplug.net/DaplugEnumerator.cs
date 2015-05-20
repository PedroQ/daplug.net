using daplug.net.Dongle;
using daplug.net.Dongle.HID;
using daplug.net.Dongle.WinUSB;
using System;
using System.Collections.Generic;
using System.Linq;

namespace daplug.net
{
    public enum DaplugCommMode
    {
        HID,
        LibUSB
    }

    public static class DaplugEnumerator
    {
        private static List<string> GetHIDDongles()
        {

            var dongles = HidDaplugEnumerator.GetDaplugDongles();
            return dongles;
        }

        private static List<string> GetWinUSBDongles()
        {

            var dongles = WinUSBDaplugEnumerator.GetDaplugDongles();
            return dongles;
        }

        public static List<Tuple<DaplugCommMode, string>> ListAllDongles()
        {
            List<Tuple<DaplugCommMode, string>> result = new List<Tuple<DaplugCommMode, string>>();

            var hidDongles = GetHIDDongles();
            foreach (var d in hidDongles)
            {
                result.Add(new Tuple<DaplugCommMode, string>(DaplugCommMode.HID, d));
            }

            var winUSBDongles = GetWinUSBDongles();
            foreach (var d in winUSBDongles)
            {
                result.Add(new Tuple<DaplugCommMode, string>(DaplugCommMode.LibUSB, d));
            }

            return result;
        }

        public static Daplug OpenFirstDongle()
        {
            IDaplugDongle device;

            if (GetHIDDongles().Any())
                device = HidDaplugEnumerator.OpenFirstDongle();
            else if (GetWinUSBDongles().Any())
                device = WinUSBDaplugEnumerator.OpenFirstDongle();
            else
                throw new DaplugAPIException("No Plugup devices were found!");

            return new Daplug(device);
        }
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using LibUsbDotNet;
using LibUsbDotNet.Main;

namespace daplug.net.Dongle.WinUSB
{
    class DaplugDongleWinUSB
    {
        private readonly int VENDOR_ID = 9601;
        private readonly int PRODUCT_ID = 6152;

        public List<string> GetDaplugDongles()
        {
            List<string> daplugDevices = new List<string>();

            UsbDeviceFinder usbDeviceFinder = new UsbDeviceFinder(VENDOR_ID, PRODUCT_ID);

            var allDevices = UsbDevice.AllDevices.FindAll(usbDeviceFinder);
            UsbDevice usbDevice;
            int i = 0;
            foreach (UsbRegistry r in allDevices)
            {
                if (r.Open(out usbDevice))
                {
                    daplugDevices.Add(string.Format("Dongle {0},WINUSB,{1},Plug-up", i++, usbDevice.UsbRegistryInfo.FullName));
                    usbDevice.Close();
                }
            }
            return daplugDevices;
        }

        internal IDaplugDongle OpenFirstDongle()
        {
            UsbDeviceFinder usbDeviceFinder = new UsbDeviceFinder(VENDOR_ID, PRODUCT_ID);

            var usbDevice = UsbDevice.OpenUsbDevice(usbDeviceFinder);

            return new WinUSBDaplugDongle(usbDevice);
        }
    }
}

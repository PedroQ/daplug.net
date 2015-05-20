using LibUsbDotNet;
using LibUsbDotNet.Main;
using System.Collections.Generic;

namespace daplug.net.Dongle.WinUSB
{
    internal static class WinUSBDaplugEnumerator
    {
        private static readonly int VENDOR_ID = 0x2581;
        private static readonly int PRODUCT_ID = 0x1808;

        internal static List<string> GetDaplugDongles()
        {
            List<string> daplugDevices = new List<string>();

            UsbDeviceFinder usbDeviceFinder = new UsbDeviceFinder(VENDOR_ID, PRODUCT_ID);

            var allDevices = UsbDevice.AllDevices.FindAll(usbDeviceFinder);
            UsbDevice usbDevice;
            foreach (UsbRegistry r in allDevices)
            {
                if (r.Open(out usbDevice))
                {
                    daplugDevices.Add(string.Format("{0} {1} ({2})", usbDevice.Info.ManufacturerString, usbDevice.Info.ProductString, usbDevice.DriverMode));
                    usbDevice.Close();
                }
            }
            return daplugDevices;
        }

        internal static IDaplugDongle OpenFirstDongle()
        {
            UsbDeviceFinder usbDeviceFinder = new UsbDeviceFinder(VENDOR_ID, PRODUCT_ID);

            var usbDevice = UsbDevice.OpenUsbDevice(usbDeviceFinder);

            return new WinUSBDaplugDongle(usbDevice);
        }
    }
}

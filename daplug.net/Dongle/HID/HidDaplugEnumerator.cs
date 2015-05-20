using HidSharp;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace daplug.net.Dongle.HID
{
    internal static class HidDaplugEnumerator
    {
        private static readonly int VENDOR_ID = 0x2581;
        private static readonly int PRODUCT_ID = 0x1807;

        private static readonly HidDeviceLoader hidLoader = new HidDeviceLoader();

        internal static List<string> GetDaplugDongles()
        {
            List<string> daplugDevices = new List<string>();

            var daplugDongles = hidLoader.GetDevices(vendorID: VENDOR_ID, productID: PRODUCT_ID);

            foreach (HidDevice d in daplugDongles)
            {
                //ignore theVirtual Keyboard interface 00
                //we filter it out by checking the Report Length
                //for interface 01 the Input/Output report lenght is 65
                if (d.MaxInputReportLength != 65 || d.MaxOutputReportLength != 65)
                    continue;
                daplugDevices.Add(string.Format("{0} {1} (HID {2})", d.Manufacturer, d.ProductName, d.DevicePath));
            }
            return daplugDevices;
        }

        internal static IDaplugDongle OpenFirstDongle()
        {
            var daplugDongle = hidLoader.GetDeviceOrDefault(vendorID: VENDOR_ID, productID: PRODUCT_ID);
            return new HidDaplugDongle(daplugDongle);

        }
    }
}

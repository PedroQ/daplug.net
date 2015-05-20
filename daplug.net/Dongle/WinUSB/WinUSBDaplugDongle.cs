using daplug.net.Dongle.APDU;
using LibUsbDotNet;
using LibUsbDotNet.Main;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace daplug.net.Dongle.WinUSB
{
    internal class WinUSBDaplugDongle : IDaplugDongle
    {
        private readonly int USB_TIMEOUT = 5000;

        private readonly UsbDevice daplugDevice;
        private UsbEndpointReader daplugReader;
        private UsbEndpointWriter daplugWriter;

        public DaplugCommMode CommunicationMode
        {
            get { return DaplugCommMode.LibUSB; }
        }

        public WinUSBDaplugDongle(UsbDevice usbDevice)
        {
            daplugDevice = usbDevice;

            IUsbDevice device = daplugDevice as IUsbDevice;

            if (!ReferenceEquals(device, null))
            {
                // Select config #1
                device.SetConfiguration(1);

                // Claim interface #0.
                device.ClaimInterface(0);
            }
            byte readEndpointIdByte = 0x00;
            byte writeEndpointIdByte = 0x00;

            foreach (var cfg in daplugDevice.Configs)
            {
                foreach (var iface in cfg.InterfaceInfoList)
                {
                    foreach (var ep in iface.EndpointInfoList)
                    {
                        if ((ep.Descriptor.Attributes & 0x02) == 0x02)
                        {
                            //check if is out endpoint
                            if ((ep.Descriptor.EndpointID & 0x80) == 0x00)
                            {
                                writeEndpointIdByte = ep.Descriptor.EndpointID;
                                continue;
                            }

                            if ((ep.Descriptor.EndpointID & 0x80) == 0x80)
                            {
                                readEndpointIdByte = ep.Descriptor.EndpointID;
                                continue;
                            }
                        }
                    }
                    if (readEndpointIdByte != 0x00 && writeEndpointIdByte != 0x00)
                        break;
                }
                if (readEndpointIdByte != 0x00 && writeEndpointIdByte != 0x00)
                    break;
            }

            if (readEndpointIdByte == 0x00 || writeEndpointIdByte == 0x00)
                throw new DaplugCommunicationException("Error while opening the USB device");

            daplugReader = daplugDevice.OpenEndpointReader((ReadEndpointID)readEndpointIdByte);
            daplugWriter = daplugDevice.OpenEndpointWriter((WriteEndpointID)writeEndpointIdByte);
        }

        public Task<APDUResponse> ExchangeAPDU(APDUCommand apdu)
        {
            int bytesWritten;
            var errorCode = daplugWriter.Write(apdu.ToByteArray(), USB_TIMEOUT, out bytesWritten);
            if (errorCode != ErrorCode.None)
                throw new DaplugCommunicationException("Error while sendind command: " + errorCode + ". " + UsbDevice.LastErrorString);

            int bytesRead;
            byte[] readBuffer = new byte[ushort.MaxValue];
            var receiveError = daplugReader.Read(readBuffer, USB_TIMEOUT, out bytesRead);
            if (receiveError != ErrorCode.None)
                throw new DaplugCommunicationException("Error while receiving response: " + receiveError + ". " + UsbDevice.LastErrorString);

            Array.Resize(ref readBuffer, bytesRead);

            APDUResponse response;

            //if response starts with 0x61, the next byte is the response length
            if (readBuffer[0] == 0x61)
            {
                byte[] responseData = new byte[readBuffer[1] + 2]; //we add 2 to the response length to account for the SW bytes
                Array.Copy(readBuffer, 2, responseData, 0, responseData.Length);
                response = new APDUResponse(responseData);
            }
            //else the response constains only the 2 SW bytes
            else
            {
                response = new APDUResponse(readBuffer);
            }
            return Task.FromResult(response);

        }

        public APDUResponse[] ExchangeAPDUs(ICollection<APDUCommand> apduCollection)
        {
            throw new NotImplementedException();
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                daplugDevice.Close();
                UsbDevice.Exit();
            }
        }
    }
}

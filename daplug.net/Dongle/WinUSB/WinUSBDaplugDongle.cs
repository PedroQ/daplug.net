using daplug.net.Dongle.APDU;
using LibUsbDotNet;
using LibUsbDotNet.Main;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace daplug.net.Dongle.WinUSB
{
    public class WinUSBDaplugDongle : IDaplugDongle
    {
        private readonly UsbDevice daplugDevice;
        private UsbEndpointReader daplugReader;
        private UsbEndpointWriter daplugWriter;

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

            daplugReader = daplugDevice.OpenEndpointReader(ReadEndpointID.Ep02);
            daplugWriter = daplugDevice.OpenEndpointWriter(WriteEndpointID.Ep02);
        }

        public Task<APDUResponse> ExchangeAPDU(APDUCommand apdu)
        {
            int bytesWritten;
            var errorCode = daplugWriter.Write(apdu.ToByteArray(), 5000, out bytesWritten);
            if (errorCode != ErrorCode.None)
                throw new DaplugCommunicationException("Error while sendind command: " + errorCode + ". " + UsbDevice.LastErrorString);

            int bytesRead;
            byte[] readBuffer = new byte[64];
            var receiveError = daplugReader.Read(readBuffer, 1000, out bytesRead);
            if (receiveError != ErrorCode.None)
                throw new DaplugCommunicationException("Error while receiving response: " + receiveError + ". " + UsbDevice.LastErrorString);

            Array.Resize(ref readBuffer, bytesRead);

            APDUResponse response;

            //if response starts with 0x61, the next byte is the response lenght
            if (readBuffer[0] == 0x61)
            {
                byte[] responseData = new byte[readBuffer[1] + 2]; //we add 2 to the response lenght to account for the SW bytes
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

        public virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                daplugDevice.Close();
                UsbDevice.Exit();
            }
        }
    }
}

using daplug.net.Dongle.APDU;
using HidSharp;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace daplug.net.Dongle.HID
{
    internal class HidDaplugDongle : IDaplugDongle
    {
        private static readonly int HID_CHUNK_SIZE = 65;
        private static readonly int HID_DATA_SIZE = 64;

        private readonly HidDevice daplugDongle;
        private HidStream dongleStream;

        public DaplugCommMode CommunicationMode
        {
            get { return DaplugCommMode.HID; }
        }

        public HidDaplugDongle(HidDevice dongle)
        {
            daplugDongle = dongle;
            bool success = daplugDongle.TryOpen(out dongleStream);
            if (success == false)
                throw new DaplugCommunicationException("Unable to open a channel to the HID dongle.");
            dongleStream.ReadTimeout = System.Threading.Timeout.Infinite;
            dongleStream.WriteTimeout = System.Threading.Timeout.Infinite;
        }

        private Task WriteData(byte[] data, int offset, int length)
        {
            var writeTask = Task.Factory.FromAsync(dongleStream.BeginWrite, dongleStream.EndWrite, data, offset, length, null);
            return writeTask;
        }

        private Task<int> ReadData(byte[] data, int offset, int length)
        {
            var readTask = Task<int>.Factory.FromAsync(dongleStream.BeginRead, dongleStream.EndRead, data, offset, length, null);
            return readTask;
        }

        public async Task<APDUResponse> ExchangeAPDU(APDUCommand apdu)
        {
            byte[] writeBuffer = new byte[HID_CHUNK_SIZE];
            byte[] readBuffer = new byte[HID_CHUNK_SIZE];

            byte[] apduBytes = apdu.ToByteArray();

            int remainingBytes = apduBytes.Length;
            int chunkLenght = 0;
            int apduOffset = 0;

            while (remainingBytes > 0)
            {
                chunkLenght = Math.Min(remainingBytes, HID_DATA_SIZE);

                //Copies the current chunk to the command byte array.
                //the untouched bytes will still be 00, adding the padding to the last chunk
                //first byte is always 00, the fake report number.
                Array.Copy(apduBytes, apduOffset, writeBuffer, 1, chunkLenght);

                await WriteData(writeBuffer, 0, HID_CHUNK_SIZE);

                //clear the buffer array
                Array.Clear(writeBuffer, 0, HID_CHUNK_SIZE);

                remainingBytes -= chunkLenght;
                apduOffset += chunkLenght;
            }

            int bytesRead = await ReadData(readBuffer, 0, HID_CHUNK_SIZE);

            if (bytesRead < 0)
                throw new DaplugCommunicationException("Error while receiving response.");

            byte[] responseData;

            //first byte of the response is 00, the report number
            //if response starts with 0x61, the next byte is the response length
            if (readBuffer[1] == 0x61)
            {
                int byteToRead = readBuffer[2] + 2;
                int responseChunkLenght = Math.Min(byteToRead, HID_DATA_SIZE - 2);
                int responseOffset = 0;
                responseData = new byte[byteToRead];

                //copy the first chunk to the response data
                Array.Copy(readBuffer, 3, responseData, 0, responseChunkLenght);
                byteToRead -= responseChunkLenght;
                responseOffset += responseChunkLenght;

                //if there is any more data to read, do it
                while (byteToRead > 0)
                {
                    await ReadData(readBuffer, 0, HID_CHUNK_SIZE);

                    responseChunkLenght = Math.Min(byteToRead, HID_DATA_SIZE);

                    Array.Copy(readBuffer, 1, responseData, responseOffset, responseChunkLenght);

                    byteToRead -= responseChunkLenght;
                    responseOffset += responseChunkLenght;
                }
            }
            //else the response constains only the 2 SW bytes
            else
            {
                responseData = new byte[2];
                Array.Copy(readBuffer, 1, responseData, 0, 2);
            }

            return new APDUResponse(responseData);
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
                if (dongleStream != null)
                    dongleStream.Close();
            }
        }
    }
}

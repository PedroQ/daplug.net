using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace daplug.net.Dongle.APDU
{
    public class APDUResponse
    {
        public byte[] ResponseData { get; set; }
        public byte SW1 { get; private set; }
        public byte SW2 { get; private set; }
        public bool IsSuccessfulResponse
        {
            get
            {
                return SW1 == 0x90 && SW2 == 0x00;
            }
        }

        public bool HasData
        {
            get
            {
                return ResponseData != null && ResponseData.Length > 0;
            }
        }

        public APDUResponse(byte[] responseBytes)
        {
            if (responseBytes.Length < 2) throw new ArgumentException("APDU response must me at least 2 bytes long.", "responseBytes");

            if (responseBytes.Length > 2)
            {
                ResponseData = new byte[responseBytes.Length - 2]; //the last 2 bytes are the SW bytes
                Array.Copy(responseBytes, 0, ResponseData, 0, responseBytes.Length - 2);
            }
            SW1 = responseBytes[responseBytes.Length - 2];
            SW2 = responseBytes[responseBytes.Length - 1];
        }


        internal byte[] ToByteArray()
        {
            MemoryStream responseMemoryStream = new MemoryStream();
            if (ResponseData != null)
                responseMemoryStream.Write(ResponseData, 0, ResponseData.Length);
            responseMemoryStream.WriteByte(SW1);
            responseMemoryStream.WriteByte(SW2);
            return responseMemoryStream.ToArray();
        }
    }
}

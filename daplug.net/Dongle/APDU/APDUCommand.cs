using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace daplug.net.Dongle.APDU
{
    public class APDUCommand
    {
        public byte InstructionClass { get; set; }
        public byte InstructionCode { get; set; }
        public byte Parameter1 { get; set; }
        public byte Parameter2 { get; set; }
        public byte[] CommandData { get; set; }
        public byte ResponseLenght { get; set; }


        public APDUCommand(string apdu)
            : this(Utils.Helpers.StringToByteArray(apdu))
        {

        }

        public APDUCommand(byte[] commandbytes, byte[] data)
            : this(commandbytes.Concat(data).ToArray())
        {

        }

        public APDUCommand(byte[] commandBytes)
        {
            int apduLenght = commandBytes.Length;
            int dataLenght = apduLenght - 5;

            InstructionClass = commandBytes[0];
            InstructionCode = commandBytes[1];
            Parameter1 = commandBytes[2];
            Parameter2 = commandBytes[3];
            CommandData = new byte[dataLenght];

            if (apduLenght == 5)
            {
                ResponseLenght = commandBytes[4];
            }
            else
            {
                Array.Copy(commandBytes, 5, CommandData, 0, dataLenght);
            }
        }

        public byte[] ToByteArray()
        {
            MemoryStream ms = new MemoryStream();
            ms.WriteByte(InstructionClass);
            ms.WriteByte(InstructionCode);
            ms.WriteByte(Parameter1);
            ms.WriteByte(Parameter2);

            if (CommandData != null && CommandData.Length > 0)
            {
                if (CommandData.Length > 255)
                    throw new ArgumentOutOfRangeException("Data", "Data lenght limit exceeded.");

                ms.WriteByte((byte)CommandData.Length);
                ms.Write(CommandData, 0, CommandData.Length);
            }
            else
            {
                ms.WriteByte(ResponseLenght);
            }

            return ms.ToArray();
        }
    }
}

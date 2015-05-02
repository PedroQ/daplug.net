using System;

namespace daplug.net.Utils
{
    internal class Helpers
    {
        internal static byte[] StringToByteArray(String hex)
        {
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }

        internal static byte[] UShortToByteArray(ushort input)
        {
            var result = BitConverter.GetBytes(input);
            // If this is little endian machine, reverse the array
            // so that the bytes are in the correct order
            if (BitConverter.IsLittleEndian)
                Array.Reverse(result);

            return result;
        }

        internal static byte[] IntToByteArray(int input)
        {
            var result = BitConverter.GetBytes(input);
            // If this is little endian machine, reverse the array
            // so that the bytes are in the correct order
            if (BitConverter.IsLittleEndian)
                Array.Reverse(result);

            return result;
        }
    }
}

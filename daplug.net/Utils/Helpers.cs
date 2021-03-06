﻿using System;

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

        internal static byte[] UIntToByteArray(uint input)
        {
            var result = BitConverter.GetBytes(input);
            // If this is little endian machine, reverse the array
            // so that the bytes are in the correct order
            if (BitConverter.IsLittleEndian)
                Array.Reverse(result);

            return result;
        }

        internal static uint ByteArrayToUInt(byte[] input)
        {
            if (BitConverter.IsLittleEndian)
                Array.Reverse(input);

            return  BitConverter.ToUInt32(input, 0);
        }

        internal static DateTime UnixTimeToLocalDateTime(uint input)
        {
            DateTime epoch = new DateTime(1970, 1, 1, 0, 0, 0, 0, System.DateTimeKind.Utc);
            return  epoch.AddSeconds(input).ToLocalTime();
        }

        internal static uint GetUnixTime()
        {
            return (uint)(DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds;
        }
    }
}

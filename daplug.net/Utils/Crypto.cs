using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace daplug.net.Utils
{
    internal class Crypto
    {

        private static readonly byte[] defaultIV = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

        private static byte[] GPKeyTo3DESKey(byte[] GPKey)
        {

            byte[] tmp = new byte[8];

            Array.Copy(GPKey, 0, tmp, 0, 8);

            byte[] _3DESKey = GPKey.Concat(tmp).ToArray();

            return _3DESKey;
        }

        internal static byte[] TripleDESEncrypt(byte[] key, byte[] data, byte[] iv = null)
        {
            MemoryStream cryptoStreamOutput = new MemoryStream();

            TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider();
            tdes.Padding = PaddingMode.None;
            tdes.Mode = CipherMode.CBC;

            using (CryptoStream encStream = new CryptoStream(cryptoStreamOutput, tdes.CreateEncryptor(GPKeyTo3DESKey(key), iv ?? defaultIV), CryptoStreamMode.Write))
            {
                encStream.Write(data, 0, data.Length);
            }

            return cryptoStreamOutput.ToArray();
        }

        internal static byte[] TripleDESDecrypt(byte[] key, byte[] data, byte[] iv = null)
        {
            MemoryStream cryptoStreamOutput = new MemoryStream();

            TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider();
            tdes.Padding = PaddingMode.None;
            tdes.Mode = CipherMode.CBC;

            using (CryptoStream encStream = new CryptoStream(cryptoStreamOutput, tdes.CreateDecryptor(GPKeyTo3DESKey(key), iv ?? defaultIV), CryptoStreamMode.Write))
            {
                encStream.Write(data, 0, data.Length);
            }

            return cryptoStreamOutput.ToArray();
        }


        internal static byte[] TripleDESEncryptECB(byte[] key, byte[] data)
        {
            MemoryStream cryptoStreamOutput = new MemoryStream();

            TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider();
            tdes.Key = GPKeyTo3DESKey(key);
            tdes.IV = new byte[8];
            tdes.Padding = PaddingMode.None;
            tdes.Mode = CipherMode.ECB;

            using (CryptoStream encStream = new CryptoStream(cryptoStreamOutput, tdes.CreateEncryptor(), CryptoStreamMode.Write))
            {
                encStream.Write(data, 0, data.Length);
            }

            return cryptoStreamOutput.ToArray();
        }

        internal static byte[] DESEncrypt(byte[] key, byte[] data, byte[] iv = null)
        {
            MemoryStream cryptoStreamOutput = new MemoryStream();

            DESCryptoServiceProvider tdes = new DESCryptoServiceProvider();
            tdes.Mode = CipherMode.CBC;
            tdes.Padding = PaddingMode.None;
            tdes.Key = key;
            using (CryptoStream encStream = new CryptoStream(cryptoStreamOutput, tdes.CreateEncryptor(key, iv ?? defaultIV), CryptoStreamMode.Write))
            {
                encStream.Write(data, 0, data.Length);
            }

            return cryptoStreamOutput.ToArray();
        }

        internal static byte[] CalculateKCV(byte[] key)
        {
            MemoryStream cryptoStreamOutput = new MemoryStream();

            TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider();
            tdes.Key = GPKeyTo3DESKey(key);
            tdes.IV = new byte[8];
            tdes.Padding = PaddingMode.None;
            tdes.Mode = CipherMode.ECB;

            using (CryptoStream encStream = new CryptoStream(cryptoStreamOutput, tdes.CreateEncryptor(), CryptoStreamMode.Write))
            {
                encStream.Write(defaultIV, 0, defaultIV.Length); //defaultIV is an 8 byte array
            }

            byte[] kcvBuffer = cryptoStreamOutput.ToArray();

            //get the first 3 bytes of the 3DES result
            byte[] finalKCV = new byte[3];
            Array.Copy(kcvBuffer, finalKCV, 3);
            return finalKCV;
        }
    }
}

using daplug.net.Dongle.APDU;
using daplug.net.Utils;
using System;
using System.Linq;

namespace daplug.net
{
    internal class DaplugCrypto
    {
        private static readonly byte[] padding = { 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

        public static DaplugSessionKeys ComputeSessionKeys(DaplugKeySet keyset, byte[] seqCounter)
        {
            byte[] dataToEncrypt = new byte[16];
            Array.Copy(seqCounter, 0, dataToEncrypt, 2, 2);

            byte[] SEncBytes = new byte[2] { 0x01, 0x82 };
            byte[] REncBytes = new byte[2] { 0x01, 0x83 };
            byte[] CMacEncBytes = new byte[2] { 0x01, 0x01 };
            byte[] RMacEncBytes = new byte[2] { 0x01, 0x02 };
            byte[] SKekEncBytes = new byte[2] { 0x01, 0x81 };

            DaplugSessionKeys sessionKeys = new DaplugSessionKeys();

            Array.Copy(SEncBytes, 0, dataToEncrypt, 0, 2);
            sessionKeys.SEncKey = Crypto.TripleDESEncrypt(keyset.EncKey, dataToEncrypt);

            Array.Copy(REncBytes, 0, dataToEncrypt, 0, 2);
            sessionKeys.REncKey = Crypto.TripleDESEncrypt(keyset.EncKey, dataToEncrypt);

            Array.Copy(CMacEncBytes, 0, dataToEncrypt, 0, 2);
            sessionKeys.CMacKey = Crypto.TripleDESEncrypt(keyset.MacKey, dataToEncrypt);

            Array.Copy(RMacEncBytes, 0, dataToEncrypt, 0, 2);
            sessionKeys.RMacKey = Crypto.TripleDESEncrypt(keyset.MacKey, dataToEncrypt);

            Array.Copy(SKekEncBytes, 0, dataToEncrypt, 0, 2);
            sessionKeys.SKEKey = Crypto.TripleDESEncrypt(keyset.DeKey, dataToEncrypt);

            return sessionKeys;
        }

        public static byte[] CalculateCryptogram(DaplugSessionKeys keyset, byte[] hostChallenge, byte[] cardChallenge)
        {
            byte[] challengesAndPadding = hostChallenge.Concat(cardChallenge).Concat(padding).ToArray();

            byte[] buffer = Crypto.TripleDESEncrypt(keyset.SEncKey, challengesAndPadding);
            byte[] cryptogram = new byte[8];
            System.Array.Copy(buffer, 16, cryptogram, 0, 8);
            return cryptogram;
        }

        public static byte[] CalculateApduMac(byte[] key, byte[] apduBytes, byte[] iv, bool rMac = false)
        {
            if (!rMac)
            {
                if (iv.All(b => b == 0x00) == false)
                {
                    apduBytes = iv.Concat(apduBytes).ToArray();
                }
            }

            apduBytes = AddPadding(apduBytes);

            byte[] firstBlocks = new byte[apduBytes.Length - 8];
            byte[] lastBlock = new byte[8];
            Array.Copy(apduBytes, 0, firstBlocks, 0, apduBytes.Length - 8);
            Array.Copy(apduBytes, apduBytes.Length - 8, lastBlock, 0, 8);

            byte[] DESCMacKey = new byte[8];
            Array.Copy(key, 0, DESCMacKey, 0, 8);

            byte[] desIV = rMac ? iv : null;

            byte[] buffer = Crypto.DESEncrypt(DESCMacKey, firstBlocks, desIV);

            byte[] triplesDESInput = new byte[8];
            for (int i = 0; i < 8; i++)
            {
                triplesDESInput[i] = (byte)(apduBytes[apduBytes.Length - 8 + i] ^ buffer[buffer.Length - 8 + i]);
            }
            buffer = Crypto.TripleDESEncryptECB(key, triplesDESInput);

            return buffer;

        }

        public static byte[] EncryptAPDUData(DaplugSessionKeys keyset, APDUCommand apdu)
        {
            byte[] paddedData = AddPadding(apdu.CommandData);

            byte[] encryptedData = Crypto.TripleDESEncrypt(keyset.SEncKey, paddedData);

            return encryptedData;
        }
        internal static byte[] DecryptAPDUResponse(DaplugSessionKeys keyset, byte[] responseBytes)
        {
            byte[] decryptedResponse = Crypto.TripleDESDecrypt(keyset.REncKey, responseBytes);

            return RemovePadding(decryptedResponse);
        }

        private static byte[] AddPadding(byte[] data)
        {
            byte[] padding = new byte[8 - (data.Length % 8)];
            padding[0] = 0x80;
            return data.Concat(padding).ToArray();
        }

        private static byte[] RemovePadding(byte[] data)
        {
            byte[] unpaddedData;
            for (int i = data.Length - 1; i >= 0; i--)
            {
                if (data[i] == 0x80)
                {
                    unpaddedData = new byte[i];
                    Array.Copy(data, 0, unpaddedData, 0, i);
                    return unpaddedData;
                }
            }
            return data;

        }

    }
}

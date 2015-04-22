using daplug.net.Dongle.APDU;
using daplug.net.Utils;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

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

        public static byte[] CalculateApduMac(DaplugSessionKeys sessionKeyset, APDUCommand apdu)
        {
            byte[] apduBytes = apdu.ToByteArray();

            apduBytes[4] += 0x08;

            byte[] workData = AddPadding(apduBytes);

            if (sessionKeyset.CMac.All(b => b == 0x00) == false)
            {
                workData = sessionKeyset.CMac.Concat(workData).ToArray();
            }

            byte[] firstBlocks = new byte[workData.Length - 8];
            byte[] lastBlock = new byte[8];
            Array.Copy(workData, 0, firstBlocks, 0, workData.Length - 8);
            Array.Copy(workData, workData.Length - 8, lastBlock, 0, 8);

            byte[] DESCMacKey = new byte[8];
            Array.Copy(sessionKeyset.CMacKey, 0, DESCMacKey, 0, 8);


            byte[] buffer = Crypto.DESEncrypt(DESCMacKey, firstBlocks);

            buffer = Crypto.TripleDESEncrypt(sessionKeyset.CMacKey, buffer, lastBlock);

            return buffer;

        }

        public static byte[] EncryptAPDUData(DaplugSessionKeys keyset, APDUCommand apdu)
        {
            byte[] paddedData = AddPadding(apdu.CommandData);

            byte[] encryptedData = Crypto.TripleDESEncrypt(keyset.SEncKey, paddedData);

            return encryptedData;
        }

        private static byte[] AddPadding(byte[] data)
        {
            byte[] padding = new byte[8 - (data.Length % 8)];
            padding[0] = 0x80;
            return data.Concat(padding).ToArray();
        }
    }
}

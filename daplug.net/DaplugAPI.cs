using daplug.net.Dongle;
using daplug.net.Dongle.APDU;
using daplug.net.Utils;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace daplug.net
{

    [Flags]
    public enum DaplugLicensing
    {
        FILE = 0x01,
        KEYBOARD = 0x02,
        URL = 0x04,
        CRYPTO = 0x08,
        SAMCOMMUNITY = 0x10,
        SAM = 0x20
    }

    [Flags]
    public enum DaplugSecurityLevel
    {
        COMMAND_MAC = 0x01,
        COMMAND_ENC = 0x02,
        RESPONSE_MAC = 0x10,
        RESPONSE_DEC = 0x20
    }

    public enum DaplugStatus
    {
        Selectable = 0x07,
        Personalized = 0x0F,
        Terminated = 0x7f,
        Locked = 0x83
    }

    public class DaplugAPI : IDisposable
    {

        private readonly IDaplugDongle dongle;

        public DaplugSessionKeys SessionKeys { get; private set; }

        private DaplugAPI(IDaplugDongle device)
        {
            dongle = device;
        }

        public static DaplugAPI OpenFirstDongle()
        {
            var firstDevice = new daplug.net.Dongle.DaplugEnumerator().OpenFirstDongle();

            if (firstDevice != null)
                return new DaplugAPI(firstDevice);

            return null;

        }

        public async Task<APDUResponse> ExchangeAPDUAsync(APDUCommand apdu)
        {
            var finalAPDU = new APDUCommand(apdu.ToByteArray());

            if (SessionKeys != null)
            {
                byte[] apduMac = null;

                if (SessionKeys.SecurityLevel.HasFlag(DaplugSecurityLevel.COMMAND_MAC))
                {
                    finalAPDU.InstructionClass |= 0x04;
                    var apduBytes = finalAPDU.ToByteArray();
                    apduBytes[4] += 0x08;
                    apduMac = DaplugCrypto.CalculateApduMac(SessionKeys.CMacKey, apduBytes, SessionKeys.CMac);
                    Array.Copy(apduMac, 0, SessionKeys.CMac, 0, 8);
                }
                if ((apdu.InstructionClass == 0x80 && apdu.InstructionCode == 0x82) == false) // Do not encrypt EXTERNAL_AUTHENTICATE APDU
                {
                    if (SessionKeys.SecurityLevel.HasFlag(DaplugSecurityLevel.COMMAND_ENC))
                    {
                        finalAPDU.CommandData = DaplugCrypto.EncryptAPDUData(SessionKeys, apdu);
                    }
                }
                if (apduMac != null)
                {
                    finalAPDU.CommandData = finalAPDU.CommandData.Concat(apduMac).ToArray();
                }

            }

            Debug.WriteLine("=> " + BitConverter.ToString(finalAPDU.ToByteArray()));

            var response = await dongle.ExchangeAPDU(finalAPDU);


            if (SessionKeys != null && response.HasData)
            {
                byte[] responseMac = null;
                if (SessionKeys.SecurityLevel.HasFlag(DaplugSecurityLevel.RESPONSE_MAC))
                {
                    // extract MAC from the response (the last 8 bytes)
                    responseMac = new byte[8];
                    Array.Copy(response.ResponseData, response.ResponseData.Length - 8, responseMac, 0, 8);

                    //resize the response data to exclude the last 8 bytes (MAC)
                    var tmpData = response.ResponseData;
                    Array.Resize(ref tmpData, response.ResponseData.Length - 8);
                    response.ResponseData = tmpData;
                }

                if (SessionKeys.SecurityLevel.HasFlag(DaplugSecurityLevel.RESPONSE_DEC))
                {
                    response.ResponseData = DaplugCrypto.DecryptAPDUResponse(SessionKeys, response.ResponseData);
                }

                if (SessionKeys.SecurityLevel.HasFlag(DaplugSecurityLevel.RESPONSE_MAC))
                {
                    //construct MAC input
                    var apduCommandBytes = apdu.ToByteArray();
                    //command bytes + data lenght + data + sw1 & sw2
                    //var macInput = new byte[apduCommandBytes.Length + 1 + response.ResponseData.Length + 2];
                    byte[] macInput = apduCommandBytes.Concat(new byte[] { (byte)response.ResponseData.Length })
                        .Concat(response.ResponseData).Concat(new byte[] { response.SW1, response.SW2 }).ToArray();

                    byte[] calculatedResponseMac = DaplugCrypto.CalculateApduMac(SessionKeys.RMacKey, macInput, SessionKeys.RMac, true);

                    if (calculatedResponseMac.SequenceEqual(responseMac) == false)
                        throw new DaplugAPIException("Secure Channel error: Invalid RMAC.");

                    Array.Copy(calculatedResponseMac, SessionKeys.RMac, 8);

                }
            }

            Debug.WriteLine("<= " + BitConverter.ToString(response.ToByteArray()));

            return response;
        }

        public async Task OpenSecureChannelAsync(DaplugKeySet keyset, DaplugSecurityLevel securityLevel, byte[] diversifier = null, byte[] hostChallenge = null)
        {
            if (keyset.EncKey == null || keyset.MacKey == null || keyset.DeKey == null)
                throw new DaplugAPIException("Invalid keyset.");

            if (hostChallenge == null)
            {
                Random rnd = new Random();
                hostChallenge = new byte[8];
                rnd.NextBytes(hostChallenge);
            }

            var authCommandHeader = new byte[] { 0x80, 0x50, keyset.Version, 0x00, 0x00 };
            var authCommand = new APDUCommand(authCommandHeader, hostChallenge);

            var response = await ExchangeAPDUAsync(authCommand);

            if (response.IsSuccessfulResponse == false)
                throw new DaplugAPIException("INITIALIZE UPDATE failed.", response.SW1, response.SW2);

            byte[] counter = new byte[2];
            byte[] cardChallenge = new byte[8];
            byte[] cardCryptogram = new byte[8];
            Array.Copy(response.ResponseData, 12, counter, 0, 2);
            Array.Copy(response.ResponseData, 12, cardChallenge, 0, 8);
            Array.Copy(response.ResponseData, 20, cardCryptogram, 0, 8);

            var tempSessionKeys = DaplugCrypto.ComputeSessionKeys(keyset, counter);

            var computedCardCryptogram = DaplugCrypto.CalculateCryptogram(tempSessionKeys, hostChallenge, cardChallenge);

            if (computedCardCryptogram.SequenceEqual(cardCryptogram) == false)
                throw new DaplugAPIException("Invalid card cryptogram.");

            var hostCryptogram = DaplugCrypto.CalculateCryptogram(tempSessionKeys, cardChallenge, hostChallenge);

            if (securityLevel.HasFlag(DaplugSecurityLevel.COMMAND_MAC) == false)
                securityLevel |= DaplugSecurityLevel.COMMAND_MAC;

            tempSessionKeys.SecurityLevel = securityLevel;

            SessionKeys = tempSessionKeys;

            var extAuthCommandHeader = new byte[] { 0x80, 0x82, (byte)SessionKeys.SecurityLevel, 0x00, 0x00 };
            var extAuthCommand = new APDUCommand(extAuthCommandHeader, hostCryptogram);

            var extAuthResponse = await ExchangeAPDUAsync(extAuthCommand);

            if (extAuthResponse.IsSuccessfulResponse == false)
            {
                SessionKeys = null;
                throw new DaplugAPIException("EXTERNAL AUTHENTICATE failed.", response.SW1, response.SW2);
            }

            Array.Copy(SessionKeys.CMac, SessionKeys.RMac, 8);
        }

        public void CloseSecureChannel()
        {
            if (SessionKeys != null)
            {
                SessionKeys = null;
            }
        }

        public async Task<byte[]> GetSerialAsync()
        {
            var getSerialCommand = new byte[] { 0x80, 0xE6, 0x00, 0x00, 0x00 };

            var command = new APDUCommand(getSerialCommand);

            var response = await ExchangeAPDUAsync(command);

            if (!response.IsSuccessfulResponse)
                throw new DaplugAPIException("Error: " + response.SW1 + response.SW2);

            return response.ResponseData;
        }

        public async Task<DaplugStatus> GetStatusAsync()
        {
            var getStatusCommand = new byte[] { 0x80, 0xF2, 0x40, 0x00, 0x00 };

            var command = new APDUCommand(getStatusCommand);

            var response = await ExchangeAPDUAsync(command);

            if (!response.IsSuccessfulResponse)
                throw new DaplugAPIException("Error: " + response.SW1 + response.SW2);

            return (DaplugStatus)response.ResponseData[9];
        }

        public async Task<byte[]> SelectFileAsync(ushort fileID)
        {

            var fileIDBytes = Helpers.UShortToByteArray(fileID);

            var selectFileCommand = new byte[] { 0x80, 0xA4, 0x00, 0x00, 0x00 };

            var command = new APDUCommand(selectFileCommand, fileIDBytes);

            var response = await ExchangeAPDUAsync(command);

            if (!response.IsSuccessfulResponse)
                throw new DaplugAPIException("Error: " + response.SW1 + response.SW2);

            return response.ResponseData;
        }

        public async Task SelectPathAsync(params ushort[] path)
        {
            foreach (ushort p in path)
            {
                await SelectFileAsync(p);
            }
        }

        public async Task DeleteFileOrDirAsync(ushort fileID)
        {
            var fileIDBytes = Helpers.UShortToByteArray(fileID);

            var deleteFileCommandBytes = new byte[] { 0x80, 0xE4, 0x00, 0x00, 0x02 };

            var command = new APDUCommand(deleteFileCommandBytes, fileIDBytes);

            var response = await ExchangeAPDUAsync(command);

            if (!response.IsSuccessfulResponse)
                throw new DaplugAPIException("Error: " + response.SW1 + response.SW2);
        }

        public async Task<byte[]> ReadFileAsync(ushort offset, byte length)
        {

            var offsetBytes = Helpers.UShortToByteArray(offset);

            var readFileCommand = new byte[] { 0x80, 0xB0, offsetBytes[0], offsetBytes[1], (SessionKeys != null) ? (byte)0x00 : length };

            var command = new APDUCommand(readFileCommand);

            var response = await ExchangeAPDUAsync(command);

            if (!response.IsSuccessfulResponse)
                throw new DaplugAPIException("Error: " + response.SW1 + response.SW2);

            return response.ResponseData;
        }



        private List<byte> PrepareKeyToPutKeyCommand(byte[] key, byte keyUsage, ushort keyAccess)
        {

            var result = new List<byte> { 0xff, 0x80, 0x10 }; // key type (FF80) + Key Length (0x10)
            //encrypt the key
            var encryptedKey = Crypto.TripleDESEncryptECB(SessionKeys.SKEKey, key);
            result.AddRange(encryptedKey);

            //Key Check Value
            result.Add(0x03); //KCV Lenght
            var keyCheckValue = Crypto.CalculateKCV(key);
            result.AddRange(keyCheckValue);

            //key usage
            result.Add(0x01); //key usage lenght
            result.Add(keyUsage);

            //key access
            result.Add(0x02); //key access lenght
            result.AddRange(Helpers.UShortToByteArray(keyAccess));

            return result;

        }

        public async Task PutKeyAsync(DaplugKeySet key, byte mode = 0x81)
        {

            var putKeyCommandAPDUBytes = new List<byte> { 0x80, 0xD8, key.Version, mode, 0x00 }; //header

            // Key version
            putKeyCommandAPDUBytes.Add(key.Version);


            //Add the keys to the command data
            var encKeyData = PrepareKeyToPutKeyCommand(key.EncKey, (byte)key.Usage, key.Access);
            putKeyCommandAPDUBytes.AddRange(encKeyData);

            var macKeyData = PrepareKeyToPutKeyCommand(key.MacKey, (byte)key.Usage, key.Access);
            putKeyCommandAPDUBytes.AddRange(macKeyData);

            var keKeyData = PrepareKeyToPutKeyCommand(key.DeKey, (byte)key.Usage, key.Access);
            putKeyCommandAPDUBytes.AddRange(keKeyData);

            var putKeyCommand = new APDUCommand(putKeyCommandAPDUBytes.ToArray());

            var response = await ExchangeAPDUAsync(putKeyCommand);

            if (!response.IsSuccessfulResponse)
                throw new DaplugAPIException("Error: " + response.SW1 + response.SW2);
        }

        public async Task DeleteKeyAsync(byte keyVersion)
        {
            //navigate to the keys dir
            await SelectPathAsync(DaplugConstants.MasterFileId, DaplugConstants.InternalConfigDirId, DaplugConstants.SecretCodesDirId, 0x0001);

            ushort keyFileID = (ushort)(0x1000 + keyVersion);
            await DeleteFileOrDirAsync(keyFileID);
        }

        public async Task<bool> UsbToHidAsync()
        {
            var usbToHidCommand = new byte[] { 0xD0, 0x52, 0x08, 0x01, 0x00 };

            var command = new APDUCommand(usbToHidCommand);

            var response = await ExchangeAPDUAsync(command);

            return response.IsSuccessfulResponse;
        }

        public async Task<bool> HidToUsbAsync()
        {
            var HidToUsbCommand = new byte[] { 0xD0, 0x52, 0x08, 0x02, 0x00 };

            var command = new APDUCommand(HidToUsbCommand);

            var response = await ExchangeAPDUAsync(command);

            return response.IsSuccessfulResponse;
        }

        public async Task<bool> ResetAsync()
        {
            var resetCommand = new byte[] { 0xD0, 0x52, 0x01, 0x00, 0x00 };

            var command = new APDUCommand(resetCommand);

            var response = await ExchangeAPDUAsync(command);

            return response.IsSuccessfulResponse;
        }

        public async Task<bool> HaltAsync()
        {
            var haltCommand = new byte[] { 0xD0, 0x52, 0x02, 0x00, 0x00 };

            var command = new APDUCommand(haltCommand);

            var response = await ExchangeAPDUAsync(command);

            return response.IsSuccessfulResponse;
        }

        public async Task<DaplugLicensing> GetLicensedOptionsAsync()
        {
            await SelectPathAsync(DaplugConstants.MasterFileId, DaplugConstants.InternalConfigDirId, DaplugConstants.ApplicationStatesDirId, DaplugConstants.LicensingFileId);
            var licFileContents = await ReadFileAsync(0, 2);
            return (DaplugLicensing)licFileContents[0];
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
                dongle.Dispose();
            }
        }
    }
}

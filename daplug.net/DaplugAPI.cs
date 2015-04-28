using daplug.net.Dongle;
using daplug.net.Dongle.APDU;
using daplug.net.Utils;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;

namespace daplug.net
{

    [Flags]
    public enum DaplugLicensing : byte
    {
        FILE = 0x01,
        KEYBOARD = 0x02,
        URL = 0x04,
        CRYPTO = 0x08,
        SAMCOMMUNITY = 0x10,
        SAM = 0x20
    }

    [Flags]
    public enum DaplugSecurityLevel : byte
    {
        COMMAND_MAC = 0x01,
        COMMAND_ENC = 0x02,
        RESPONSE_MAC = 0x10,
        RESPONSE_DEC = 0x20
    }

    public enum DaplugStatus : byte
    {
        Selectable = 0x07,
        Personalized = 0x0f,
        Terminated = 0x7f,
        Locked = 0x83
    }

    [Flags]
    public enum DaplugCryptoOptions : byte
    {
        //01: use ECB mode
        //02: use CBC mode
        //04: use one diversifier
        //08: use two diversifiers
        ModeECB = 0x01,
        ModeCBC = 0x02,
        OneDiversifier = 0x04,
        TwoDiversifiers = 0x08
    }

    public enum DaplugKeyType : byte
    {
        EncryptionKey = 0x01,
        MACKey = 0x02,
        KeyEncryptionKey = 0x03
    }

    public class DaplugAPI : IDisposable
    {
        public static readonly ushort MAX_FS_FILE_SIZE = 0xffff; //Max size of an EF
        public static readonly byte MAX_IO_DATA_SIZE = 0xef; //EF = FF - 8 - 8 (data max len - possible mac - possible pad if data encrypted)



        private readonly IDaplugDongle dongle;
        public DaplugLicensing LicensedOptions { get; private set; }

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

        private async Task CheckLicencedOptionAsync(DaplugLicensing option)
        {
            if (LicensedOptions == 0x00)
                LicensedOptions = await GetLicensedOptionsAsync();

            if (LicensedOptions.HasFlag(option) == false)
                throw new DaplugAPIException("This token does not have a " + option + " license.");
        }

        private void CheckSecureChannelOpen([CallerMemberName] string callerMethodName = "")
        {
            if (SessionKeys == null)
                throw new DaplugAPIException("You need to open a Secure Channel to use the " + callerMethodName + " method.");
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
                    //command bytes + data length + data + sw1 & sw2
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

            if (securityLevel.HasFlag(DaplugSecurityLevel.COMMAND_MAC) == false)
                securityLevel |= DaplugSecurityLevel.COMMAND_MAC;

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
            var licFileContents = await ReadFileDataAsync(0, 2);
            await SelectFileAsync(DaplugConstants.MasterFileId);
            return (DaplugLicensing)licFileContents[0];
        }

        public async Task<byte[]> SelectFileAsync(ushort fileID)
        {

            var fileIDBytes = Helpers.UShortToByteArray(fileID);

            var selectFileCommand = new byte[] { 0x80, 0xA4, 0x00, 0x00, 0x00 };

            var command = new APDUCommand(selectFileCommand, fileIDBytes);

            var response = await ExchangeAPDUAsync(command);

            if (!response.IsSuccessfulResponse)
                throw new DaplugAPIException("Error selecting file.", response.SW1, response.SW2);

            return response.ResponseData;
        }

        public async Task<byte[]> SelectPathAsync(params ushort[] path)
        {
            byte[] result = null;
            foreach (ushort p in path)
            {
                result = await SelectFileAsync(p);
            }

            return result;
        }



        public async Task DeleteFileOrDirAsync(ushort fileID)
        {
            var fileIDBytes = Helpers.UShortToByteArray(fileID);

            var deleteFileCommandBytes = new byte[] { 0x80, 0xE4, 0x00, 0x00, 0x02 };

            var command = new APDUCommand(deleteFileCommandBytes, fileIDBytes);

            var response = await ExchangeAPDUAsync(command);

            if (!response.IsSuccessfulResponse)
                throw new DaplugAPIException("Unable to delete the file.", response.SW1, response.SW2);
        }

        private async Task<List<byte>> ReadFileDataInternalAsync(ushort offset, byte length)
        {
            var offsetBytes = Helpers.UShortToByteArray(offset);

            //header
            var readDataCommandAPDUBytes = new List<byte> { 0x80, 0xB0, offsetBytes[0], offsetBytes[1], (SessionKeys != null) ? (byte)0x00 : length };

            var command = new APDUCommand(readDataCommandAPDUBytes);

            var response = await ExchangeAPDUAsync(command);

            if (!response.IsSuccessfulResponse)
                throw new DaplugAPIException("Error reading data: " + response.SW1 + response.SW2);

            return new List<byte>(response.ResponseData);
        }

        public async Task<byte[]> ReadFileDataAsync(ushort offset, ushort length)
        {
            if (offset + length > MAX_FS_FILE_SIZE)
                throw new DaplugAPIException("Maximum filesize (" + MAX_FS_FILE_SIZE + ") exceeded.");

            ushort dataLength = length;
            ushort readOffset = offset;
            List<byte> result = new List<byte>();

            while (dataLength > MAX_IO_DATA_SIZE)
            {
                var readResult = await ReadFileDataInternalAsync(readOffset, MAX_IO_DATA_SIZE);
                result.AddRange(readResult);
                readOffset += MAX_IO_DATA_SIZE;
                dataLength -= MAX_IO_DATA_SIZE;
            }
            if (dataLength > 0)
            {
                var readResult = await ReadFileDataInternalAsync(readOffset, (byte)dataLength);
                result.AddRange(readResult);
            }

            return result.ToArray();
        }

        private async Task WriteFileDataInternalAsync(ushort offset, List<byte> data, ushort seek, byte count)
        {
            var offsetBytes = Helpers.UShortToByteArray(offset);

            //header
            var writeDataCommandAPDUBytes = new List<byte> { 0x80, 0xD6, offsetBytes[0], offsetBytes[1], (byte)count };

            //append data 
            writeDataCommandAPDUBytes.AddRange(data.Skip(seek).Take(count));

            var command = new APDUCommand(writeDataCommandAPDUBytes);

            var response = await ExchangeAPDUAsync(command);

            if (!response.IsSuccessfulResponse)
                throw new DaplugAPIException("Error writing data: " + response.SW1 + response.SW2);
        }

        public async Task WriteFileDataAsync(ushort offset, List<byte> dataToWrite)
        {
            if (offset + dataToWrite.Count > MAX_FS_FILE_SIZE)
                throw new DaplugAPIException("Maximum filesize (" + MAX_FS_FILE_SIZE + ") exceeded.");

            ushort dataLength = (ushort)dataToWrite.Count;
            ushort writeOffset = offset;

            while (dataLength > MAX_IO_DATA_SIZE)
            {
                await WriteFileDataInternalAsync(writeOffset, dataToWrite, writeOffset, MAX_IO_DATA_SIZE);
                writeOffset += MAX_IO_DATA_SIZE;
                dataLength -= MAX_IO_DATA_SIZE;
            }
            if (dataLength > 0)
                await WriteFileDataInternalAsync((ushort)(writeOffset + offset), dataToWrite, writeOffset, (byte)dataLength);
        }

        public async Task WriteFileDataAsync(ushort offset, byte[] dataToWrite)
        {
            await WriteFileDataAsync(offset, new List<byte>(dataToWrite));
        }

        public async Task CreateFileAsync(ushort fileId, ushort size, byte deleteFileAccessCondition, byte updateAccessCondition, byte readAccessCondition, bool isEncryptedFile = false, bool isCounterFile = false)
        {
            //This function is denied for non counter files if the FILE license is not present. 
            if (isCounterFile == false)
                await CheckLicencedOptionAsync(DaplugLicensing.FILE);


            var createFileCommandAPDUBytes = new List<byte> { 0x80, 0xE0, 0x00, 0x00, 0x1c }; //header

            //62 14 82 02 01 21 83 02 
            var createFileCommandAPDUData = new List<byte> { 0x62, 0x14, 0x82, 0x02, 0x01, 0x21, 0x83, 0x02 };

            createFileCommandAPDUData.AddRange(Helpers.UShortToByteArray(fileId));
            createFileCommandAPDUData.Add(0x81);
            createFileCommandAPDUData.Add(0x02);

            if (isCounterFile)
                size = 8;

            createFileCommandAPDUData.AddRange(Helpers.UShortToByteArray(size));

            //Security Attributes
            createFileCommandAPDUData.AddRange(new List<byte> { 0x8c, 0x06, 0x00, deleteFileAccessCondition, 0x00, 0x00, updateAccessCondition, readAccessCondition });

            //File encryption
            byte enableEncryptionValue = 0x00;
            if (isEncryptedFile)
                enableEncryptionValue = 0x01;

            createFileCommandAPDUData.AddRange(new List<byte> { 0x86, 0x01, enableEncryptionValue });

            //Counter file
            byte isCounterFileValue = 0x00;
            if (isCounterFile)
                isCounterFileValue = 0x01;

            createFileCommandAPDUData.AddRange(new List<byte> { 0x87, 0x01, isCounterFileValue });


            createFileCommandAPDUBytes.AddRange(createFileCommandAPDUData);

            var createDirCommand = new APDUCommand(createFileCommandAPDUBytes.ToArray());

            var response = await ExchangeAPDUAsync(createDirCommand);

            if (!response.IsSuccessfulResponse)
                throw new DaplugAPIException("An error ocurred while creating the file.", response.SW1, response.SW2);

        }

        public async Task CreateFileAsync(ushort fileId, ushort size, byte accessCondition, bool isEncryptedFile = false, bool isCounterFile = false)
        {
            await CreateFileAsync(fileId, size, accessCondition, accessCondition, accessCondition, isEncryptedFile, isCounterFile);
        }

        public async Task CreateDirectoryAsync(ushort directoryId, byte deleteSelfAccessCondition, byte createDirAccessCondition, byte createFileAccessCondition)
        {
            //Check if this device has a FILE license
            await CheckLicencedOptionAsync(DaplugLicensing.FILE);


            var createDirCommandAPDUBytes = new List<byte> { 0x80, 0xE0, 0x00, 0x00, 0x10 }; //header

            var createDirCommandAPDUData = new List<byte> { 0x62, 0x0E, 0x82, 0x02, 0x32, 0x21, 0x83, 0x02 };

            createDirCommandAPDUData.AddRange(Helpers.UShortToByteArray(directoryId));

            createDirCommandAPDUData.AddRange(new List<byte> { 0x8c, 0x04, 0x00, deleteSelfAccessCondition, createDirAccessCondition, createFileAccessCondition });

            createDirCommandAPDUBytes.AddRange(createDirCommandAPDUData);

            var createDirCommand = new APDUCommand(createDirCommandAPDUBytes.ToArray());

            var response = await ExchangeAPDUAsync(createDirCommand);

            if (!response.IsSuccessfulResponse)
                throw new DaplugAPIException("An error ocurred while creating the directory.", response.SW1, response.SW2);

        }

        public async Task CreateDirectoryAsync(ushort directoryId, byte accessCondition)
        {
            await CreateDirectoryAsync(directoryId, accessCondition, accessCondition, accessCondition);
        }

        private List<byte> PrepareKeyToPutKeyCommand(byte[] key, byte keyUsage, ushort keyAccess)
        {

            var result = new List<byte> { 0xff, 0x80, 0x10 }; // key type (FF80) + Key Length (0x10)
            //encrypt the key
            var encryptedKey = Crypto.TripleDESEncryptECB(SessionKeys.SKEKey, key);
            result.AddRange(encryptedKey);

            //Key Check Value
            result.Add(0x03); //KCV Length
            var keyCheckValue = Crypto.CalculateKCV(key);
            result.AddRange(keyCheckValue);

            //key usage
            result.Add(0x01); //key usage length
            result.Add(keyUsage);

            //key access
            result.Add(0x02); //key access length
            result.AddRange(Helpers.UShortToByteArray(keyAccess));

            return result;

        }

        public async Task PutKeyAsync(DaplugKeySet key, byte mode = 0x81)
        {
            CheckSecureChannelOpen();

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

        public async Task<byte[]> GenerateRandomAsync(byte length)
        {
            if (length > MAX_IO_DATA_SIZE)
                throw new ArgumentException("Length must be between 0 and " + MAX_IO_DATA_SIZE, "length");

            var generateRandomCommandAPDUBytes = new byte[] { 0xD0, 0x24, 0x00, 0x00, length };

            // append <length> bytes to the command APDU so that Le matches the Lc
            generateRandomCommandAPDUBytes = generateRandomCommandAPDUBytes.Concat(new byte[length]).ToArray();

            var generateRandomCommand = new APDUCommand(generateRandomCommandAPDUBytes);

            var response = await ExchangeAPDUAsync(generateRandomCommand);

            if (!response.IsSuccessfulResponse)
                throw new DaplugAPIException("An error ocurred while generating random bytes.", response.SW1, response.SW2);

            return response.ResponseData;
        }

        private async Task<byte[]> EncryptOrDecryptDataInternalAsync(byte keyVersion, DaplugKeyType keyType, DaplugCryptoOptions options, byte[] data, bool decrypt, byte[] iv = null, byte[] diversifier1 = null, byte[] diversifier2 = null)
        {
            //This function is only available if the CRYPTO license is set.
            await CheckLicencedOptionAsync(DaplugLicensing.CRYPTO);

            if (data.Length % 8 != 0)
                throw new ArgumentException("Data length must be a multiple of 8 bytes.", "data");

            byte apduDataLenght = 10; //key version (1) + key id (1) + iv (8);

            if (options.HasFlag(DaplugCryptoOptions.OneDiversifier) || options.HasFlag(DaplugCryptoOptions.TwoDiversifiers))
            {
                if (diversifier1 == null)
                    throw new ArgumentException("Diversifier 1 is required when using the OneDiversifier or TwoDiversifiers option.", "diversifier1");

                if (diversifier1.Length != 16)
                    throw new ArgumentException("Diversifier 1 must be 16 bytes long.", "diversifier1");

                apduDataLenght += 16;
            }

            if (options.HasFlag(DaplugCryptoOptions.TwoDiversifiers))
            {
                if (diversifier2 == null)
                    throw new ArgumentException("Diversifier 2 is required when using the TwoDiversifiers option.", "diversifier2");

                if (diversifier2.Length != 16)
                    throw new ArgumentException("Diversifier 1 must be 16 bytes long.", "diversifier2");

                apduDataLenght += 16;
            }

            if (data.Length + apduDataLenght > MAX_IO_DATA_SIZE)
                throw new ArgumentException("Data length limit exceeded.", "data");


            //if no IV is supplied, set the IV to a new array of 8 0x0 bytes
            if (iv == null)
                iv = new byte[8];
            else if (iv.Length != 8)
                throw new ArgumentException("IV must be 8 bytes long.", "iv");

            //0x01 = encrypt, 0x02 = decrypt
            byte selectedFunction = 0x01;
            if (decrypt)
                selectedFunction = 0x02;

            var encryptOrDecryptCommandAPDUBytes = new List<byte> { 0xD0, 0x20, selectedFunction, (byte)options, 0x00 };

            encryptOrDecryptCommandAPDUBytes.Add(keyVersion);
            encryptOrDecryptCommandAPDUBytes.Add((byte)keyType);
            encryptOrDecryptCommandAPDUBytes.AddRange(iv);

            if (options.HasFlag(DaplugCryptoOptions.OneDiversifier) || options.HasFlag(DaplugCryptoOptions.TwoDiversifiers))
                encryptOrDecryptCommandAPDUBytes.AddRange(diversifier1);

            if (options.HasFlag(DaplugCryptoOptions.TwoDiversifiers))
                encryptOrDecryptCommandAPDUBytes.AddRange(diversifier2);

            encryptOrDecryptCommandAPDUBytes.AddRange(data);

            var cryptCommand = new APDUCommand(encryptOrDecryptCommandAPDUBytes);

            var response = await ExchangeAPDUAsync(cryptCommand);

            if (response.IsSuccessfulResponse == false)
                throw new DaplugAPIException("An error ocurred while performing the cryptography operation.", response.SW1, response.SW2);

            return response.ResponseData;

        }

        public async Task<byte[]> EncryptDataAsync(byte keyVersion, DaplugKeyType keyType, DaplugCryptoOptions options, byte[] plaintext, byte[] iv = null, byte[] diversifier1 = null, byte[] diversifier2 = null)
        {
            return await EncryptOrDecryptDataInternalAsync(keyVersion, keyType, options, plaintext, false, iv, diversifier1, diversifier2);
        }

        public async Task<byte[]> DecryptDataAsync(byte keyVersion, DaplugKeyType keyType, DaplugCryptoOptions oprions, byte[] ciphertext, byte[] iv = null, byte[] diversifier1 = null, byte[] diversifier2 = null)
        {
            return await EncryptOrDecryptDataInternalAsync(keyVersion, keyType, oprions, ciphertext, true, iv, diversifier1, diversifier2);
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
                dongle.Dispose();
            }
        }
    }
}

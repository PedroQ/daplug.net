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
    public class DaplugAPI : IDisposable
    {

        [Flags]
        public enum SecurityLevel
        {
            COMMAND_MAC = 0x01,
            COMMAND_ENC = 0x02,
            RESPONSE_MAC = 0x10,
            RESPONSE_DEC = 0x20
        }

        [Flags]
        public enum Licensing
        {
            FILE = 0x01,
            KEYBOARD = 0x02,
            URL = 0x04,
            CRYPTO = 0x08,
            SAMCOMMUNITY = 0x10,
            SAM = 0x20
        }


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

        public async Task<APDUResponse> ExchangeAPDU(APDUCommand apdu)
        {
            var finalAPDU = new APDUCommand(apdu.ToByteArray());

            if (SessionKeys != null)
            {
                byte[] apduMac = null;

                if (SessionKeys.SecurityLevel.HasFlag(SecurityLevel.COMMAND_MAC))
                {
                    finalAPDU.InstructionClass |= 0x04;
                    var apduBytes = finalAPDU.ToByteArray();
                    apduBytes[4] += 0x08;
                    apduMac = DaplugCrypto.CalculateApduMac(SessionKeys.CMacKey, apduBytes, SessionKeys.CMac);
                    Array.Copy(apduMac, 0, SessionKeys.CMac, 0, 8);
                }
                if ((apdu.InstructionClass == 0x80 && apdu.InstructionCode == 0x82) == false) // Do not encrypt EXTERNAL_AUTHENTICATE APDU
                {
                    if (SessionKeys.SecurityLevel.HasFlag(SecurityLevel.COMMAND_ENC))
                    {
                        finalAPDU.CommandData = DaplugCrypto.EncryptAPDUData(SessionKeys, apdu);
                    }
                }
                if (apduMac.Length != null)
                {
                    finalAPDU.CommandData = finalAPDU.CommandData.Concat(apduMac).ToArray();
                }

            }

            Debug.WriteLine("=> " + BitConverter.ToString(finalAPDU.ToByteArray()));

            var response = await dongle.ExchangeAPDU(finalAPDU);


            if (SessionKeys != null && response.HasData)
            {
                byte[] responseMac = null;
                if (SessionKeys.SecurityLevel.HasFlag(SecurityLevel.RESPONSE_MAC))
                {
                    // extract MAC from the response (the last 8 bytes)
                    responseMac = new byte[8];
                    Array.Copy(response.ResponseData, response.ResponseData.Length - 8, responseMac, 0, 8);

                    //resize the response data to exclude the last 8 bytes (MAC)
                    var tmpData = response.ResponseData;
                    Array.Resize(ref tmpData, response.ResponseData.Length - 8);
                    response.ResponseData = tmpData;
                }

                if (SessionKeys.SecurityLevel.HasFlag(SecurityLevel.RESPONSE_DEC))
                {
                        response.ResponseData = DaplugCrypto.DecryptAPDUResponse(SessionKeys, response.ResponseData);
                }

                if (SessionKeys.SecurityLevel.HasFlag(SecurityLevel.RESPONSE_MAC))
                {
                    //construct MAC input
                    var apduCommandBytes = apdu.ToByteArray();
                    //command bytes + data lenght + data + sw1 & sw2
                    //var macInput = new byte[apduCommandBytes.Length + 1 + response.ResponseData.Length + 2];
                    byte[] macInput = apduCommandBytes.Concat(new byte[] {(byte)response.ResponseData.Length} )
                        .Concat(response.ResponseData).Concat(new byte[] { response.SW1, response.SW2}).ToArray();

                    byte[] calculatedResponseMac = DaplugCrypto.CalculateApduMac(SessionKeys.RMacKey, macInput, SessionKeys.RMac, true);

                    if (calculatedResponseMac.SequenceEqual(responseMac) == false)
                        Console.WriteLine("MAC CHECK FAILED!!");

                    Array.Copy(calculatedResponseMac, SessionKeys.RMac, 8);

                }
            }

            Debug.WriteLine("<= " + BitConverter.ToString(response.ToByteArray()));

            return response;
        }


        public async Task<byte[]> GetSerial()
        {
            var getSerialCommand = new byte[] { 0x80, 0xE6, 0x00, 0x00, 0x00 };

            var command = new APDUCommand(getSerialCommand);

            var response = await ExchangeAPDU(command);

            if (!response.IsSuccessfulResponse)
                throw new DaplugAPIException("Error: " + response.SW1 + response.SW2);

            return response.ResponseData;
        }

        public async Task<Status> GetStatus()
        {
            var getStatusCommand = new byte[] { 0x80, 0xF2, 0x40, 0x00, 0x00 };

            var command = new APDUCommand(getStatusCommand);

            var response = await ExchangeAPDU(command);

            if (!response.IsSuccessfulResponse)
                throw new DaplugAPIException("Error: " + response.SW1 + response.SW2);

            return (Status)response.ResponseData[9];
        }

        public async Task<bool> OpenSecureChannel(DaplugKeySet keyset, SecurityLevel securityLevel, byte[] diversifier = null, byte[] hostChallenge = null)
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

            var response = await ExchangeAPDU(authCommand);

            if (response.IsSuccessfulResponse == false)
                return false;

            byte[] counter = new byte[2];
            byte[] cardChallenge = new byte[8];
            byte[] cardCryptogram = new byte[8];
            Array.Copy(response.ResponseData, 12, counter, 0, 2);
            Array.Copy(response.ResponseData, 12, cardChallenge, 0, 8);
            Array.Copy(response.ResponseData, 20, cardCryptogram, 0, 8);

            var tempSessionKeys = DaplugCrypto.ComputeSessionKeys(keyset, counter);

            var computedCardCryptogram = DaplugCrypto.CalculateCryptogram(tempSessionKeys, hostChallenge, cardChallenge);

            if (computedCardCryptogram.SequenceEqual(cardCryptogram) == false)
                return false;

            var hostCryptogram = DaplugCrypto.CalculateCryptogram(tempSessionKeys, cardChallenge, hostChallenge);

            if (securityLevel.HasFlag(SecurityLevel.COMMAND_MAC) == false)
                securityLevel |= SecurityLevel.COMMAND_MAC;

            tempSessionKeys.SecurityLevel = securityLevel;

            SessionKeys = tempSessionKeys;

            var extAuthCommandHeader = new byte[] { 0x80, 0x82, (byte)SessionKeys.SecurityLevel, 0x00, 0x00 };
            var extAuthCommand = new APDUCommand(extAuthCommandHeader, hostCryptogram);

            var extAuthResponse = await ExchangeAPDU(extAuthCommand);

            if (extAuthResponse.IsSuccessfulResponse)
            {
                Array.Copy(SessionKeys.CMac, SessionKeys.RMac, 8);
                return true;
            }

            SessionKeys = null;
            return false;
        }

        public void CloseSecureChannel()
        {
            if (SessionKeys != null)
            {
                SessionKeys = null;
            }
        }

        public async Task<byte[]> SelectFile(ushort fileID)
        {

            var fileIDBytes = BitConverter.GetBytes(fileID);
            // If this is little endian machine, reverse the array
            // so that the bytes are in the correct order
            if (BitConverter.IsLittleEndian)
                Array.Reverse(fileIDBytes);

            var selectFileCommand = new byte[] { 0x80, 0xA4, 0x00, 0x00, 0x00 };

            var command = new APDUCommand(selectFileCommand, fileIDBytes);

            var response = await ExchangeAPDU(command);

            if (!response.IsSuccessfulResponse)
                throw new DaplugAPIException("Error: " + response.SW1 + response.SW2);

            return response.ResponseData;
        }

        public async Task<byte[]> ReadFile(ushort offset, byte length)
        {

            var offsetBytes = BitConverter.GetBytes(offset);
            // If this is little endian machine, reverse the array
            // so that the bytes are in the correct order
            if (BitConverter.IsLittleEndian)
                Array.Reverse(offsetBytes);

            var readFileCommand = new byte[] { 0x80, 0xB0, offsetBytes[0], offsetBytes[1], (SessionKeys != null) ? (byte)0x00 : length };

            var command = new APDUCommand(readFileCommand);

            var response = await ExchangeAPDU(command);

            if (!response.IsSuccessfulResponse)
                throw new DaplugAPIException("Error: " + response.SW1 + response.SW2);

            return response.ResponseData;
        }

        public async Task<bool> UsbToHid()
        {
            var usbToHidCommand = new byte[] { 0xD0, 0x52, 0x08, 0x01, 0x00 };

            var command = new APDUCommand(usbToHidCommand);

            var response = await ExchangeAPDU(command);

            return response.IsSuccessfulResponse;
        }

        public async Task<bool> HidToUsb()
        {
            var HidToUsbCommand = new byte[] { 0xD0, 0x52, 0x08, 0x02, 0x00 };

            var command = new APDUCommand(HidToUsbCommand);

            var response = await ExchangeAPDU(command);

            return response.IsSuccessfulResponse;
        }

        public async Task<bool> Reset()
        {
            var resetCommand = new byte[] { 0xD0, 0x52, 0x01, 0x00, 0x00 };

            var command = new APDUCommand(resetCommand);

            var response = await ExchangeAPDU(command);

            return response.IsSuccessfulResponse;
        }

        public async Task<bool> Halt()
        {
            var haltCommand = new byte[] { 0xD0, 0x52, 0x02, 0x00, 0x00 };

            var command = new APDUCommand(haltCommand);

            var response = await ExchangeAPDU(command);

            return response.IsSuccessfulResponse;
        }

        public async Task<Licensing> GetLicensedOptions()
        {
            await SelectFile(0x3F00);
            await SelectFile(0xC00F);
            await SelectFile(0xD00D);
            await SelectFile(0xA1BA);
            var licFileContents = await ReadFile(0, 2);
            return (Licensing)licFileContents[0];
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



        public enum Status
        {
            Selectable = 0x07,
            Personalized = 0x0F,
            Terminated = 0x7f,
            Locked = 83
        }
    }
}

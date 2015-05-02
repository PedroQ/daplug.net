using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace daplug.net.test
{
    class Program
    {
        private static DaplugKeySet defaultKeyset = new DaplugKeySet(0x01, "404142434445464748494A4B4C4D4E4F");
        private static DaplugKeySet testKeyset = new DaplugKeySet(0x65, DaplugKeySet.KeyUsage.USAGE_GP, 0x0001, "404142434445464748494A4B4C4D4E4F");
        private static DaplugSecurityLevel fullSecurityLevel = DaplugSecurityLevel.COMMAND_MAC | DaplugSecurityLevel.COMMAND_ENC | DaplugSecurityLevel.RESPONSE_DEC | DaplugSecurityLevel.RESPONSE_MAC;
        private static DaplugSecurityLevel cMacSecurityLevel = DaplugSecurityLevel.COMMAND_MAC;

        static void Main(string[] args)
        {
            var tests = RunTests();
            tests.Wait();
            Console.Write("Press <ENTER> to quit...");
            Console.ReadLine();
        }

        private static async Task RunTests()
        {
            try
            {
                using (DaplugAPI api = DaplugAPI.OpenFirstDongle())
                {
                    await TestSecureChannel(api, defaultKeyset, cMacSecurityLevel);
                    await TestGetSerial(api);
                    await TestGetStatus(api);
                    await TestGetLicensedOptions(api);
                    await TestPutKey(api);
                    await TestFilesystem(api);
                    await TestGenerateRandom(api);
                    await TestCryptoOperations(api);
                    await TestHMACSHA1(api);
                    await TestHOTP(api);
                    await TestTOTP(api);
                }
            }
            catch (Exception e)
            {
                WriteError(e);
            }
        }

        private static async Task TestSecureChannel(DaplugAPI api, DaplugKeySet keyset, DaplugSecurityLevel secLevel)
        {
            WriteTitle();
            await api.OpenSecureChannelAsync(keyset, secLevel);
            WriteSuccess("Success!");
            api.CloseSecureChannel();
        }

        private static async Task TestGetSerial(DaplugAPI api)
        {
            WriteTitle();
            var res = await api.GetSerialAsync();
            WriteSuccess("Result: {0}", BitConverter.ToString(res).Replace("-", "").ToLowerInvariant());
        }

        private static async Task TestGetStatus(DaplugAPI api)
        {
            WriteTitle();
            var res = await api.GetStatusAsync();
            WriteSuccess("Result: {0}", res);
        }

        private static async Task TestGetLicensedOptions(DaplugAPI api)
        {
            WriteTitle();
            var licFileContents = await api.GetLicensedOptionsAsync();
            WriteSuccess("License File: {0}", licFileContents);
        }

        private static async Task TestPutKey(DaplugAPI api)
        {
            WriteTitle();
            await api.OpenSecureChannelAsync(defaultKeyset, cMacSecurityLevel);
            WriteInfo("Putting key 0x65...");
            await api.PutKeyAsync(testKeyset);
            api.CloseSecureChannel();
            WriteInfo("Opening Secure Channel with key 0x{0:X2}...", testKeyset.Version);
            await api.OpenSecureChannelAsync(testKeyset, cMacSecurityLevel);
            WriteSuccess("Success!");
            api.CloseSecureChannel();
            WriteInfo("Deleting key 0x{0:X2}...", testKeyset.Version);
            await api.OpenSecureChannelAsync(defaultKeyset, cMacSecurityLevel);
            await api.DeleteKeyAsync(testKeyset.Version);
            api.CloseSecureChannel();
        }

        public static async Task TestFilesystem(DaplugAPI api)
        {
            ushort dirId = 0x2012;
            ushort fileId = 1001;
            ushort testDataLength = 600;
            byte[] testBytes = new byte[testDataLength];
            Random rnd = new Random();
            rnd.NextBytes(testBytes);

            WriteTitle();
            WriteInfo("Opening Secure Channel...");
            await api.OpenSecureChannelAsync(defaultKeyset, fullSecurityLevel);
            WriteInfo("Selecting Master File...");
            await api.SelectPathAsync(DaplugConstants.MasterFileId);
            WriteInfo("Creating DF 0x{0:X2}...", dirId);
            await api.CreateDirectoryAsync(dirId, DaplugConstants.AccessAlways);
            WriteInfo("Selecting DF 0x{0:X2}...", dirId);
            var result = await api.SelectPathAsync(dirId);
            WriteInfo("Creating File 0x{0:X2}...", fileId);
            await api.CreateFileAsync(fileId, testDataLength, DaplugConstants.AccessAlways);
            WriteInfo("Selecting File 0x{0:X2}...", fileId);
            await api.SelectFileAsync(fileId);
            WriteInfo("Writing test data to file...");
            await api.WriteFileDataAsync(0, testBytes);
            WriteInfo("Reading test data to file...");
            var fileContents = await api.ReadFileDataAsync(0, testDataLength);
            bool readTestSuccess = testBytes.SequenceEqual(fileContents);
            if (readTestSuccess)
                WriteSuccess("Success! Read data matches Test data.");
            else
                WriteFail("Fail! Read data does not match Test data.");
            WriteInfo("Selecting Master File...");
            await api.SelectPathAsync(DaplugConstants.MasterFileId);
            WriteInfo("Selecting DF 0x{0:X2}...", dirId);
            await api.SelectPathAsync(dirId);
            WriteInfo("Deleting File 0x{0:X2}...", fileId);
            await api.DeleteFileOrDirAsync(fileId);
            WriteInfo("Selecting Master File...");
            await api.SelectPathAsync(DaplugConstants.MasterFileId);
            WriteInfo("Deleting DF 0x{0:X2}...", dirId);
            await api.DeleteFileOrDirAsync(dirId);
            api.CloseSecureChannel();
            WriteSuccess("Success!");
        }

        public static async Task TestGenerateRandom(DaplugAPI api)
        {
            byte numBytes = 128;

            WriteTitle();
            WriteInfo("Opening Secure Channel...");
            await api.OpenSecureChannelAsync(defaultKeyset, fullSecurityLevel);
            var randomBytes = await api.GenerateRandomAsync(numBytes);
            WriteSuccess("Success! Got {0} random bytes.", numBytes);
            api.CloseSecureChannel();

        }

        public static async Task TestCryptoOperations(DaplugAPI api)
        {
            WriteTitle();
            //Encryption/decryption keyset, access first byte codes the key access (here : 0 = always), access second byte codes the decryption access (here 0 = always)
            DaplugKeySet cryptoKeyset = new DaplugKeySet(0x31, DaplugKeySet.KeyUsage.USAGE_ENC_DEC, 0x0000, "404142434445464748494A4B4C4D4E4F");
            DaplugCryptoOptions options = DaplugCryptoOptions.ModeCBC | DaplugCryptoOptions.TwoDiversifiers;

            Random rnd = new Random();

            byte[] testData = new byte[128];
            byte[] iv = new byte[8];
            byte[] div1 = new byte[16];
            byte[] div2 = new byte[16];

            rnd.NextBytes(testData);
            rnd.NextBytes(iv);
            rnd.NextBytes(div1);
            rnd.NextBytes(div2);

            WriteInfo("Opening Secure Channel...");
            await api.OpenSecureChannelAsync(defaultKeyset, fullSecurityLevel);
            WriteInfo("Setting up... Putting key with ID 0x{0:X2}...", cryptoKeyset.Version);
            await api.PutKeyAsync(cryptoKeyset);

            byte[] cipherText = await api.EncryptDataAsync(cryptoKeyset.Version, DaplugKeyType.EncryptionKey, options, testData, iv, div1, div2);
            WriteSuccess("Got ciphertext.");
            WriteInfo("Decrypting...");
            byte[] plaintext = await api.DecryptDataAsync(cryptoKeyset.Version, DaplugKeyType.EncryptionKey, options, cipherText, iv, div1, div2);
            WriteSuccess("Got plaintext.");
            bool testDataMatches = plaintext.SequenceEqual(testData);
            if (testDataMatches)
                WriteSuccess("Plaintext matches test data.");
            else
                WriteFail("Plaintext does not match test data.");

            WriteInfo("Cleaning up... Deleting key with ID 0x{0:X2}...", cryptoKeyset.Version);
            await api.DeleteKeyAsync(cryptoKeyset.Version);
            api.CloseSecureChannel();
        }

        public static async Task TestHMACSHA1(DaplugAPI api)
        {
            WriteTitle();

            //HMAC-SHA1 keyset, access first byte codes the key access (here : 0 = always), access second byte codes the key length (must be < 48)
            ushort hmacKeysetAccess = 48;
            DaplugKeySet hmacKeyset = new DaplugKeySet(0x32, DaplugKeySet.KeyUsage.USAGE_HMAC_SHA1, hmacKeysetAccess, "3fad384539a266c6b2dbc64619a876c8");
            DaplugHMACOptions options = DaplugHMACOptions.NoDiversifier;

            //calculate HMACSHA1 locally
            var localHMACKey = StringToByteArray("3fad384539a266c6b2dbc64619a876c83fad384539a266c6b2dbc64619a876c83fad384539a266c6b2dbc64619a876c8");
            HMACSHA1 hmacSha1 = new HMACSHA1(localHMACKey);

            WriteInfo("Opening Secure Channel...");
            await api.OpenSecureChannelAsync(defaultKeyset, fullSecurityLevel);
            WriteInfo("Setting up... Putting HMAC-SHA1 key with ID 0x{0:X2}...", hmacKeyset.Version);
            await api.PutKeyAsync(hmacKeyset);

            byte[] data = Encoding.ASCII.GetBytes("Test With Truncation");
            byte[] expectedSignature = hmacSha1.ComputeHash(data);

            WriteInfo("Calling HMAC-SHA1...");
            byte[] signature = await api.HMACSHA1Async(hmacKeyset.Version, options, data);

            bool testDataMatches = signature.SequenceEqual(expectedSignature);
            if (testDataMatches)
                WriteSuccess("Signature matches test case.");
            else
                WriteFail("Signature does not match test case.");

            WriteInfo("Cleaning up... Deleting key with ID 0x{0:X2}...", hmacKeyset.Version);
            await api.DeleteKeyAsync(hmacKeyset.Version);
            api.CloseSecureChannel();
        }

        public static async Task TestHOTP(DaplugAPI api)
        {
            WriteTitle();

            //HOTP keyset, access first byte codes the key access (here : 0 = always), access second byte codes the key length (must be < 48)
            ushort hotpKeysetAccess = 48;
            DaplugKeySet hotpKeyset = new DaplugKeySet(0x33, DaplugKeySet.KeyUsage.USAGE_HOTP, hotpKeysetAccess, "3fad384539a266c6b2dbc64619a876c8");
            DaplugHMACOptions options = DaplugHMACOptions.HOTP6Digits;
            ushort counterFileId = 0xc01d;

            WriteInfo("Opening Secure Channel...");
            await api.OpenSecureChannelAsync(defaultKeyset, fullSecurityLevel);
            WriteInfo("Setting up... Putting HOTP key with ID 0x{0:X2}...", hotpKeyset.Version);
            await api.PutKeyAsync(hotpKeyset);
            WriteInfo("Creating counter file...");
            await api.SelectPathAsync(DaplugConstants.MasterFileId, DaplugConstants.CountersDirId);
            await api.CreateFileAsync(0xc01d, 8, DaplugConstants.AccessAlways, isCounterFile: true);

            WriteInfo("Generating HOTP...");
            byte[] hotpResult = await api.HOTPAsync(hotpKeyset.Version, options, counterFileId);

            string hotpString = Encoding.UTF8.GetString(hotpResult);

            WriteSuccess("Generated HTOP: {0}", hotpString);

            WriteInfo("Cleaning up...");
            WriteInfo("Deleting counter file...");
            await api.SelectPathAsync(DaplugConstants.MasterFileId, DaplugConstants.CountersDirId);
            await api.DeleteFileOrDirAsync(counterFileId);

            WriteInfo("Deleting HOTP key with ID 0x{0:X2}...", hotpKeyset.Version);
            await api.DeleteKeyAsync(hotpKeyset.Version);
            api.CloseSecureChannel();
        }

        public static async Task TestTOTP(DaplugAPI api)
        {
            WriteTitle();

            //Time source keyset, access first byte codes the key access (here : 0 = always), access second byte is not meaningful here
            DaplugKeySet totpTimeSrcKeyset = new DaplugKeySet(0x34, DaplugKeySet.KeyUsage.USAGE_TOTP_TIME_SRC, 0x00, "cad048df2b00b9f3031d1b193bb5f0bd");

            //TOTP keyset, access first byte codes the time source keyset version, access second byte codes the key length (must be < 48)
            ushort totpKeysetAccess = (ushort)((totpTimeSrcKeyset.Version << 8) + 48);
            DaplugKeySet totpKeyset = new DaplugKeySet(0x35, DaplugKeySet.KeyUsage.USAGE_TOTP, totpKeysetAccess, "b14007d5607f554fbf6377b87855ce90");

            DaplugHMACOptions options = DaplugHMACOptions.HOTP6Digits;

            WriteInfo("Opening Secure Channel...");
            await api.OpenSecureChannelAsync(defaultKeyset, fullSecurityLevel);
            WriteInfo("Setting up... Putting Time Reference key with ID 0x{0:X2}...", totpTimeSrcKeyset.Version);
            await api.PutKeyAsync(totpTimeSrcKeyset);
            WriteInfo("Setting up... Putting TOTP key with ID 0x{0:X2}...", totpKeyset.Version);
            await api.PutKeyAsync(totpKeyset);

            WriteInfo("Setting time reference...");
            await api.SetTimeReferenceAsync(totpTimeSrcKeyset.Version, DaplugKeyType.EncryptionKey, totpTimeSrcKeyset.EncKey);

            WriteInfo("Generating TOTP...");
            byte[] hotpResult = await api.TOTPAsync(totpKeyset.Version, options);

            string hotpString = Encoding.UTF8.GetString(hotpResult);
            WriteSuccess("Generated TOTP: {0}", hotpString);

            WriteInfo("Cleaning up...");
            WriteInfo("Deleting Time Reference key with ID 0x{0:X2}...", totpTimeSrcKeyset.Version);
            await api.DeleteKeyAsync(totpTimeSrcKeyset.Version);
            WriteInfo("Deleting TOTP key with ID 0x{0:X2}...", totpKeyset.Version);
            await api.DeleteKeyAsync(totpKeyset.Version);
            api.CloseSecureChannel();
        }

        private static void WriteSuccess(string message)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine(message);
            Console.ResetColor();
        }

        private static void WriteSuccess(string message, params object[] args)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine(string.Format(message, args));
            Console.ResetColor();
        }

        private static void WriteFail(string error)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine(error);
            Console.ResetColor();
        }

        private static void WriteInfo(string message, params object[] args)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine(string.Format(message, args));
            Console.ResetColor();
        }

        private static void WriteError(Exception e)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("====================== MAYDAY ======================");
            Console.WriteLine("An exception was thrown!");
            Console.WriteLine(e.Message);
            Console.WriteLine("====================================================");
            Console.ResetColor();
        }
        private static void WriteTitle([CallerMemberName]string testname = "")
        {
            Console.WriteLine("~~~~~~ {0} ~~~~~~", testname);
        }

        private static byte[] StringToByteArray(String hex)
        {
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }
    }
}

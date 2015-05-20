using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace daplug.net.test
{
    class Program
    {

        //adminKeyset (0x01) already exists on the card. It acts as a specific administrative code with extended capabilities for dongle management.
        private static DaplugKeySet adminKeyset = new DaplugKeySet(0x01, "404142434445464748494A4B4C4D4E4F");

        private static DaplugSecurityLevel fullSecurityLevel = DaplugSecurityLevel.COMMAND_MAC | DaplugSecurityLevel.COMMAND_ENC | DaplugSecurityLevel.RESPONSE_DEC | DaplugSecurityLevel.RESPONSE_MAC;
        private static DaplugSecurityLevel cMacSecurityLevel = DaplugSecurityLevel.COMMAND_MAC;

        //testKeyset, used just for testing new keyset upload
        private static DaplugKeySet testKeyset = new DaplugKeySet(0x65, DaplugKeySet.KeyUsage.GP, 0x0001, "6e7bf326a7c8103fe7c3d169a644c15e");

        //Encryption/decryption keyset, access first byte codes the key access (here : 0 = always), access second byte codes the decryption access (here 0 = always)
        private static DaplugKeySet cryptoKeyset = new DaplugKeySet(0x31, DaplugKeySet.KeyUsage.ENC_DEC, 0x0000, "61d1ff8efe6a482ac81414bbdd69a42d");

        //HMAC-SHA1 keyset, access first byte codes the key access (here : 0 = always), access second byte codes the key length (must be < 48)
        private static ushort hmacKeysetAccess = 48;
        private static DaplugKeySet hmacKeyset = new DaplugKeySet(0x32, DaplugKeySet.KeyUsage.HMAC_SHA1, hmacKeysetAccess, "3fad384539a266c6b2dbc64619a876c8");

        //HOTP keyset, access first byte codes the key access (here : 0 = always), access second byte codes the key length (must be < 48)
        private static ushort hotpKeysetAccess = (0x00 << 8) + 48;
        private static DaplugKeySet hotpKeyset = new DaplugKeySet(0x33, DaplugKeySet.KeyUsage.HOTP, hotpKeysetAccess, "763309febc67fec19aad0b1b8e858b1d");

        //Time source keyset, access first byte codes the key access (here : 0 = always), access second byte is not meaningful here
        private static DaplugKeySet totpTimeSrcKeyset = new DaplugKeySet(0x34, DaplugKeySet.KeyUsage.TOTP_TIME_SRC, 0x00, "cad048df2b00b9f3031d1b193bb5f0bd");

        //TOTP keyset, access first byte codes the time source keyset version, access second byte codes the key length (must be < 48)
        private static ushort totpKeysetAccess = (ushort)((totpTimeSrcKeyset.Version << 8) + 48);
        private static DaplugKeySet totpKeyset = new DaplugKeySet(0x35, DaplugKeySet.KeyUsage.TOTP, totpKeysetAccess, "b14007d5607f554fbf6377b87855ce90");

        //The transientKeyset (0xF0) is a virtual keyset located in RAM.. wich can be exported & imported.
        //When exported, the keyset is encrypted with a transient export keyset (role 0x0F)
        //In our test we use the ENC key of the existing transient export keyset (0xFD)

        //access first byte codes the key access (here : 0 = always), access second byte codes the minimum security level mask required to open a Secure Channel using this keyset
        private static DaplugKeySet transientKeyset = new DaplugKeySet(0xF0, DaplugKeySet.KeyUsage.GP, 0x0001, "b6914fac3f25e74615d6723f5f7c8332");
        private static DaplugKeySet transientKeyset2 = new DaplugKeySet(0xF0, DaplugKeySet.KeyUsage.GP, 0x0001, "760aeeedd51ade037186045fd9cfab97");

        static void Main(string[] args)
        {
            var dList = DaplugEnumerator.ListAllDongles();

            foreach (var dongle in dList)
            {
                Console.WriteLine("{0} ({1})", dongle.Item2, dongle.Item1);
            }

            Task tests = RunTests();
            tests.Wait();
            Console.Write("Press any key to quit...");
            Console.ReadKey();
        }

        private static async Task RunTests()
        {
            try
            {
                using (Daplug daplug = DaplugEnumerator.OpenFirstDongle())
                {
                    WriteInfo("Using Daplug in {0} mode.", daplug.CommunicationMode);
                    await TestSecureChannel(daplug, adminKeyset, fullSecurityLevel);
                    await TestGetSerial(daplug);
                    await TestGetStatus(daplug);
                    await TestGetLicensedOptions(daplug);
                    await TestPutKey(daplug);
                    await TestTransientKeyset(daplug);
                    await TestFilesystem(daplug);
                    await TestGenerateRandom(daplug);
                    await TestCryptoOperations(daplug);
                    await TestHMACSHA1(daplug);
                    await TestHOTP(daplug);
                    await TestTOTP(daplug);
                }
            }
            catch (Exception e)
            {
                WriteError(e);
            }
        }

        private static async Task TestSecureChannel(Daplug api, DaplugKeySet keyset, DaplugSecurityLevel secLevel)
        {
            WriteTitle();
            await api.OpenSecureChannelAsync(keyset, secLevel);
            WriteSuccess("Success!");
            api.CloseSecureChannel();
        }

        private static async Task TestGetSerial(Daplug api)
        {
            WriteTitle();
            byte[] res = await api.GetSerialAsync();
            WriteSuccess("Result: {0}", BitConverter.ToString(res).Replace("-", "").ToLowerInvariant());
        }

        private static async Task TestGetStatus(Daplug api)
        {
            WriteTitle();
            DaplugStatus res = await api.GetStatusAsync();
            WriteSuccess("Result: {0}", res);
        }

        private static async Task TestGetLicensedOptions(Daplug api)
        {
            WriteTitle();
            DaplugLicensing licFileContents = await api.GetLicensedOptionsAsync();
            WriteSuccess("License File: {0}", licFileContents);
        }

        private static async Task TestPutKey(Daplug api)
        {
            WriteTitle();
            await api.OpenSecureChannelAsync(adminKeyset, cMacSecurityLevel);
            WriteInfo("Putting key 0x{0:X2}...", testKeyset.Version);
            await api.PutKeyAsync(testKeyset);
            api.CloseSecureChannel();
            WriteInfo("Opening Secure Channel with key ...", testKeyset.Version);
            await api.OpenSecureChannelAsync(testKeyset, cMacSecurityLevel);
            WriteSuccess("Success!");
            api.CloseSecureChannel();
            WriteInfo("Deleting key 0x{0:X2}...", testKeyset.Version);
            await api.OpenSecureChannelAsync(adminKeyset, cMacSecurityLevel);
            await api.DeleteKeyAsync(testKeyset.Version);
            api.CloseSecureChannel();
        }

        private static async Task TestTransientKeyset(Daplug api)
        {
            WriteTitle();
            await api.OpenSecureChannelAsync(adminKeyset, cMacSecurityLevel);

            WriteInfo("Putting first transient key 0x{0:X2}...", transientKeyset.Version);
            await api.PutKeyAsync(transientKeyset);

            WriteInfo("Exporting first transient keyset...");
            byte[] keysetBlob = await api.ExportTransientKeyAsync(0xFD, DaplugKeyType.EncryptionKey);
            api.CloseSecureChannel();

            WriteInfo("Testing first transient keyset...");
            await api.OpenSecureChannelAsync(transientKeyset, cMacSecurityLevel);
            WriteSuccess("Success!");
            api.CloseSecureChannel();

            WriteInfo("Putting second transient key 0x{0:X2}...", transientKeyset2.Version);
            await api.OpenSecureChannelAsync(adminKeyset, cMacSecurityLevel);
            await api.PutKeyAsync(transientKeyset2);
            api.CloseSecureChannel();

            WriteInfo("Testing second transient keyset...");
            await api.OpenSecureChannelAsync(transientKeyset2, cMacSecurityLevel);
            WriteSuccess("Success!");
            api.CloseSecureChannel();

            WriteInfo("Importing first keyset from exported blob...");
            await api.ImportTransientKeyAsync(0xFD, DaplugKeyType.EncryptionKey, keysetBlob);

            WriteInfo("Testing imported keyset...");
            await api.OpenSecureChannelAsync(transientKeyset, cMacSecurityLevel);
            WriteSuccess("Success!");
            api.CloseSecureChannel();
        }

        public static async Task TestFilesystem(Daplug api)
        {
            ushort dirId = 0x2000;
            ushort fileId = 0x2001;
            ushort testDataLength = 512;
            byte[] testBytes = new byte[testDataLength];
            Random rnd = new Random();
            rnd.NextBytes(testBytes);

            WriteTitle();
            WriteInfo("Opening Secure Channel...");
            await api.OpenSecureChannelAsync(adminKeyset, cMacSecurityLevel);
            WriteInfo("Selecting Master File...");
            await api.SelectPathAsync(DaplugConstants.MasterFileId);
            WriteInfo("Creating DF 0x{0:X2}...", dirId);
            await api.CreateDirectoryAsync(dirId, DaplugConstants.AccessAlways);
            WriteInfo("Selecting DF 0x{0:X2}...", dirId);
            await api.SelectPathAsync(dirId);
            WriteInfo("Creating File 0x{0:X2}...", fileId);
            await api.CreateFileAsync(fileId, testDataLength, DaplugConstants.AccessAlways);
            WriteInfo("Selecting File 0x{0:X2}...", fileId);
            await api.SelectFileAsync(fileId);
            WriteInfo("Writing test data to file...");
            await api.WriteFileDataAsync(0, testBytes);
            WriteInfo("Reading test data to file...");
            byte[] fileContents = await api.ReadFileDataAsync(0, testDataLength);
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

        public static async Task TestGenerateRandom(Daplug api)
        {
            byte numBytes = 128;

            WriteTitle();
            WriteInfo("Opening Secure Channel...");
            await api.OpenSecureChannelAsync(adminKeyset, cMacSecurityLevel);
            byte[] randomBytes = await api.GenerateRandomAsync(numBytes);
            WriteSuccess("Success! Got {0} random bytes.", numBytes);
            api.CloseSecureChannel();

        }

        public static async Task TestCryptoOperations(Daplug api)
        {
            WriteTitle();

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
            await api.OpenSecureChannelAsync(adminKeyset, cMacSecurityLevel);
            WriteInfo("Setting up... Putting key with ID 0x{0:X2}...", cryptoKeyset.Version);
            await api.PutKeyAsync(cryptoKeyset);

            DaplugCryptoOptions options = DaplugCryptoOptions.ModeCBC | DaplugCryptoOptions.TwoDiversifiers;

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

        public static async Task TestHMACSHA1(Daplug api)
        {
            WriteTitle();

            //calculate HMACSHA1 locally
            byte[] localHMACKey = StringToByteArray("3fad384539a266c6b2dbc64619a876c83fad384539a266c6b2dbc64619a876c83fad384539a266c6b2dbc64619a876c8");
            HMACSHA1 hmacSha1 = new HMACSHA1(localHMACKey);

            WriteInfo("Opening Secure Channel...");
            await api.OpenSecureChannelAsync(adminKeyset, cMacSecurityLevel);
            WriteInfo("Setting up... Putting HMAC-SHA1 key with ID 0x{0:X2}...", hmacKeyset.Version);
            await api.PutKeyAsync(hmacKeyset);

            byte[] data = Encoding.ASCII.GetBytes("Test With Truncation");
            byte[] expectedSignature = hmacSha1.ComputeHash(data);

            WriteInfo("Calling HMAC-SHA1...");
            DaplugHMACOptions options = DaplugHMACOptions.NoDiversifier;
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

        public static async Task TestHOTP(Daplug api)
        {
            WriteTitle();

            ushort counterFileId = 0xc01d;

            WriteInfo("Opening Secure Channel...");
            await api.OpenSecureChannelAsync(adminKeyset, cMacSecurityLevel);
            WriteInfo("Setting up... Putting HOTP key with ID 0x{0:X2}...", hotpKeyset.Version);
            await api.PutKeyAsync(hotpKeyset);
            WriteInfo("Creating counter file...");
            await api.SelectPathAsync(DaplugConstants.MasterFileId, DaplugConstants.CountersDirId);
            await api.CreateFileAsync(0xc01d, 8, DaplugConstants.AccessAlways, isCounterFile: true);

            WriteInfo("Generating HOTP...");
            DaplugHMACOptions options = DaplugHMACOptions.HOTP6Digits;
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

        public static async Task TestTOTP(Daplug api)
        {
            WriteTitle();

            WriteInfo("Opening Secure Channel...");
            await api.OpenSecureChannelAsync(adminKeyset, cMacSecurityLevel);
            WriteInfo("Setting up... Putting Time Reference key with ID 0x{0:X2}...", totpTimeSrcKeyset.Version);
            await api.PutKeyAsync(totpTimeSrcKeyset);
            WriteInfo("Setting up... Putting TOTP key with ID 0x{0:X2}...", totpKeyset.Version);
            await api.PutKeyAsync(totpKeyset);

            WriteInfo("Setting time reference...");
            await api.SetTimeReferenceAsync(totpTimeSrcKeyset.Version, DaplugKeyType.EncryptionKey, totpTimeSrcKeyset.EncKey);

            DateTime dongleTime = await api.GetTimeReferenceAsync();
            WriteInfo("Time is: {0}", dongleTime);

            WriteInfo("Generating TOTP...");
            DaplugHMACOptions options = DaplugHMACOptions.HOTP6Digits;
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

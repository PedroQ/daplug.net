using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
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
            WriteInfo("Opening Secure Channel with key 0x65...");
            await api.OpenSecureChannelAsync(testKeyset, cMacSecurityLevel);
            WriteSuccess("Success!");
            api.CloseSecureChannel();
            WriteInfo("Deleting key 0x65...");
            await api.OpenSecureChannelAsync(defaultKeyset, cMacSecurityLevel);
            await api.DeleteKeyAsync(testKeyset.Version);
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
        
        private static void WriteInfo(string message)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine(message);
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
            Console.BackgroundColor = ConsoleColor.White;
            Console.ForegroundColor = ConsoleColor.Black;
            Console.WriteLine("~~~~~~ {0} ~~~~~~", testname);
            Console.ResetColor();
        }
    }
}

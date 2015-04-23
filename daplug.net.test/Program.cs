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
        static void Main(string[] args)
        {
            var tests = RunTests();
            tests.Wait();
            Console.WriteLine("Press <ENTER> to quit...");
            Console.ReadLine();
        }

        private static async Task RunTests()
        {

            try
            {
                using (DaplugAPI api = DaplugAPI.OpenFirstDongle())
                {
                    await TestSecureChannel(api);
                    await TestGetSerial(api);
                    await TestGetStatus(api);
                    await TestGetLicensedOptions(api);
                }
            }
            catch (Exception e)
            {
                WriteError(e);
            }
        }

        private static async Task TestSecureChannel(DaplugAPI api)
        {
            WriteTitle();
            var keyset = new DaplugKeySet(0x01, "404142434445464748494A4B4C4D4E4F");
            var securityLevel = DaplugAPI.SecurityLevel.COMMAND_MAC | DaplugAPI.SecurityLevel.COMMAND_ENC | DaplugAPI.SecurityLevel.RESPONSE_DEC | DaplugAPI.SecurityLevel.RESPONSE_MAC;
            var res = await api.OpenSecureChannel(keyset, securityLevel);
            Console.WriteLine("Result: {0}", res ? "Passed" : "Failed");
        }

        private static async Task TestGetSerial(DaplugAPI api)
        {
            WriteTitle();
            var res = await api.GetSerial();
            Console.WriteLine("Result: {0}", BitConverter.ToString(res).Replace("-", "").ToLowerInvariant());
        }

        private static async Task TestGetStatus(DaplugAPI api)
        {
            WriteTitle();
            var res = await api.GetStatus();
            Console.WriteLine("Result: {0}", res);
        }

        private static async Task TestGetLicensedOptions(DaplugAPI api)
        {
            WriteTitle();
            var licFileContents = await api.GetLicensedOptions();
            Console.WriteLine("License File: {0}", licFileContents);
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
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("~~~~~~ {0} ~~~~~~", testname);
            Console.ResetColor();
        }
    }
}

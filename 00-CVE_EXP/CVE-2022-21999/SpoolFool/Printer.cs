using System;
using System.Runtime.InteropServices;
using System.Text;

namespace SpoolFool
{
    class Printer
    {

        [DllImport("winspool.drv", CharSet = CharSet.Auto, SetLastError = true)]
        static extern bool OpenPrinter(string pPrinterName, out IntPtr phPrinter, ref PRINTER_DEFAULTS pDefault);

        [DllImport("winspool.drv", CharSet = CharSet.Auto, SetLastError = true)]
        static extern IntPtr AddPrinter(string pPrinterName, int level, ref PRINTER_INFO_2 printerInfo);

        [StructLayout(LayoutKind.Sequential)]
        struct PRINTER_DEFAULTS
        {
            [MarshalAs(UnmanagedType.LPTStr)] public string pDatatype;
            public IntPtr pDevMode;
            public int DesiredAccess;
        }

        private const int PRINTER_ACCESS_ADMINISTRATOR = 0x4;
        private const int PRINTER_ACCESS_USE = 0x8;
        private const int STANDARD_RIGHTS_REQUIRED = 0xF0000;
        private const int PRINTER_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED | PRINTER_ACCESS_ADMINISTRATOR | PRINTER_ACCESS_USE;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct PRINTER_INFO_2
        {
            [MarshalAs(UnmanagedType.LPTStr)]
            public string pServerName;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string pPrinterName;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string pShareName;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string pPortName;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string pDriverName;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string pComment;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string pLocation;
            public IntPtr pDevMode;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string pSepFile;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string pPrintProcessor;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string pDatatype;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string pParameters;
            public IntPtr pSecurityDescriptor;
            public uint Attributes; // See note below!
            public uint Priority;
            public uint DefaultPriority;
            public uint StartTime;
            public uint UntilTime;
            public uint Status;
            public uint cJobs;
            public uint AveragePPM;
        }

        [DllImport("winspool.drv")]
        static extern bool GetPrinterDriverDirectory(StringBuilder pName,
                             StringBuilder pEnv,
                             int Level,
                             [Out] StringBuilder outPath,
                             int bufferSize,
                             ref int Bytes);

        [DllImport("winspool.drv")]
        internal static extern int SetPrinterDataEx(IntPtr pHandle,
                             string pKeyName,
                             string pValueName,
                             int Type,
                             string pData,
                             int cbData);

        internal static string GetDriverDirectory()
        {
            StringBuilder str = new StringBuilder(1024);
            int i = 0;
            GetPrinterDriverDirectory(null, null, 1, str, 1024, ref i);
            return str.ToString();
        }

        internal static bool OpenExistingPrinter(string printerName, ref IntPtr pHandle)
        {
            PRINTER_DEFAULTS defaults = new PRINTER_DEFAULTS();
            defaults.DesiredAccess = PRINTER_ALL_ACCESS;

            return OpenPrinter(printerName, out pHandle, ref defaults);
        }

        internal static IntPtr CreatePrinter(string printerName)
        {
            PRINTER_INFO_2 printerInfo = new PRINTER_INFO_2();
            printerInfo.pPrinterName = printerName;
            printerInfo.pDriverName = "Microsoft XPS Document Writer v4";
            printerInfo.pPortName = "PORTPROMPT:";
            printerInfo.pPrintProcessor = "winprint";
            printerInfo.pDatatype = "RAW";

            IntPtr hPrinter = AddPrinter("", 2, ref printerInfo);

            return hPrinter;
        }
    }
}

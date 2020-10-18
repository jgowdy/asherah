using System;
using System.Runtime.InteropServices;
using System.Threading;
using GoDaddy.Asherah.PlatformNative.LLP64.Windows.Enums;
using GoDaddy.Asherah.PlatformNative.LP64.OpenSSL;

namespace GoDaddy.Asherah.PlatformNative.LLP64.Windows
{
    internal class WindowsSystemInterfaceImpl : SystemInterface
    {
        private const string ProcessEncryptionCipher = "aes-256-gcm";
        private static readonly IntPtr InvalidPointer = new IntPtr(-1);
        private readonly Lazy<OpenSSLCryptProtectMemory> openSSLCryptProtectMemory;
        private readonly IntPtr hProcess;

        public WindowsSystemInterfaceImpl()
        {
            hProcess = WindowsInterop.GetCurrentProcess();

            // IntPtr library = WindowsInterop.LoadLibrary("C:\\OpenSSL\\libcrypto-1_1-x64.dll");
            openSSLCryptProtectMemory =
                new Lazy<OpenSSLCryptProtectMemory>(
                    () =>
                    {
                        return new OpenSSLCryptProtectMemory(ProcessEncryptionCipher, this);
                    }, LazyThreadSafetyMode.ExecutionAndPublication);
        }

        public override void CopyMemory(IntPtr source, IntPtr dest, ulong length)
        {
            WindowsInterop.CopyMemory(dest, source, UIntPtr.Add(UIntPtr.Zero, (int)length));
        }

        public override void ZeroMemory(IntPtr ptr, ulong length)
        {
            WindowsInterop.ZeroMemory(ptr, UIntPtr.Add(UIntPtr.Zero, (int)length));
        }

        public override bool AreCoreDumpsGloballyDisabled()
        {
            return false;
        }

        public override bool DisableCoreDumpGlobally()
        {
            return false;
        }

        public override void SetNoAccess(IntPtr pointer, ulong length)
        {
            var result = WindowsInterop.VirtualProtectEx(
                hProcess,
                pointer,
                (UIntPtr)length,
                (uint)MemoryProtection.PAGE_NOACCESS,
                out uint oldProtect);
            if (!result)
            {
                throw new WindowsOperationFailedException("VirtualProtectEx", result ? -1 : 0, Marshal.GetLastWin32Error());
            }
        }

        public override void SetReadAccess(IntPtr pointer, ulong length)
        {
            var result = WindowsInterop.VirtualProtectEx(
                hProcess,
                pointer,
                (UIntPtr)length,
                (uint)MemoryProtection.PAGE_READONLY,
                out uint oldProtect);

            if (!result)
            {
                throw new WindowsOperationFailedException("VirtualProtectEx", result ? -1 : 0, Marshal.GetLastWin32Error());
            }
        }

        public override void SetReadWriteAccess(IntPtr pointer, ulong length)
        {
            var result = WindowsInterop.VirtualProtectEx(
                hProcess,
                pointer,
                (UIntPtr)length,
                (uint)MemoryProtection.PAGE_READWRITE,
                out uint oldProtect);

            if (!result)
            {
                throw new WindowsOperationFailedException("VirtualProtectEx", result ? -1 : 0, Marshal.GetLastWin32Error());
            }
        }

        public override void SetNoDump(IntPtr protectedMemory, ulong length)
        {
        }

        public override IntPtr PageAlloc(ulong length)
        {
            var result = WindowsInterop.VirtualAlloc(IntPtr.Zero, (UIntPtr)length, AllocationType.COMMIT | AllocationType.RESERVE, MemoryProtection.PAGE_EXECUTE_READWRITE);
            if (result == IntPtr.Zero || result == InvalidPointer)
            {
                var errno = Marshal.GetLastWin32Error();
                throw new WindowsOperationFailedException("VirtualAlloc", (long)result, errno);
            }

            return result;
        }

        public override void PageFree(IntPtr pointer, ulong length)
        {
            if (!WindowsInterop.VirtualFree(pointer, UIntPtr.Zero, AllocationType.RELEASE))
            {
                var errno = Marshal.GetLastWin32Error();
                throw new WindowsOperationFailedException("VirtualFree", 0L, errno);
            }
        }

        public override void LockMemory(IntPtr pointer, ulong length)
        {
            if (!WindowsInterop.VirtualLock(pointer, (UIntPtr)length))
            {
                var errno = Marshal.GetLastWin32Error();
                throw new WindowsOperationFailedException("VirtualLock", 0L, errno);
            }
        }

        public override void UnlockMemory(IntPtr pointer, ulong length)
        {
            if (!WindowsInterop.VirtualUnlock(pointer, (UIntPtr)length))
            {
                var errno = Marshal.GetLastWin32Error();
                if (errno == (int)VirtualUnlockErrors.ERROR_NOT_LOCKED)
                {
                    return;
                }

                throw new WindowsOperationFailedException("VirtualUnlock", 0L, errno);
            }
        }

        public override ulong GetMemoryLockLimit()
        {
            UIntPtr min = UIntPtr.Zero;
            UIntPtr max = UIntPtr.Zero;
            IntPtr hProcess = WindowsInterop.GetCurrentProcess();
            var result = WindowsInterop.GetProcessWorkingSetSize(hProcess, ref min, ref max);
            if (!result)
            {
                throw new Exception("GetProcessWorkingSetSize failed");
            }

            return (ulong)max;
        }

        public override void SetMemoryLockLimit(ulong limit)
        {
            UIntPtr min = UIntPtr.Zero;
            UIntPtr max = UIntPtr.Zero;
            var result = WindowsInterop.GetProcessWorkingSetSize(hProcess, ref min, ref max);
            if (!result)
            {
                throw new Exception("GetProcessWorkingSetSize failed");
            }

            if (limit < (ulong)max)
            {
                // Already sufficiently large limit
                return;
            }

            max = (UIntPtr)limit;

            result = WindowsInterop.SetProcessWorkingSetSize(hProcess, min, max);
            if (!result)
            {
                throw new Exception($"SetProcessWorkingSetSize({min.ToUInt64()},{max.ToUInt64()}) failed");
            }
        }

        public override ulong GetEncryptedMemoryBlockSize()
        {
            return (ulong)openSSLCryptProtectMemory.Value.GetBlockSize();

            // return CryptProtect.BLOCKSIZE;
        }

        public override void ProcessEncryptMemory(IntPtr pointer, ulong length)
        {
            openSSLCryptProtectMemory.Value.CryptProtectMemory(pointer, (int)length);

            /*
            if (!WindowsInterop.CryptProtectMemory(pointer, (UIntPtr)length, CryptProtectMemoryOptions.SAME_PROCESS))
            {
                var errno = Marshal.GetLastWin32Error();
                throw new WindowsOperationFailedException("CryptProtectMemory", 0L, errno);
            }
            */
        }

        public override void ProcessDecryptMemory(IntPtr pointer, ulong length)
        {
            openSSLCryptProtectMemory.Value.CryptProtectMemory(pointer, (int)length);
            /*
            if (!WindowsInterop.CryptUnprotectMemory(pointer, (UIntPtr)length, CryptProtectMemoryOptions.SAME_PROCESS))
            {
                var errno = Marshal.GetLastWin32Error();
                throw new WindowsOperationFailedException("CryptUnprotectMemory", 0L, errno);
            }
            */
        }
    }
}

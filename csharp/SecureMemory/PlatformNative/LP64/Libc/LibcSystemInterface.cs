using System;
using System.Threading;
using GoDaddy.Asherah.PlatformNative.LP64.OpenSSL;

namespace GoDaddy.Asherah.PlatformNative.LP64.Libc
{
    internal abstract class LibcSystemInterface : SystemInterface
    {
        private const string ProcessEncryptionCipher = "aes-256-gcm";
        private readonly Lazy<OpenSSLCryptProtectMemory> openSSLCryptProtectMemory;
        private bool globallyDisabledCoreDumps;

        internal LibcSystemInterface()
        {
            openSSLCryptProtectMemory =
                new Lazy<OpenSSLCryptProtectMemory>(
                    () =>
                    {
                        return new OpenSSLCryptProtectMemory(ProcessEncryptionCipher, this);
                    }, LazyThreadSafetyMode.ExecutionAndPublication);
        }

        public override void SetNoAccess(IntPtr pointer, ulong length)
        {
            Check.Zero(LibcLP64.mprotect(pointer, length, GetProtNoAccess()), "mprotect(PROT_NONE)");
        }

        public override void SetReadAccess(IntPtr pointer, ulong length)
        {
            Check.Zero(LibcLP64.mprotect(pointer, length, GetProtRead()), "mprotect(PROT_READ)");
        }

        public override void SetReadWriteAccess(IntPtr pointer, ulong length)
        {
            Check.Zero(
                LibcLP64.mprotect(
                    pointer,
                    length,
                    GetProtReadWrite()),
                "mprotect(PROT_READ|PROT_WRITE)");
        }

        public override IntPtr PageAlloc(ulong length)
        {
            // Some platforms may require fd to be -1 even if using anonymous
            IntPtr ptr = LibcLP64.mmap(
                IntPtr.Zero, length, GetProtReadWrite(), GetPrivateAnonymousFlags(), -1, 0);

            Check.IntPtr(ptr, "mmap");

            return ptr;
        }

        public override void PageFree(IntPtr pointer, ulong length)
        {
            Check.Zero(LibcLP64.munmap(pointer, length), "munmap");
        }

        public override void CopyMemory(IntPtr source, IntPtr dest, ulong length)
        {
            LibcLP64.memcpy(dest, source, length);
        }

        public override void LockMemory(IntPtr pointer, ulong length)
        {
            Check.Zero(LibcLP64.mlock(pointer, length), "mlock");
        }

        public override void UnlockMemory(IntPtr pointer, ulong length)
        {
            Check.Zero(LibcLP64.munlock(pointer, length), "munlock");
        }

        public override ulong GetMemoryLockLimit()
        {
            LibcLP64.getrlimit(GetMemLockLimit(), out var rlim);
            return (ulong)(rlim.rlim_max == rlimit.UNLIMITED ? 0 : (long)rlim.rlim_max);
        }

        public override void SetMemoryLockLimit(ulong limit)
        {
            rlimit rlim = new rlimit { rlim_cur = 0, rlim_max = limit == 0 ? rlimit.UNLIMITED : limit };
            Check.Result(LibcLP64.setrlimit(GetMemLockLimit(), rlim), 0, "setrlimit");
        }

        public override ulong GetEncryptedMemoryBlockSize()
        {
            return (ulong)openSSLCryptProtectMemory.Value.GetBlockSize();
        }

        public override void ProcessEncryptMemory(IntPtr pointer, ulong length)
        {
            openSSLCryptProtectMemory.Value.CryptProtectMemory(pointer, (int)length);
        }

        public override void ProcessDecryptMemory(IntPtr pointer, ulong length)
        {
            openSSLCryptProtectMemory.Value.CryptUnprotectMemory(pointer, (int)length);
        }

        public override bool AreCoreDumpsGloballyDisabled()
        {
            return globallyDisabledCoreDumps;
        }

        public override bool DisableCoreDumpGlobally()
        {
            try
            {
                Check.Zero(
                    LibcLP64.setrlimit(
                        GetRlimitCoreResource(),
                        rlimit.Zero()),
                    "setrlimit(RLIMIT_CORE)");
                globallyDisabledCoreDumps = true;
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        // These flags are platform specific in their integer values
        internal abstract int GetRlimitCoreResource();

        internal abstract int GetProtReadWrite();

        internal abstract int GetProtRead();

        internal abstract int GetProtNoAccess();

        internal abstract int GetPrivateAnonymousFlags();

        internal abstract int GetMemLockLimit();
    }
}

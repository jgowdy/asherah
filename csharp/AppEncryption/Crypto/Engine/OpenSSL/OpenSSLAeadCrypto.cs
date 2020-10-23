using System;
using System.Runtime.InteropServices;
using GoDaddy.Asherah.Crypto.Envelope;
using GoDaddy.Asherah.Crypto.Keys;
using GoDaddy.Asherah.PlatformNative.OpenSSL;
using Microsoft.Extensions.Configuration;

namespace GoDaddy.Asherah.Crypto.Engine.OpenSSL
{
    public class OpenSSLAeadCrypto : AeadEnvelopeCrypto, IDisposable
    {
        private readonly IOpenSSLCrypto crypto;
        private readonly ulong blockSize;
        private readonly ulong ivSize;
        private readonly IntPtr cipher;
        private readonly IntPtr ctx;

        public OpenSSLAeadCrypto(IConfiguration configuration)
            : base(configuration)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                crypto = new OpenSSLCryptoWindows(configuration);
            }
            else
            {
                crypto = new OpenSSLCryptoLibc(configuration);
            }

            cipher = crypto.EVP_get_cipherbyname("aes-256-gcm");
            blockSize = (ulong)crypto.EVP_CIPHER_block_size(cipher);
            ivSize = (ulong)crypto.EVP_CIPHER_iv_length(cipher);
            ctx = crypto.EVP_CIPHER_CTX_new();
        }

        ~OpenSSLAeadCrypto()
        {
            Dispose(false);
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        public override byte[] Encrypt(byte[] input, CryptoKey key)
        {
            return key.WithKey((ptr, len) =>
            {
                // TODO: Deal with the iv
                var iv = IntPtr.Zero;
                var result = crypto.EVP_EncryptInit_ex(ctx, cipher, IntPtr.Zero, ptr, iv);
                crypto.CheckResult(result, 1, "EVP_EncryptInit_ex");

                var handle = GCHandle.Alloc(input, GCHandleType.Pinned);
                try
                {
                    var outPtr = crypto.CRYPTO_secure_malloc(len + blockSize);
                    try
                    {
                        result = crypto.EVP_EncryptUpdate(
                            ctx,
                            outPtr,
                            out int outLength,
                            handle.AddrOfPinnedObject(),
                            input.Length);

                        crypto.CheckResult(result, 1, "EVP_EncryptUpdate");
                        var finalPtr = IntPtr.Add(outPtr, outLength);
                        result = crypto.EVP_EncryptFinal_ex(ctx, finalPtr, out outLength);
                        crypto.CheckResult(result, 1, "EVP_EncryptFinal_ex");
                        var outputBytes = new byte[outLength];
                        Marshal.Copy(outPtr, outputBytes, 0, outLength);
                        return outputBytes;
                    }
                    finally
                    {
                        crypto.CRYPTO_secure_clear_free(outPtr, len + blockSize);
                    }
                }
                finally
                {
                    handle.Free();
                }
            });
        }

        public override byte[] Decrypt(byte[] input, CryptoKey key)
        {
            return key.WithKey((ptr, len) =>
            {
                // TODO: Deal with the iv
                var iv = IntPtr.Zero;

                var nonceSizeBytes = (ulong)(GetNonceSizeBits() / 8);
                IntPtr noncePtr = crypto.CRYPTO_secure_malloc(nonceSizeBytes);
                crypto.RAND_bytes(noncePtr, (int)nonceSizeBytes);

                var result = crypto.EVP_DecryptInit_ex(ctx, cipher, IntPtr.Zero, ptr, iv);
                crypto.CheckResult(result, 1, "EVP_DecryptInit_ex");

                var handle = GCHandle.Alloc(input, GCHandleType.Pinned);
                try
                {
                    var outPtr = crypto.CRYPTO_secure_malloc(len + blockSize);
                    try
                    {
                        result = crypto.EVP_DecryptUpdate(
                            ctx,
                            outPtr,
                            out int outLength,
                            handle.AddrOfPinnedObject(),
                            input.Length);

                        crypto.CheckResult(result, 1, "EVP_DecryptUpdate");
                        var finalPtr = IntPtr.Add(outPtr, outLength);
                        result = crypto.EVP_DecryptFinal_ex(ctx, finalPtr, out outLength);
                        crypto.CheckResult(result, 1, "EVP_DecryptFinal_ex");

                        var outputBytes = new byte[outLength];
                        Marshal.Copy(outPtr, outputBytes, 0, outLength);
                        return outputBytes;
                    }
                    finally
                    {
                        crypto.CRYPTO_secure_clear_free(outPtr, len + blockSize);
                    }
                }
                finally
                {
                    handle.Free();
                }
            });
        }

        protected internal override int GetKeySizeBits()
        {
            return crypto.EVP_CIPHER_key_length(cipher);
        }

        protected virtual void Dispose(bool disposing)
        {
            ReleaseUnmanagedResources();
            if (disposing)
            {
            }
        }

        protected override int GetNonceSizeBits()
        {
            return crypto.EVP_CIPHER_iv_length(cipher);
        }

        private void ReleaseUnmanagedResources()
        {
            crypto.EVP_CIPHER_CTX_free(ctx);
        }
    }
}

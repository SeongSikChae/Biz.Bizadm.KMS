using Microsoft.Extensions.ObjectPool;
using System.Security.Cryptography;

namespace Biz.Bizadm.KMS.Cipher
{
    internal sealed class AesGcmPolicy(byte[] key) : PooledObjectPolicy<AesGcm>
    {
        public override AesGcm Create()
        {
            return new AesGcm(key, 16);
        }

        public override bool Return(AesGcm obj)
        {
            return true;
        }
    }

    public sealed class AesGcmKekCipher : IKekCipher
    {
        private const int NonceSize = 12;
        private const int TagSize = 16;

        private readonly byte[] key;
        private readonly ObjectPool<AesGcm> aesGcmPool;

        private bool disposedValue;

        public AesGcmKekCipher(byte[] password, byte[] salt, int iterationCount)
        {
            key = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterationCount, HashAlgorithmName.SHA256, 32);
            DefaultObjectPoolProvider provider = new DefaultObjectPoolProvider
            {
                MaximumRetained = Environment.ProcessorCount * 2
            };
            aesGcmPool = provider.Create(new AesGcmPolicy(key));
        }

        public byte[] Encrypt(byte[] plain)
        {
            if (disposedValue)
                throw new ObjectDisposedException(nameof(AesGcmKekCipher));

            byte[] output = new byte[NonceSize + plain.Length + TagSize];
            Span<byte> nonce = output.AsSpan(0, NonceSize);
            Span<byte> cipher = output.AsSpan(NonceSize, plain.Length);
            Span<byte> tag = output.AsSpan(NonceSize + plain.Length, TagSize);

            RandomNumberGenerator.Fill(nonce);

            AesGcm aesGcm = aesGcmPool.Get();
            try
            {
                aesGcm.Encrypt(nonce, plain, cipher, tag);
                return output;
            } 
            finally
            {
                aesGcmPool.Return(aesGcm);
            }            
        }

        public byte[] Decrypt(byte[] encrypted)
        {
            if (disposedValue)
                throw new ObjectDisposedException(nameof(AesGcmKekCipher));

            if (encrypted.Length < NonceSize + TagSize)
                throw new ArgumentException("Invalid encrypted data.", nameof(encrypted));

            int cipherLength = encrypted.Length - NonceSize - TagSize;
            ReadOnlySpan<byte> nonce = encrypted.AsSpan(0, NonceSize);
            ReadOnlySpan<byte> cipher = encrypted.AsSpan(NonceSize, cipherLength);
            ReadOnlySpan<byte> tag = encrypted.AsSpan(NonceSize + cipherLength, TagSize);

            AesGcm aesGcm = aesGcmPool.Get();
            byte[] plain = new byte[cipherLength];
            try
            {
                aesGcm.Decrypt(nonce, cipher, tag, plain);
                return plain;
            }
            catch
            {
                CryptographicOperations.ZeroMemory(plain);
                throw;
            }
            finally
            {
                aesGcmPool.Return(aesGcm);
            }
        }

        public void Dispose()
        {
            if (disposedValue)
                return;

            disposedValue = true;
            CryptographicOperations.ZeroMemory(key);
        }
    }
}

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

    /// <summary>
    /// AES-256-GCM 기반 암·복호화 공통 구현.
    /// 출력 형식은 <c>nonce(12) || cipher || tag(16)</c>이다.
    /// </summary>
    public abstract class AbstractAesGcmCipher : ICipher
    {
        private const int NonceSize = 12;
        private const int TagSize = 16;

        /// <summary>
        /// AES-GCM에 사용하는 키 바이트.
        /// </summary>
        protected readonly byte[] key;
        private readonly ObjectPool<AesGcm> aesGcmPool;

        private bool disposedValue;

        /// <summary>
        /// 지정한 키로 AES-GCM 암호를 초기화한다.
        /// </summary>
        /// <param name="key">AES-GCM 키.</param>
        protected AbstractAesGcmCipher(byte[] key)
        {
            this.key = key;
            DefaultObjectPoolProvider provider = new DefaultObjectPoolProvider
            {
                MaximumRetained = Environment.ProcessorCount * 2
            };
            aesGcmPool = provider.Create(new AesGcmPolicy(key));
        }

        /// <inheritdoc />
        public byte[] Encrypt(byte[] plain)
        {
            ObjectDisposedException.ThrowIf(disposedValue, this);

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

        /// <inheritdoc />
        public byte[] Decrypt(byte[] encrypted)
        {
            ObjectDisposedException.ThrowIf(disposedValue, this);

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

        /// <inheritdoc />
        public void Dispose()
        {
            if (disposedValue)
                return;

            disposedValue = true;

            if (aesGcmPool is IDisposable disposable)
                disposable.Dispose();

            CryptographicOperations.ZeroMemory(key);
            GC.SuppressFinalize(this);
        }
    }
}

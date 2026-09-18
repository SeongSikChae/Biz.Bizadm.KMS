namespace Biz.Bizadm.KMS.Cipher
{
    /// <summary>
    /// 데이터 암호화 키(DEK)로 데이터를 암·복호화하는 암호 인터페이스.
    /// </summary>
    public interface IDekCipher : ICipher
    {
        /// <summary>
        /// 암·복호화 없이 입력 바이트를 그대로 통과시키는 Null DEK 인스턴스.
        /// </summary>
        static IDekCipher Null { get; } = NullDekCipher.Instance;
    }

    internal sealed class NullDekCipher : IDekCipher
    {
        public static NullDekCipher Instance { get; } = new();

        private NullDekCipher()
        {
        }

        public byte[] Encrypt(byte[] plain)
        {
            return plain;
        }

        public async Task<byte[]> EncryptAsync(byte[] plain, CancellationToken cancellationToken = default)
        {
            return plain;
        }

        public byte[] Decrypt(byte[] encrypted)
        {
            return encrypted;
        }

        public async Task<byte[]> DecryptAsync(byte[] encrypted, CancellationToken cancellationToken = default)
        {
            return encrypted;
        }

        public void Dispose()
        {
        }
    }
}

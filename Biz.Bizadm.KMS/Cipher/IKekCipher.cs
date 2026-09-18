namespace Biz.Bizadm.KMS.Cipher
{
    /// <summary>
    /// 키 암호화 키(KEK)로 키 물질을 wrap·unwrap하는 암호 인터페이스.
    /// </summary>
    public interface IKekCipher : ICipher
    {
        /// <summary>
        /// 이 KEK 인스턴스를 식별하는 ID. wrap된 DEK에 함께 저장된다.
        /// </summary>
        string KeyId { get; }

        /// <summary>
        /// wrap/unwrap 없이 입력 바이트를 그대로 통과시키는 Null KEK 인스턴스.
        /// </summary>
        static IKekCipher Null { get; } = NullKekCipher.Instance;
    }

    internal sealed class NullKekCipher : IKekCipher
    {
        public static NullKekCipher Instance { get; } = new();

        private NullKekCipher()
        {
        }

        // Wrapped DEK envelope은 비어 있지 않은 KeyId를 요구한다.
        public string KeyId => "null";

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

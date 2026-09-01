using System.Security.Cryptography;

namespace Biz.Bizadm.KMS.Cipher
{
    /// <summary>
    /// PBKDF2-SHA256으로 유도한 키를 사용하는 소프트웨어 AES-GCM KEK 암호.
    /// </summary>
    public sealed class AesGcmKekCipher : AbstractAesGcmCipher, IKekCipher
    {
        /// <inheritdoc />
        public string KeyId { get; }

        /// <summary>
        /// 자격 증명과 salt·반복 횟수로 KEK 암호를 생성한다.
        /// </summary>
        /// <param name="credentialProvider">KEK 패스워드 제공자.</param>
        /// <param name="salt">PBKDF2 salt.</param>
        /// <param name="iterationCount">PBKDF2 반복 횟수.</param>
        /// <returns>생성된 <see cref="AesGcmKekCipher"/>.</returns>
        public static AesGcmKekCipher Create(IKekCredentialProvider credentialProvider, byte[] salt, int iterationCount)
        {
            byte[] password = credentialProvider.GetPassword();
            try
            {
                return new AesGcmKekCipher(password, salt, iterationCount);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(password);
            }
        }

        /// <summary>
        /// 새 salt·자격 증명으로 로테이션된 KEK 인스턴스를 생성한다.
        /// </summary>
        /// <param name="newCredential">새 KEK 패스워드 제공자.</param>
        /// <param name="newSalt">새 PBKDF2 salt.</param>
        /// <param name="iterationCount">PBKDF2 반복 횟수.</param>
        /// <returns>생성된 <see cref="AesGcmKekCipher"/>.</returns>
        public static AesGcmKekCipher CreateRotated(
            IKekCredentialProvider newCredential,
            byte[] newSalt,
            int iterationCount)
            => Create(newCredential, newSalt, iterationCount);

        private AesGcmKekCipher(byte[] password, byte[] salt, int iterationCount)
            : base(DeriveKey(password, salt, iterationCount, out string keyId))
        {
            KeyId = keyId;
        }

        private static byte[] DeriveKey(byte[] password, byte[] salt, int iterationCount, out string keyId)
        {
            byte[] key = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterationCount, HashAlgorithmName.SHA256, 32);
            keyId = CreateKeyId(key);
            return key;
        }

        private static string CreateKeyId(ReadOnlySpan<byte> keyMaterial)
            => $"aesgcm:{Convert.ToHexString(SHA256.HashData(keyMaterial)).ToLowerInvariant()}";

        /// <inheritdoc />
        public override Task<byte[]> EncryptAsync(byte[] plain, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(Encrypt(plain));
        }

        /// <inheritdoc />
        public override Task<byte[]> DecryptAsync(byte[] encrypted, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(Decrypt(encrypted));
        }
    }
}

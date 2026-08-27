using System.Security.Cryptography;

namespace Biz.Bizadm.KMS.Cipher
{
    /// <summary>
    /// PBKDF2-SHA256으로 유도한 키를 사용하는 소프트웨어 AES-GCM KEK 암호.
    /// </summary>
    public sealed class AesGcmKekCipher : AbstractAesGcmCipher, IKekCipher
    {
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

        private AesGcmKekCipher(byte[] password, byte[] salt, int iterationCount) : base(Rfc2898DeriveBytes.Pbkdf2(password, salt, iterationCount, HashAlgorithmName.SHA256, 32))
        {
        }
    }
}

namespace Biz.Bizadm.KMS.Cipher
{
    /// <summary>
    /// <see cref="AesGcmKekCipher"/> 기반 KEK Manager.
    /// </summary>
    public sealed class AesGcmKekManager : KekManagerBase
    {
        private AesGcmKekManager(AesGcmKekCipher initial) : base(initial)
        {
        }

        /// <summary>
        /// 자격 증명과 salt·반복 횟수로 Manager를 생성한다.
        /// </summary>
        /// <param name="credentialProvider">KEK 패스워드 제공자.</param>
        /// <param name="salt">PBKDF2 salt.</param>
        /// <param name="iterationCount">PBKDF2 반복 횟수.</param>
        /// <returns>생성된 <see cref="AesGcmKekManager"/>.</returns>
        public static AesGcmKekManager Create(IKekCredentialProvider credentialProvider, byte[] salt, int iterationCount)
        {
            AesGcmKekCipher cipher = AesGcmKekCipher.Create(credentialProvider, salt, iterationCount);
            return new AesGcmKekManager(cipher);
        }

        /// <summary>
        /// 새 salt·자격 증명으로 KEK를 로테이션하고 Current를 교체한다.
        /// </summary>
        /// <param name="newCredential">새 KEK 패스워드 제공자.</param>
        /// <param name="newSalt">새 PBKDF2 salt.</param>
        /// <param name="iterationCount">PBKDF2 반복 횟수.</param>
        /// <returns>새 Current KEK.</returns>
        public AesGcmKekCipher Rotate(IKekCredentialProvider newCredential, byte[] newSalt, int iterationCount)
        {
            AesGcmKekCipher rotated = AesGcmKekCipher.CreateRotated(newCredential, newSalt, iterationCount);
            SetCurrent(rotated);
            return rotated;
        }

        /// <summary>
        /// 저장된 salt·자격 증명으로 기존 KEK를 로드하여 registry에 등록한다. <see cref="IKekManager.Current"/>는 바꾸지 않는다.
        /// </summary>
        /// <param name="credentialProvider">KEK 패스워드 제공자.</param>
        /// <param name="salt">PBKDF2 salt.</param>
        /// <param name="iterationCount">PBKDF2 반복 횟수.</param>
        /// <returns>등록된 KEK.</returns>
        public AesGcmKekCipher LoadKey(IKekCredentialProvider credentialProvider, byte[] salt, int iterationCount)
        {
            AesGcmKekCipher cipher = AesGcmKekCipher.Create(credentialProvider, salt, iterationCount);
            Register(cipher);
            return cipher;
        }
    }
}

using Biz.Bizadm.KMS.Cipher.Tpm;
using Tpm2Lib;

namespace Biz.Bizadm.KMS.Cipher.Tpm
{
    /// <summary>
    /// <see cref="TpmKekCipher"/> 기반 KEK Manager.
    /// </summary>
    public sealed class TpmKekManager : KekManagerBase
    {
        private readonly Tpm2Device device;
        private readonly IKekCredentialProvider credentialProvider;

        private TpmKekManager(Tpm2Device device, IKekCredentialProvider credentialProvider, TpmKekCipher initial)
            : base(initial)
        {
            this.device = device;
            this.credentialProvider = credentialProvider;
        }

        /// <summary>
        /// TPM 디바이스와 자격 증명·KEK blob으로 Manager를 생성한다.
        /// </summary>
        /// <param name="device">연결된 TPM 디바이스.</param>
        /// <param name="credentialProvider">SRK 유도용 패스워드 제공자.</param>
        /// <param name="kekBlobFile">KEK blob 저장·로드 파일.</param>
        /// <param name="options">wrap 모드·RSA 키 옵션.</param>
        /// <returns>생성된 <see cref="TpmKekManager"/>.</returns>
        public static TpmKekManager Create(
            Tpm2Device device,
            IKekCredentialProvider credentialProvider,
            FileInfo kekBlobFile,
            TpmKekOptions? options = null)
        {
            TpmKekCipher cipher = TpmKekCipher.Create(device, credentialProvider, kekBlobFile, options);
            return new TpmKekManager(device, credentialProvider, cipher);
        }

        /// <summary>
        /// 새 KEK blob으로 KEK를 로테이션하고 Current를 교체한다.
        /// </summary>
        /// <param name="newKekBlobFile">새 KEK blob 저장 파일.</param>
        /// <param name="options">wrap 모드·RSA 키 옵션. null이면 현재 옵션을 재사용한다.</param>
        /// <returns>새 Current KEK.</returns>
        public TpmKekCipher Rotate(FileInfo newKekBlobFile, TpmKekOptions? options = null)
        {
            TpmKekCipher current = (TpmKekCipher)Current;
            TpmKekCipher rotated = current.Rotate(newKekBlobFile, options);
            SetCurrent(rotated);
            return rotated;
        }
    }
}

namespace Biz.Bizadm.KMS.Cipher.Tpm
{
    /// <summary>
    /// TPM KEK wrap/unwrap 모드.
    /// </summary>
    public enum TpmKekWrapMode
    {
        /// <summary>
        /// TPM 내부 AES-256-CFB 대칭 KEK.
        /// </summary>
        Aes256Cfb,

        /// <summary>
        /// TPM 내부 RSA-OAEP-256 비대칭 KEK.
        /// </summary>
        RsaOaep256,
    }

    /// <summary>
    /// TPM KEK wrap/unwrap 및 RSA 키 생성 옵션.
    /// </summary>
    public sealed class TpmKekOptions
    {
        /// <summary>
        /// DEK wrap에 사용할 모드. 기본 <see cref="TpmKekWrapMode.Aes256Cfb"/>.
        /// </summary>
        public TpmKekWrapMode WrapMode { get; init; } = TpmKekWrapMode.Aes256Cfb;

        /// <summary>
        /// RSA KEK 키 크기(비트). 기본 2048.
        /// </summary>
        public int RsaKeySize { get; init; } = 2048;
    }
}

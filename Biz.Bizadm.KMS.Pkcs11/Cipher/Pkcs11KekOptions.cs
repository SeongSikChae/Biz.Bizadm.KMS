using Net.Pkcs11Interop.Common;

namespace Biz.Bizadm.KMS.Pkcs11.Cipher
{
    /// <summary>
    /// PKCS#11 KEK wrap/unwrap 메커니즘 및 RSA 키 생성 옵션.
    /// </summary>
    public sealed class Pkcs11KekOptions
    {
        /// <summary>
        /// RSA 키 크기(비트). 기본 4096.
        /// </summary>
        public int RsaKeySize { get; init; } = 4096;

        /// <summary>
        /// DEK wrap에 사용할 메커니즘. 기본 <see cref="CKM.CKM_RSA_PKCS_OAEP"/>.
        /// </summary>
        public CKM WrapMechanism { get; init; } = CKM.CKM_RSA_PKCS_OAEP;

        /// <summary>
        /// OAEP 해시 알고리즘. 기본 SHA-256.
        /// </summary>
        public CKM OaepHashAlgorithm { get; init; } = CKM.CKM_SHA256;

        /// <summary>
        /// OAEP MGF. 기본 MGF1-SHA256.
        /// </summary>
        public CKG OaepMgf { get; init; } = CKG.CKG_MGF1_SHA256;

        /// <summary>
        /// OAEP label. null이면 빈 label.
        /// </summary>
        public byte[]? OaepLabel { get; init; }
    }
}

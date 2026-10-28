using Net.Pkcs11Interop.Common;

namespace Biz.Bizadm.KMS.NetFramework.Cipher.Pkcs11;

public sealed class Pkcs11KekOptions
{
    public int RsaKeySize { get; set; } = 4096;

    public CKM WrapMechanism { get; set; } = CKM.CKM_RSA_PKCS_OAEP;

    public CKM OaepHashAlgorithm { get; set; } = CKM.CKM_SHA256;

    public CKG OaepMgf { get; set; } = CKG.CKG_MGF1_SHA256;

    public byte[]? OaepLabel { get; set; }
}

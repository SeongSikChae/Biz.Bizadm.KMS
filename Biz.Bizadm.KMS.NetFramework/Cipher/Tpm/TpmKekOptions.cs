namespace Biz.Bizadm.KMS.NetFramework.Cipher.Tpm;

public enum TpmKekWrapMode
{
    Aes256Cfb,
    RsaOaep256
}

public sealed class TpmKekOptions
{
    public TpmKekWrapMode WrapMode { get; set; } = TpmKekWrapMode.Aes256Cfb;

    public int RsaKeySize { get; set; } = 2048;
}

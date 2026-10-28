namespace Biz.Bizadm.KMS.NetFramework.Cipher;

/// <summary>
/// Encrypts and decrypts application data using a data-encryption key (DEK).
/// </summary>
public interface IDekCipher : ICipher
{
}

public static class DekCipherFactory
{
    public static IDekCipher CreateNull() => NullDekCipher.Instance;
}

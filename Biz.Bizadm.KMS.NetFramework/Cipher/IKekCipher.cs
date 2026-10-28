namespace Biz.Bizadm.KMS.NetFramework.Cipher;

/// <summary>
/// Wraps and unwraps key material using a key-encryption key (KEK).
/// </summary>
public interface IKekCipher : ICipher
{
    string KeyId { get; }

    byte[] RewrapDek(IKekCipher source, byte[] wrappedDek);

    Task<byte[]> RewrapDekAsync(
        IKekCipher source,
        byte[] wrappedDek,
        CancellationToken cancellationToken = default);
}

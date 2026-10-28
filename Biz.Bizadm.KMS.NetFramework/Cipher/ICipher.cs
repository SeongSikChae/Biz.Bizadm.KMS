namespace Biz.Bizadm.KMS.NetFramework.Cipher;

/// <summary>
/// Byte-array based synchronous and asynchronous encryption contract.
/// </summary>
public interface ICipher : IDisposable
{
    byte[] Encrypt(byte[] plain);

    Task<byte[]> EncryptAsync(byte[] plain, CancellationToken cancellationToken = default);

    byte[] Decrypt(byte[] encrypted);

    Task<byte[]> DecryptAsync(byte[] encrypted, CancellationToken cancellationToken = default);
}

namespace Biz.Bizadm.KMS.NetFramework.Cipher;

internal sealed class NullDekCipher : IDekCipher
{
    internal static NullDekCipher Instance { get; } = new NullDekCipher();

    private NullDekCipher()
    {
    }

    public byte[] Encrypt(byte[] plain)
    {
        if (plain is null) throw new ArgumentNullException(nameof(plain));
        return plain;
    }

    public Task<byte[]> EncryptAsync(byte[] plain, CancellationToken cancellationToken = default)
    {
        if (plain is null) throw new ArgumentNullException(nameof(plain));
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(plain);
    }

    public byte[] Decrypt(byte[] encrypted)
    {
        if (encrypted is null) throw new ArgumentNullException(nameof(encrypted));
        return encrypted;
    }

    public Task<byte[]> DecryptAsync(byte[] encrypted, CancellationToken cancellationToken = default)
    {
        if (encrypted is null) throw new ArgumentNullException(nameof(encrypted));
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(encrypted);
    }

    public void Dispose()
    {
    }
}

namespace Biz.Bizadm.KMS.NetFramework.Cipher;

/// <summary>
/// Wraps <see cref="IDekCipher"/> with a UTF-8 string API and prefixed ciphertext format.
/// </summary>
public interface IDekCipherService : IDisposable
{
    bool StartsWithFromPrefix(string input);

    string Encrypt(string plain);

    Task<string> EncryptAsync(string plain, CancellationToken cancellationToken = default);

    string Decrypt(string encrypted);

    Task<string> DecryptAsync(string encrypted, CancellationToken cancellationToken = default);
}

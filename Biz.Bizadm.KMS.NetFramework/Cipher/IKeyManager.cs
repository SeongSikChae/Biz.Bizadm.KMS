namespace Biz.Bizadm.KMS.NetFramework.Cipher;

/// <summary>
/// Loads and manages the active data-encryption key.
/// </summary>
public interface IKeyManager : IDisposable
{
    IDekCipher Load();

    Task<IDekCipher> LoadAsync(CancellationToken cancellationToken = default);
}

namespace Biz.Bizadm.KMS.NetFramework.Cipher;

/// <summary>
/// Provides password bytes used to derive or load a KEK.
/// </summary>
public interface IKekCredentialProvider
{
    byte[] GetPassword();

    Task<byte[]> GetPasswordAsync(CancellationToken cancellationToken = default);
}

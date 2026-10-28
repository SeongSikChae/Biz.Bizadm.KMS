namespace Biz.Bizadm.KMS.NetFramework.Cipher;

/// <summary>
/// Stores and retrieves KEK password bytes from Windows Credential Manager.
/// </summary>
public interface IWindowsKekCredentialStore : IKekCredentialProvider
{
    string Service { get; }

    string Account { get; }

    void StorePassword(byte[] password);

    bool RemovePassword();
}

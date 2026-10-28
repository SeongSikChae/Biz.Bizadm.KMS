namespace Biz.Bizadm.KMS.NetFramework.Cipher;

/// <summary>
/// Default Windows Credential Manager keys used by the independent net48 provider.
/// Values match the existing net10 credential defaults for shared OS entries.
/// </summary>
public static class WindowsKekCredentialDefaults
{
    public const string Namespace = "Biz.Bizadm.KMS";
    public const string Service = "bizadm-kms://kek";
    public const string Account = "default";
}

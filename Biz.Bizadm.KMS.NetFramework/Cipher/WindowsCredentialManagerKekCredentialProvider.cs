using System.Text;
using GitCredentialManager;

namespace Biz.Bizadm.KMS.NetFramework.Cipher;

/// <summary>
/// Independent Windows Credential Manager-backed KEK credential provider for net48.
/// Password bytes are stored as Base64, matching the existing net10 Credentials runtime.
/// </summary>
public sealed class WindowsCredentialManagerKekCredentialProvider : IWindowsKekCredentialStore
{
    private readonly ICredentialStore store;

    private WindowsCredentialManagerKekCredentialProvider(ICredentialStore store, string service, string account)
    {
        this.store = store ?? throw new ArgumentNullException(nameof(store));
        Service = service;
        Account = account;
    }

    public string Service { get; }

    public string Account { get; }

    public static WindowsCredentialManagerKekCredentialProvider Create(
        string service = WindowsKekCredentialDefaults.Service,
        string account = WindowsKekCredentialDefaults.Account,
        string? @namespace = WindowsKekCredentialDefaults.Namespace)
    {
        if (Environment.OSVersion.Platform != PlatformID.Win32NT)
        {
            throw new PlatformNotSupportedException(
                "WindowsCredentialManagerKekCredentialProvider requires Windows.");
        }

        if (string.IsNullOrWhiteSpace(service)) throw new ArgumentException("Service is required.", nameof(service));
        if (string.IsNullOrWhiteSpace(account)) throw new ArgumentException("Account is required.", nameof(account));

        if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable("GCM_CREDENTIAL_STORE")))
        {
            Environment.SetEnvironmentVariable("GCM_CREDENTIAL_STORE", "wincredman");
        }

        string credentialNamespace = string.IsNullOrWhiteSpace(@namespace)
            ? WindowsKekCredentialDefaults.Namespace
            : @namespace!;

        ICredentialStore store = CredentialManager.Create(credentialNamespace);
        return new WindowsCredentialManagerKekCredentialProvider(store, service, account);
    }

    public byte[] GetPassword()
    {
        ICredential? credential = store.Get(Service, Account);
        if (credential is null || string.IsNullOrEmpty(credential.Password))
        {
            throw new InvalidOperationException(
                $"KEK credential not found. Service='{Service}', Account='{Account}'.");
        }

        return DecodePassword(credential.Password);
    }

    public Task<byte[]> GetPasswordAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(GetPassword());
    }

    public void StorePassword(byte[] password)
    {
        if (password is null) throw new ArgumentNullException(nameof(password));
        if (password.Length == 0) throw new ArgumentException("Password must not be empty.", nameof(password));
        store.AddOrUpdate(Service, Account, Convert.ToBase64String(password));
    }

    public bool RemovePassword()
        => store.Remove(Service, Account);

    private static byte[] DecodePassword(string encoded)
    {
        try
        {
            return Convert.FromBase64String(encoded);
        }
        catch (FormatException)
        {
            return Encoding.UTF8.GetBytes(encoded);
        }
    }
}

using Azure;
using Azure.Core;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;

namespace Biz.Bizadm.KMS.NetFramework.Cipher;

/// <summary>
/// Independent Azure Key Vault RSA-OAEP-256 KEK for net48.
/// KeyId format matches net10: azurekv:{keyName}:{version}.
/// </summary>
public sealed class AzureKeyVaultKekCipher : IKekCipher
{
    private readonly Uri uri;
    private readonly TokenCredential credential;
    private readonly KeyClient client;
    private readonly string keyName;
    private CryptographyClient? cryptographyClient;
    private string? keyVersion;

    public string KeyId => "azurekv:" + keyName + ":" + keyVersion;

    private AzureKeyVaultKekCipher(Uri uri, TokenCredential credential, string keyName)
    {
        this.uri = uri ?? throw new ArgumentNullException(nameof(uri));
        this.credential = credential ?? throw new ArgumentNullException(nameof(credential));
        if (string.IsNullOrWhiteSpace(keyName)) throw new ArgumentException("Key name is required.", nameof(keyName));
        this.keyName = keyName;
        client = new KeyClient(uri, credential);
    }

    public static async Task<AzureKeyVaultKekCipher> CreateAsync(
        Uri uri,
        TokenCredential credential,
        string name,
        string? version = null,
        CancellationToken cancellationToken = default)
    {
        AzureKeyVaultKekCipher cipher = new AzureKeyVaultKekCipher(uri, credential, name);
        await cipher.InitializeAsync(name, version, cancellationToken).ConfigureAwait(false);
        return cipher;
    }

    public async Task<AzureKeyVaultKekCipher> RotateAsync(CancellationToken cancellationToken = default)
    {
        CreateRsaKeyOptions options = new CreateRsaKeyOptions(keyName)
        {
            KeySize = 4096,
            Enabled = true
        };
        options.KeyOperations.Add(KeyOperation.WrapKey);
        options.KeyOperations.Add(KeyOperation.UnwrapKey);

        KeyVaultKey vaultKey = await client.CreateRsaKeyAsync(options, cancellationToken).ConfigureAwait(false);
        AzureKeyVaultKekCipher rotated = new AzureKeyVaultKekCipher(uri, credential, keyName);
        rotated.keyVersion = vaultKey.Properties.Version;
        rotated.cryptographyClient = new CryptographyClient(vaultKey.Id, credential);
        return rotated;
    }

    public byte[] Encrypt(byte[] plain)
    {
        if (cryptographyClient is null) throw new InvalidOperationException("Cipher is not initialized.");
        if (plain is null) throw new ArgumentNullException(nameof(plain));
        return cryptographyClient.WrapKey(KeyWrapAlgorithm.RsaOaep256, plain).EncryptedKey;
    }

    public async Task<byte[]> EncryptAsync(byte[] plain, CancellationToken cancellationToken = default)
    {
        if (cryptographyClient is null) throw new InvalidOperationException("Cipher is not initialized.");
        if (plain is null) throw new ArgumentNullException(nameof(plain));
        WrapResult result = await cryptographyClient
            .WrapKeyAsync(KeyWrapAlgorithm.RsaOaep256, plain, cancellationToken)
            .ConfigureAwait(false);
        return result.EncryptedKey;
    }

    public byte[] Decrypt(byte[] encrypted)
    {
        if (cryptographyClient is null) throw new InvalidOperationException("Cipher is not initialized.");
        if (encrypted is null) throw new ArgumentNullException(nameof(encrypted));
        return cryptographyClient.UnwrapKey(KeyWrapAlgorithm.RsaOaep256, encrypted).Key;
    }

    public async Task<byte[]> DecryptAsync(byte[] encrypted, CancellationToken cancellationToken = default)
    {
        if (cryptographyClient is null) throw new InvalidOperationException("Cipher is not initialized.");
        if (encrypted is null) throw new ArgumentNullException(nameof(encrypted));
        UnwrapResult result = await cryptographyClient
            .UnwrapKeyAsync(KeyWrapAlgorithm.RsaOaep256, encrypted, cancellationToken)
            .ConfigureAwait(false);
        return result.Key;
    }

    public byte[] RewrapDek(IKekCipher source, byte[] wrappedDek)
        => KekCipherExtensions.RewrapDek(this, source, wrappedDek);

    public Task<byte[]> RewrapDekAsync(IKekCipher source, byte[] wrappedDek, CancellationToken cancellationToken = default)
        => KekCipherExtensions.RewrapDekAsync(this, source, wrappedDek, cancellationToken);

    public void Dispose()
    {
    }

    private async Task InitializeAsync(string name, string? version, CancellationToken cancellationToken)
    {
        KeyVaultKey vaultKey = string.IsNullOrEmpty(version)
            ? await GetOrCreateKeyAsync(name, cancellationToken).ConfigureAwait(false)
            : (await client.GetKeyAsync(name, version, cancellationToken).ConfigureAwait(false)).Value;

        keyVersion = vaultKey.Properties.Version;
        cryptographyClient = new CryptographyClient(vaultKey.Id, credential);
    }

    private async Task<KeyVaultKey> GetOrCreateKeyAsync(string name, CancellationToken cancellationToken)
    {
        try
        {
            return (await client.GetKeyAsync(name, cancellationToken: cancellationToken).ConfigureAwait(false)).Value;
        }
        catch (RequestFailedException e) when (IsKeyNotFound(e))
        {
            try
            {
                CreateRsaKeyOptions options = new CreateRsaKeyOptions(name)
                {
                    KeySize = 4096,
                    Enabled = true
                };
                options.KeyOperations.Add(KeyOperation.WrapKey);
                options.KeyOperations.Add(KeyOperation.UnwrapKey);
                return await client.CreateRsaKeyAsync(options, cancellationToken).ConfigureAwait(false);
            }
            catch (RequestFailedException createEx) when (createEx.Status == 409)
            {
                try
                {
                    return (await client.GetKeyAsync(name, cancellationToken: cancellationToken).ConfigureAwait(false)).Value;
                }
                catch (RequestFailedException getEx) when (IsKeyNotFound(getEx))
                {
                    RecoverDeletedKeyOperation operation = await client
                        .StartRecoverDeletedKeyAsync(name, cancellationToken)
                        .ConfigureAwait(false);
                    return (await operation.WaitForCompletionAsync(cancellationToken).ConfigureAwait(false)).Value;
                }
            }
        }
    }

    private static bool IsKeyNotFound(RequestFailedException e)
        => e.Status == 404 && string.Equals(e.ErrorCode, "KeyNotFound", StringComparison.Ordinal);
}

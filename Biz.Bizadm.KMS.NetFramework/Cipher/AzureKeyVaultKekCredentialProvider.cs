using System.Security.Cryptography;
using Azure;
using Azure.Core;
using Azure.Security.KeyVault.Secrets;

namespace Biz.Bizadm.KMS.NetFramework.Cipher;

/// <summary>
/// Independent Azure Key Vault Secret-backed password provider for net48.
/// Secrets are Base64-encoded 32-byte values, matching the net10 contract.
/// </summary>
public sealed class AzureKeyVaultKekCredentialProvider : IKekCredentialProvider
{
    private const int KeySize = 32;

    private readonly SecretClient client;
    private readonly string name;

    public AzureKeyVaultKekCredentialProvider(Uri uri, TokenCredential credential, string name)
    {
        if (uri is null) throw new ArgumentNullException(nameof(uri));
        if (credential is null) throw new ArgumentNullException(nameof(credential));
        if (string.IsNullOrWhiteSpace(name)) throw new ArgumentException("Secret name is required.", nameof(name));

        this.name = name;
        client = new SecretClient(uri, credential);
    }

    public byte[] GetPassword()
    {
        try
        {
            return DecodePassword(client.GetSecret(name).Value.Value);
        }
        catch (RequestFailedException e) when (IsSecretNotFound(e))
        {
            EnsureSecretCreated();
            return DecodePassword(client.GetSecret(name).Value.Value);
        }
    }

    public async Task<byte[]> GetPasswordAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            Response<KeyVaultSecret> response = await client
                .GetSecretAsync(name, cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            return DecodePassword(response.Value.Value);
        }
        catch (RequestFailedException e) when (IsSecretNotFound(e))
        {
            await EnsureSecretCreatedAsync(cancellationToken).ConfigureAwait(false);
            Response<KeyVaultSecret> response = await client
                .GetSecretAsync(name, cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            return DecodePassword(response.Value.Value);
        }
    }

    private void EnsureSecretCreated()
    {
        byte[] key = new byte[KeySize];
        using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(key);
        }

        try
        {
            try
            {
                client.SetSecret(new KeyVaultSecret(name, Convert.ToBase64String(key)));
            }
            catch (RequestFailedException e) when (e.Status == 409)
            {
                ResolveSecretConflict();
            }
        }
        finally
        {
            Array.Clear(key, 0, key.Length);
        }
    }

    private async Task EnsureSecretCreatedAsync(CancellationToken cancellationToken)
    {
        byte[] key = new byte[KeySize];
        using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(key);
        }

        try
        {
            try
            {
                await client
                    .SetSecretAsync(new KeyVaultSecret(name, Convert.ToBase64String(key)), cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (RequestFailedException e) when (e.Status == 409)
            {
                await ResolveSecretConflictAsync(cancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            Array.Clear(key, 0, key.Length);
        }
    }

    private void ResolveSecretConflict()
    {
        try
        {
            _ = client.GetSecret(name);
        }
        catch (RequestFailedException getEx) when (IsSecretNotFound(getEx))
        {
            RecoverDeletedSecretOperation operation = client.StartRecoverDeletedSecret(name);
            operation.WaitForCompletion();
        }
    }

    private async Task ResolveSecretConflictAsync(CancellationToken cancellationToken)
    {
        try
        {
            _ = await client.GetSecretAsync(name, cancellationToken: cancellationToken).ConfigureAwait(false);
        }
        catch (RequestFailedException getEx) when (IsSecretNotFound(getEx))
        {
            RecoverDeletedSecretOperation operation = await client
                .StartRecoverDeletedSecretAsync(name, cancellationToken)
                .ConfigureAwait(false);
            _ = await operation.WaitForCompletionAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    private static bool IsSecretNotFound(RequestFailedException e)
        => e.Status == 404 && string.Equals(e.ErrorCode, "SecretNotFound", StringComparison.Ordinal);

    private static byte[] DecodePassword(string password)
    {
        byte[] bytes;
        try
        {
            bytes = Convert.FromBase64String(password);
        }
        catch (FormatException ex)
        {
            throw new InvalidOperationException("KEK secret is not valid Base64.", ex);
        }

        if (bytes.Length != KeySize)
        {
            Array.Clear(bytes, 0, bytes.Length);
            throw new InvalidOperationException(
                "KEK secret must decode to " + KeySize + " bytes, but was " + bytes.Length + ".");
        }

        return bytes;
    }
}

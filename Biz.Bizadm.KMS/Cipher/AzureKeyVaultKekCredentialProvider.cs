using Azure;
using Azure.Core;
using Azure.Security.KeyVault.Secrets;
using System.Security.Cryptography;

namespace Biz.Bizadm.KMS.Cipher
{
    /// <summary>
    /// Azure Key Vault Secret에 보관된 KEK 패스워드를 제공한다.
    /// </summary>
    public sealed class AzureKeyVaultKekCredentialProvider : IKekCredentialProvider
    {
        private const int KeySize = 32;

        private readonly SecretClient client;
        private readonly string name;

        /// <summary>
        /// Key Vault URI·자격 증명·시크릿 이름으로 제공자를 만든다.
        /// </summary>
        public AzureKeyVaultKekCredentialProvider(Uri uri, TokenCredential credential, string name)
        {
            ArgumentNullException.ThrowIfNull(uri);
            ArgumentNullException.ThrowIfNull(credential);
            ArgumentException.ThrowIfNullOrWhiteSpace(name);

            this.name = name;
            client = new SecretClient(uri, credential);
        }

        /// <inheritdoc />
        public byte[] GetPassword()
        {
            try
            {
                return DecodePassword(client.GetSecret(name).Value.Value);
            }
            catch (RequestFailedException e) when (IsSecretNotFound(e))
            {
                EnsureSecretCreated();
                // 동시 생성 시 마지막 버전으로 수렴하도록 항상 재조회한다.
                return DecodePassword(client.GetSecret(name).Value.Value);
            }
        }

        /// <inheritdoc />
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
            RandomNumberGenerator.Fill(key);
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
                CryptographicOperations.ZeroMemory(key);
            }
        }

        private async Task EnsureSecretCreatedAsync(CancellationToken cancellationToken)
        {
            byte[] key = new byte[KeySize];
            RandomNumberGenerator.Fill(key);
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
                CryptographicOperations.ZeroMemory(key);
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
                CryptographicOperations.ZeroMemory(bytes);
                throw new InvalidOperationException(
                    $"KEK secret must decode to {KeySize} bytes, but was {bytes.Length}.");
            }

            return bytes;
        }
    }
}

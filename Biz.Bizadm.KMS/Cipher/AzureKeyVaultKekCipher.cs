using Azure;
using Azure.Core;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;

namespace Biz.Bizadm.KMS.Cipher
{
    /// <summary>
    /// Azure Key Vault RSA 키로 DEK를 wrap/unwrap하는 KEK 암호.
    /// </summary>
    public sealed class AzureKeyVaultKekCipher : IKekCipher
    {
        private readonly KeyClient client;
        private readonly TokenCredential credential;

        private CryptographyClient? cryptographyClient;

        /// <summary>
        /// Key Vault URI와 자격 증명으로 인스턴스를 만든다. 사용 전 <see cref="InitializeAsync"/> 또는 <see cref="CreateAsync"/>가 필요하다.
        /// </summary>
        private AzureKeyVaultKekCipher(Uri uri, TokenCredential credential)
        {
            ArgumentNullException.ThrowIfNull(uri);
            ArgumentNullException.ThrowIfNull(credential);

            this.credential = credential;
            client = new KeyClient(uri, credential);
        }

        /// <summary>
        /// Key Vault에서 키를 로드(없으면 생성)한 뒤 사용 가능한 암호를 반환한다.
        /// </summary>
        public static async Task<AzureKeyVaultKekCipher> CreateAsync(
            Uri uri,
            TokenCredential credential,
            string name,
            CancellationToken cancellationToken = default)
        {
            AzureKeyVaultKekCipher cipher = new(uri, credential);
            await cipher.InitializeAsync(name, cancellationToken).ConfigureAwait(false);
            return cipher;
        }

        /// <summary>
        /// 지정한 이름의 RSA 키를 로드하거나, 없으면 Wrap/Unwrap 전용으로 생성한다.
        /// </summary>
        private async Task InitializeAsync(string name, CancellationToken cancellationToken = default)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(name);

            KeyVaultKey vaultKey = await GetOrCreateKeyAsync(name, cancellationToken).ConfigureAwait(false);
            cryptographyClient = new CryptographyClient(vaultKey.Id, credential);
        }

        private async Task<KeyVaultKey> GetOrCreateKeyAsync(string name, CancellationToken cancellationToken)
        {
            try
            {
                Response<KeyVaultKey> response = await client
                    .GetKeyAsync(name, cancellationToken: cancellationToken)
                    .ConfigureAwait(false);
                return response.Value;
            }
            catch (RequestFailedException e) when (IsKeyNotFound(e))
            {
                try
                {
                    CreateRsaKeyOptions options = new(name)
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
                    // 다른 호출자가 생성했거나 soft-delete된 키가 남아 있는 경우.
                    try
                    {
                        Response<KeyVaultKey> response = await client
                            .GetKeyAsync(name, cancellationToken: cancellationToken)
                            .ConfigureAwait(false);
                        return response.Value;
                    }
                    catch (RequestFailedException getEx) when (IsKeyNotFound(getEx))
                    {
                        RecoverDeletedKeyOperation operation = await client
                            .StartRecoverDeletedKeyAsync(name, cancellationToken)
                            .ConfigureAwait(false);
                        Response<KeyVaultKey> recovered = await operation
                            .WaitForCompletionAsync(cancellationToken)
                            .ConfigureAwait(false);
                        return recovered.Value;
                    }
                }
            }
        }

        private static bool IsKeyNotFound(RequestFailedException e)
            => e.Status == 404 && string.Equals(e.ErrorCode, "KeyNotFound", StringComparison.Ordinal);

        /// <inheritdoc />
        public async Task<byte[]> EncryptAsync(byte[] plain, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(cryptographyClient);
            WrapResult result = await cryptographyClient
                .WrapKeyAsync(KeyWrapAlgorithm.RsaOaep256, plain, cancellationToken)
                .ConfigureAwait(false);
            return result.EncryptedKey;
        }

        /// <inheritdoc />
        public byte[] Encrypt(byte[] plain)
        {
            ArgumentNullException.ThrowIfNull(cryptographyClient);
            WrapResult result = cryptographyClient.WrapKey(KeyWrapAlgorithm.RsaOaep256, plain);
            return result.EncryptedKey;
        }

        /// <inheritdoc />
        public async Task<byte[]> DecryptAsync(byte[] encrypted, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(cryptographyClient);
            UnwrapResult result = await cryptographyClient
                .UnwrapKeyAsync(KeyWrapAlgorithm.RsaOaep256, encrypted, cancellationToken)
                .ConfigureAwait(false);
            return result.Key;
        }

        /// <inheritdoc />
        public byte[] Decrypt(byte[] encrypted)
        {
            ArgumentNullException.ThrowIfNull(cryptographyClient);
            UnwrapResult result = cryptographyClient.UnwrapKey(KeyWrapAlgorithm.RsaOaep256, encrypted);
            return result.Key;
        }

        /// <inheritdoc />
        public void Dispose()
        {
        }
    }
}

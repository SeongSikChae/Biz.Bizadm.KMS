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
        private readonly Uri uri;
        private readonly TokenCredential credential;
        private readonly KeyClient client;
        private readonly string keyName;

        private CryptographyClient? cryptographyClient;
        private string? keyVersion;

        /// <inheritdoc />
        public string KeyId => $"azurekv:{keyName}:{keyVersion}";

        private AzureKeyVaultKekCipher(Uri uri, TokenCredential credential, string keyName)
        {
            ArgumentNullException.ThrowIfNull(uri);
            ArgumentNullException.ThrowIfNull(credential);
            ArgumentException.ThrowIfNullOrWhiteSpace(keyName);

            this.uri = uri;
            this.credential = credential;
            this.keyName = keyName;
            client = new KeyClient(uri, credential);
        }

        /// <summary>
        /// Key Vault에서 키를 로드(없으면 생성)한 뒤 사용 가능한 암호를 반환한다.
        /// </summary>
        /// <param name="uri">Key Vault URI.</param>
        /// <param name="credential">Azure 자격 증명.</param>
        /// <param name="name">키 이름.</param>
        /// <param name="version">특정 키 버전. null이면 최신 버전.</param>
        /// <param name="cancellationToken">작업 취소 토큰.</param>
        /// <returns>생성된 <see cref="AzureKeyVaultKekCipher"/>.</returns>
        public static async Task<AzureKeyVaultKekCipher> CreateAsync(
            Uri uri,
            TokenCredential credential,
            string name,
            string? version = null,
            CancellationToken cancellationToken = default)
        {
            AzureKeyVaultKekCipher cipher = new(uri, credential, name);
            await cipher.InitializeAsync(name, version, cancellationToken).ConfigureAwait(false);
            return cipher;
        }

        /// <summary>
        /// 동일 keyName으로 새 RSA 키 버전을 생성한 뒤 새 <see cref="AzureKeyVaultKekCipher"/>를 반환한다.
        /// </summary>
        /// <param name="cancellationToken">작업 취소 토큰.</param>
        /// <returns>새 키 버전을 사용하는 <see cref="AzureKeyVaultKekCipher"/>.</returns>
        public async Task<AzureKeyVaultKekCipher> RotateAsync(CancellationToken cancellationToken = default)
        {
            CreateRsaKeyOptions options = new(keyName)
            {
                KeySize = 4096,
                Enabled = true
            };

            options.KeyOperations.Add(KeyOperation.WrapKey);
            options.KeyOperations.Add(KeyOperation.UnwrapKey);

            KeyVaultKey vaultKey = await client.CreateRsaKeyAsync(options, cancellationToken).ConfigureAwait(false);
            AzureKeyVaultKekCipher rotated = new(uri, credential, keyName);
            rotated.keyVersion = vaultKey.Properties.Version;
            rotated.cryptographyClient = new CryptographyClient(vaultKey.Id, credential);
            return rotated;
        }

        /// <summary>
        /// 지정한 이름의 RSA 키를 로드하거나, 없으면 Wrap/Unwrap 전용으로 생성한다.
        /// </summary>
        private async Task InitializeAsync(string name, string? version, CancellationToken cancellationToken = default)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(name);

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

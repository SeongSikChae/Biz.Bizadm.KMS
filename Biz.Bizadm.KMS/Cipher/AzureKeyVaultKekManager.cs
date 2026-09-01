using Azure.Core;

namespace Biz.Bizadm.KMS.Cipher
{
    /// <summary>
    /// <see cref="AzureKeyVaultKekCipher"/> 기반 KEK Manager.
    /// </summary>
    public sealed class AzureKeyVaultKekManager : KekManagerBase
    {
        private AzureKeyVaultKekManager(AzureKeyVaultKekCipher initial) : base(initial)
        {
        }

        /// <summary>
        /// Key Vault에서 KEK를 로드(없으면 생성)한 뒤 Manager를 생성한다.
        /// </summary>
        /// <param name="uri">Key Vault URI.</param>
        /// <param name="credential">Azure 자격 증명.</param>
        /// <param name="name">키 이름.</param>
        /// <param name="version">특정 키 버전. null이면 최신 버전.</param>
        /// <param name="cancellationToken">작업 취소 토큰.</param>
        /// <returns>생성된 <see cref="AzureKeyVaultKekManager"/>.</returns>
        public static async Task<AzureKeyVaultKekManager> CreateAsync(
            Uri uri,
            TokenCredential credential,
            string name,
            string? version = null,
            CancellationToken cancellationToken = default)
        {
            AzureKeyVaultKekCipher cipher = await AzureKeyVaultKekCipher
                .CreateAsync(uri, credential, name, version, cancellationToken)
                .ConfigureAwait(false);
            return new AzureKeyVaultKekManager(cipher);
        }

        /// <summary>
        /// Key Vault에 새 키 버전을 생성하고 Current를 교체한다.
        /// </summary>
        /// <param name="cancellationToken">작업 취소 토큰.</param>
        /// <returns>새 Current KEK.</returns>
        public async Task<AzureKeyVaultKekCipher> RotateAsync(CancellationToken cancellationToken = default)
        {
            AzureKeyVaultKekCipher current = (AzureKeyVaultKekCipher)Current;
            AzureKeyVaultKekCipher rotated = await current.RotateAsync(cancellationToken).ConfigureAwait(false);
            SetCurrent(rotated);
            return rotated;
        }
    }
}

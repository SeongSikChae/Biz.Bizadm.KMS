using System.Security.Cryptography;

namespace Biz.Bizadm.KMS.Cipher
{
    /// <summary>
    /// IKekCipher 확장 메서드.
    /// </summary>
    public static class KekCipherExtensions
    {
        /// <summary>
        /// source KEK로 unwrap한 DEK를 target KEK로 다시 wrap한다.
        /// </summary>
        /// <param name="target">wrap에 사용할 새 KEK.</param>
        /// <param name="source">unwrap에 사용할 기존 KEK.</param>
        /// <param name="wrappedDek">source KEK로 wrap된 DEK.</param>
        /// <returns>target KEK로 wrap된 DEK.</returns>
        public static byte[] RewrapDek(this IKekCipher target, IKekCipher source, byte[] wrappedDek)
        {
            ArgumentNullException.ThrowIfNull(target);
            ArgumentNullException.ThrowIfNull(source);
            ArgumentNullException.ThrowIfNull(wrappedDek);

            byte[] dek = source.Decrypt(wrappedDek);
            try
            {
                return target.Encrypt(dek);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(dek);
            }
        }

        /// <summary>
        /// source KEK로 unwrap한 DEK를 target KEK로 비동기로 다시 wrap한다.
        /// </summary>
        /// <param name="target">wrap에 사용할 새 KEK.</param>
        /// <param name="source">unwrap에 사용할 기존 KEK.</param>
        /// <param name="wrappedDek">source KEK로 wrap된 DEK.</param>
        /// <param name="cancellationToken">작업 취소 토큰.</param>
        /// <returns>target KEK로 wrap된 DEK.</returns>
        public static async Task<byte[]> RewrapDekAsync(
            this IKekCipher target,
            IKekCipher source,
            byte[] wrappedDek,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(target);
            ArgumentNullException.ThrowIfNull(source);
            ArgumentNullException.ThrowIfNull(wrappedDek);

            byte[] dek = await source.DecryptAsync(wrappedDek, cancellationToken).ConfigureAwait(false);
            try
            {
                return await target.EncryptAsync(dek, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(dek);
            }
        }
    }
}

namespace Biz.Bizadm.KMS.Cipher
{
    /// <summary>
    /// 바이트 배열을 암·복호화하는 공통 암호 인터페이스.
    /// </summary>
    public interface ICipher : IDisposable
    {
        /// <summary>
        /// 평문을 암호화한다.
        /// </summary>
        /// <param name="plain">암호화할 평문.</param>
        /// <returns>암호문.</returns>
        byte[] Encrypt(byte[] plain);

        /// <summary>
        /// 평문을 비동기로 암호화한다.
        /// </summary>
        /// <param name="plain">암호화할 평문.</param>
        /// <param name="cancellationToken">작업 취소 토큰.</param>
        /// <returns>암호문.</returns>
        Task<byte[]> EncryptAsync(byte[] plain, CancellationToken cancellationToken = default);

        /// <summary>
        /// 암호문을 복호화한다.
        /// </summary>
        /// <param name="encrypted">복호화할 암호문.</param>
        /// <returns>평문.</returns>
        byte[] Decrypt(byte[] encrypted);

        /// <summary>
        /// 암호문을 비동기로 복호화한다.
        /// </summary>
        /// <param name="encrypted">복호화할 암호문.</param>
        /// <param name="cancellationToken">작업 취소 토큰.</param>
        /// <returns>평문.</returns>
        Task<byte[]> DecryptAsync(byte[] encrypted, CancellationToken cancellationToken = default);
    }
}

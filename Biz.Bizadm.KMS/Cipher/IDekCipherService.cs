namespace Biz.Bizadm.KMS.Cipher
{
    /// <summary>
    /// <see cref="IDekCipher"/>를 UTF-8 문자열과 접두사 기반 암호문 형식으로 감싸는 서비스.
    /// </summary>
    public interface IDekCipherService : IDisposable
    {
        /// <summary>
        /// 입력이 DEK 암호문 접두사로 시작하는지 확인한다.
        /// </summary>
        /// <param name="input">검사할 문자열.</param>
        /// <returns>접두사로 시작하면 <see langword="true"/>.</returns>
        bool StartsWithFromPrefix(string input);

        /// <summary>
        /// 평문 문자열을 암호화한다.
        /// </summary>
        /// <param name="plain">암호화할 평문.</param>
        /// <returns>접두사와 Base64가 붙은 암호문.</returns>
        string Encrypt(string plain);

        /// <summary>
        /// 평문 문자열을 비동기로 암호화한다.
        /// </summary>
        /// <param name="plain">암호화할 평문.</param>
        /// <param name="cancellationToken">작업 취소 토큰.</param>
        /// <returns>접두사와 Base64가 붙은 암호문.</returns>
        Task<string> EncryptAsync(string plain, CancellationToken cancellationToken = default);

        /// <summary>
        /// 암호문 문자열을 복호화한다.
        /// </summary>
        /// <param name="encrypted">복호화할 암호문.</param>
        /// <returns>평문.</returns>
        string Decrypt(string encrypted);

        /// <summary>
        /// 암호문 문자열을 비동기로 복호화한다.
        /// </summary>
        /// <param name="encrypted">복호화할 암호문.</param>
        /// <param name="cancellationToken">작업 취소 토큰.</param>
        /// <returns>평문.</returns>
        Task<string> DecryptAsync(string encrypted, CancellationToken cancellationToken = default);
    }
}

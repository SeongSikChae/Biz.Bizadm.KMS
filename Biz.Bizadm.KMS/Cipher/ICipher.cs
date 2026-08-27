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
        /// 암호문을 복호화한다.
        /// </summary>
        /// <param name="encrypted">복호화할 암호문.</param>
        /// <returns>평문.</returns>
        byte[] Decrypt(byte[] encrypted);
    }
}

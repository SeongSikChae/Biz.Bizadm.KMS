namespace Biz.Bizadm.KMS.Cipher
{
    /// <summary>
    /// KEK 유도·로드에 사용할 자격 증명(패스워드)을 제공한다.
    /// </summary>
    public interface IKekCredentialProvider
    {
        /// <summary>
        /// KEK에 사용할 패스워드 바이트를 반환한다.
        /// </summary>
        /// <returns>패스워드 바이트. 호출부가 사용 후 안전하게 지워야 한다.</returns>
        byte[] GetPassword();
    }
}

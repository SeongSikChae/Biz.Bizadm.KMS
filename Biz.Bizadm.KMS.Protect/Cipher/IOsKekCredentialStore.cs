using Biz.Bizadm.KMS.Cipher;

namespace Biz.Bizadm.KMS.Protect.Cipher
{
    /// <summary>
    /// OS 자격 증명 금고에 KEK 패스워드를 저장·조회·삭제하는 <see cref="IKekCredentialProvider"/>.
    /// </summary>
    public interface IOsKekCredentialStore : IKekCredentialProvider
    {
        /// <summary>자격 증명 서비스(키) 이름.</summary>
        string Service { get; }

        /// <summary>계정(엔트리) 이름.</summary>
        string Account { get; }

        /// <summary>
        /// 패스워드를 OS 자격 증명 금고에 저장(또는 갱신)한다.
        /// </summary>
        /// <param name="password">KEK에 사용할 패스워드 바이트.</param>
        void StorePassword(ReadOnlySpan<byte> password);

        /// <summary>
        /// 금고에서 해당 엔트리를 삭제한다.
        /// </summary>
        /// <returns>삭제되었으면 <c>true</c>.</returns>
        bool RemovePassword();
    }
}

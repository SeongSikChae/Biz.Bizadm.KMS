namespace Biz.Bizadm.KMS.Cipher
{
    /// <summary>
    /// 키 암호화 키(KEK)로 키 물질을 wrap·unwrap하는 암호 인터페이스.
    /// </summary>
    public interface IKekCipher : ICipher
    {
        /// <summary>
        /// 이 KEK 인스턴스를 식별하는 ID. wrap된 DEK에 함께 저장된다.
        /// </summary>
        string KeyId { get; }
    }
}

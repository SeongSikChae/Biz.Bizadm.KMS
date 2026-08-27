namespace Biz.Bizadm.KMS.Protect.Cipher
{
    /// <summary>
    /// OS 자격 증명 금고 연동 시 사용하는 기본 키 이름.
    /// </summary>
    public static class OsKekCredentialDefaults
    {
        /// <summary>GCM 자격 증명 네임스페이스.</summary>
        public const string Namespace = "Biz.Bizadm.KMS";

        /// <summary>기본 서비스(키) 이름.</summary>
        public const string Service = "bizadm-kms://kek";

        /// <summary>기본 계정 이름.</summary>
        public const string Account = "default";
    }
}

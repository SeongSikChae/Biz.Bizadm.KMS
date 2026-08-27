namespace Biz.Bizadm.KMS.Protect.Cipher
{
    /// <summary>
    /// Linux Secret Service / libsecret(<c>secretservice</c>) 기반 KEK 자격 증명 제공자.
    /// </summary>
    /// <remarks>
    /// GUI 세션·키링 unlock이 필요할 수 있다. 헤드리스 환경에서는
    /// <c>GCM_CREDENTIAL_STORE=gpg</c> 등 다른 백킹 스토어를 프로세스 시작 전에 설정한다.
    /// </remarks>
    public sealed class LinuxSecretServiceKekCredentialProvider : CredentialStoreKekCredentialProvider
    {
        private LinuxSecretServiceKekCredentialProvider(
            GitCredentialManager.ICredentialStore store,
            string service,
            string account)
            : base(store, service, account)
        {
        }

        /// <summary>
        /// Linux Secret Service 제공자를 생성한다.
        /// </summary>
        /// <param name="service">서비스(키) 이름.</param>
        /// <param name="account">계정 이름.</param>
        /// <param name="namespace">GCM 네임스페이스.</param>
        /// <returns>생성된 제공자.</returns>
        /// <exception cref="PlatformNotSupportedException">Linux가 아닐 때.</exception>
        public static LinuxSecretServiceKekCredentialProvider Create(
            string service = OsKekCredentialDefaults.Service,
            string account = OsKekCredentialDefaults.Account,
            string? @namespace = OsKekCredentialDefaults.Namespace)
        {
            if (!OperatingSystem.IsLinux())
            {
                throw new PlatformNotSupportedException("LinuxSecretServiceKekCredentialProvider requires Linux.");
            }

            EnsureCredentialStore("secretservice");
            return new LinuxSecretServiceKekCredentialProvider(CreateStore(@namespace), service, account);
        }
    }
}

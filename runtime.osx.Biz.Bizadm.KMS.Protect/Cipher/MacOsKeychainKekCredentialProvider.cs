namespace Biz.Bizadm.KMS.Protect.Cipher
{
    /// <summary>
    /// macOS Keychain(<c>keychain</c>) 기반 KEK 자격 증명 제공자.
    /// </summary>
    public sealed class MacOsKeychainKekCredentialProvider : CredentialStoreKekCredentialProvider
    {
        private MacOsKeychainKekCredentialProvider(
            GitCredentialManager.ICredentialStore store,
            string service,
            string account)
            : base(store, service, account)
        {
        }

        /// <summary>
        /// macOS Keychain 제공자를 생성한다.
        /// </summary>
        /// <param name="service">서비스(키) 이름.</param>
        /// <param name="account">계정 이름.</param>
        /// <param name="namespace">GCM 네임스페이스.</param>
        /// <returns>생성된 제공자.</returns>
        /// <exception cref="PlatformNotSupportedException">macOS가 아닐 때.</exception>
        public static MacOsKeychainKekCredentialProvider Create(
            string service = OsKekCredentialDefaults.Service,
            string account = OsKekCredentialDefaults.Account,
            string? @namespace = OsKekCredentialDefaults.Namespace)
        {
            if (!OperatingSystem.IsMacOS())
            {
                throw new PlatformNotSupportedException("MacOsKeychainKekCredentialProvider requires macOS.");
            }

            EnsureCredentialStore("keychain");
            return new MacOsKeychainKekCredentialProvider(CreateStore(@namespace), service, account);
        }
    }
}

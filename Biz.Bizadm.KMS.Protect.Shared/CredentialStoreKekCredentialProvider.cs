using System.Text;
using GitCredentialManager;

namespace Biz.Bizadm.KMS.Protect.Cipher
{
    /// <summary>
    /// Git Credential Manager 저장소를 사용하는 KEK 자격 증명 제공자 기반 형식.
    /// </summary>
    public abstract class CredentialStoreKekCredentialProvider : IOsKekCredentialStore
    {
        private readonly ICredentialStore store;

        /// <summary>
        /// 저장소와 서비스·계정으로 제공자를 초기화한다.
        /// </summary>
        /// <param name="store">GCM 자격 증명 저장소.</param>
        /// <param name="service">서비스(키) 이름.</param>
        /// <param name="account">계정 이름.</param>
        protected CredentialStoreKekCredentialProvider(ICredentialStore store, string service, string account)
        {
            ArgumentNullException.ThrowIfNull(store);
            ArgumentException.ThrowIfNullOrWhiteSpace(service);
            ArgumentException.ThrowIfNullOrWhiteSpace(account);

            this.store = store;
            Service = service;
            Account = account;
        }

        /// <inheritdoc />
        public string Service { get; }

        /// <inheritdoc />
        public string Account { get; }

        /// <inheritdoc />
        public byte[] GetPassword()
        {
            ICredential? credential = store.Get(Service, Account);
            if (credential is null || string.IsNullOrEmpty(credential.Password))
            {
                throw new InvalidOperationException(
                    $"KEK credential not found. Service='{Service}', Account='{Account}'.");
            }

            return DecodePassword(credential.Password);
        }

        /// <inheritdoc />
        public Task<byte[]> GetPasswordAsync(CancellationToken cancellationToken = default)
        {
            return Task.FromResult(GetPassword());
        }

        /// <inheritdoc />
        public void StorePassword(ReadOnlySpan<byte> password)
        {
            if (password.IsEmpty)
            {
                throw new ArgumentException("Password must not be empty.", nameof(password));
            }

            store.AddOrUpdate(Service, Account, EncodePassword(password));
        }

        /// <inheritdoc />
        public bool RemovePassword()
            => store.Remove(Service, Account);

        /// <summary>
        /// GCM 저장소가 아직 지정되지 않았으면 프로세스 환경 변수로 백킹 스토어를 설정한다.
        /// </summary>
        /// <param name="storeName">GCM_CREDENTIAL_STORE 값.</param>
        protected static void EnsureCredentialStore(string storeName)
        {
            if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable("GCM_CREDENTIAL_STORE")))
            {
                Environment.SetEnvironmentVariable("GCM_CREDENTIAL_STORE", storeName);
            }
        }

        /// <summary>
        /// 네임스페이스로 GCM 자격 증명 저장소를 생성한다.
        /// </summary>
        /// <param name="namespace">자격 증명 네임스페이스.</param>
        /// <returns>생성된 저장소.</returns>
        protected static ICredentialStore CreateStore(string? @namespace)
            => CredentialManager.Create(
                string.IsNullOrWhiteSpace(@namespace) ? OsKekCredentialDefaults.Namespace : @namespace);

        private static string EncodePassword(ReadOnlySpan<byte> password)
            => Convert.ToBase64String(password);

        private static byte[] DecodePassword(string encoded)
        {
            try
            {
                return Convert.FromBase64String(encoded);
            }
            catch (FormatException)
            {
                return Encoding.UTF8.GetBytes(encoded);
            }
        }
    }
}

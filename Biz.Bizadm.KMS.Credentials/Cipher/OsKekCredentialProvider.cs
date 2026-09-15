using System.Reflection;

namespace Biz.Bizadm.KMS.Credentials.Cipher
{
    /// <summary>
    /// RID별 <c>Biz.Bizadm.KMS.Credentials.Runtime.*</c> 구현 패키지에서
    /// 현재 OS용 <see cref="IOsKekCredentialStore"/>를 로드한다.
    /// </summary>
    public static class OsKekCredentialProvider
    {
        private const string RuntimeAssemblyName = "Biz.Bizadm.KMS.Credentials.Runtime";
        private const string RuntimeFactoryTypeName =
            "Biz.Bizadm.KMS.Credentials.Cipher.RuntimeOsKekCredentialStoreFactory";

        /// <summary>
        /// 현재 플랫폼에 맞는 runtime 구현 어셈블리에서 제공자를 생성한다.
        /// </summary>
        /// <param name="service">서비스(키) 이름.</param>
        /// <param name="account">계정 이름.</param>
        /// <param name="namespace">GCM 네임스페이스.</param>
        /// <returns>현재 OS용 제공자.</returns>
        /// <exception cref="PlatformNotSupportedException">지원하지 않는 OS.</exception>
        /// <exception cref="InvalidOperationException">runtime 구현 패키지가 로드되지 않은 경우.</exception>
        public static IOsKekCredentialStore CreateForCurrentOs(
            string service = OsKekCredentialDefaults.Service,
            string account = OsKekCredentialDefaults.Account,
            string? @namespace = OsKekCredentialDefaults.Namespace)
        {
            Type type = Type.GetType(
                    $"{RuntimeFactoryTypeName}, {RuntimeAssemblyName}",
                    throwOnError: false)
                ?? throw new InvalidOperationException(
                    $"Runtime implementation '{RuntimeAssemblyName}' is not available. " +
                    "Reference Biz.Bizadm.KMS.Credentials and publish for a supported RID.");

            MethodInfo create = type.GetMethod(
                    "Create",
                    BindingFlags.Public | BindingFlags.Static,
                    binder: null,
                    types: [typeof(string), typeof(string), typeof(string)],
                    modifiers: null)
                ?? throw new InvalidOperationException($"Create method not found on '{RuntimeFactoryTypeName}'.");

            return (IOsKekCredentialStore)create.Invoke(null, [service, account, @namespace])!;
        }
    }
}

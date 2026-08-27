using System.Reflection;

namespace Biz.Bizadm.KMS.Protect.Cipher
{
    /// <summary>
    /// RID별 <c>Biz.Bizadm.KMS.Protect.Runtime.*</c> 구현 패키지에서
    /// 현재 OS용 <see cref="IOsKekCredentialStore"/>를 로드한다.
    /// </summary>
    public static class OsKekCredentialProvider
    {
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
            (string assemblyName, string typeName) = ResolveRuntimeType();

            Type type = Type.GetType($"{typeName}, {assemblyName}", throwOnError: false)
                ?? throw new InvalidOperationException(
                    $"Runtime protect package '{assemblyName}' is not available. " +
                    "Reference Biz.Bizadm.KMS.Protect (NuGet RID restore) or the matching Runtime.* package.");

            MethodInfo create = type.GetMethod(
                    "Create",
                    BindingFlags.Public | BindingFlags.Static,
                    binder: null,
                    types: [typeof(string), typeof(string), typeof(string)],
                    modifiers: null)
                ?? throw new InvalidOperationException($"Create method not found on '{typeName}'.");

            return (IOsKekCredentialStore)create.Invoke(null, [service, account, @namespace])!;
        }

        private static (string AssemblyName, string TypeName) ResolveRuntimeType()
        {
            if (OperatingSystem.IsWindows())
            {
                return (
                    "Biz.Bizadm.KMS.Protect.Runtime.win",
                    "Biz.Bizadm.KMS.Protect.Cipher.WindowsCredentialManagerKekCredentialProvider");
            }

            if (OperatingSystem.IsMacOS())
            {
                return (
                    "Biz.Bizadm.KMS.Protect.Runtime.osx",
                    "Biz.Bizadm.KMS.Protect.Cipher.MacOsKeychainKekCredentialProvider");
            }

            if (OperatingSystem.IsLinux())
            {
                return (
                    "Biz.Bizadm.KMS.Protect.Runtime.linux",
                    "Biz.Bizadm.KMS.Protect.Cipher.LinuxSecretServiceKekCredentialProvider");
            }

            throw new PlatformNotSupportedException(
                $"OS credential protect is not supported on {System.Runtime.InteropServices.RuntimeInformation.OSDescription}.");
        }
    }
}

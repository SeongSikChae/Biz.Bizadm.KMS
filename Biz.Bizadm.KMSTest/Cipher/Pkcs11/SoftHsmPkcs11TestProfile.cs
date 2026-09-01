using Biz.Bizadm.KMS.Cipher;
using Biz.Bizadm.KMS.Pkcs11.Cipher;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using System.Text;

namespace Biz.Bizadm.KMSTest.Cipher.Pkcs11
{
    /// <summary>
    /// SoftHSM 2.5.0 portable/MSI 환경용 Manual 테스트 프로파일.
    /// 프로덕션 기본값(RSA-OAEP-256)과 달리 SoftHSM 2.5.0이 지원하는 wrap 메커니즘을 사용한다.
    /// </summary>
    internal static class SoftHsmPkcs11TestProfile
    {
        internal static readonly byte[] Pin = GetRequiredBytes("PKCS11_PIN");

        /// <summary>
        /// SoftHSM 2.5.0에서 검증된 wrap 옵션. CKM_RSA_PKCS + RSA-2048.
        /// </summary>
        internal static Pkcs11KekOptions KekOptions { get; } = new()
        {
            WrapMechanism = CKM.CKM_RSA_PKCS,
            RsaKeySize = 2048,
        };

        internal static Pkcs11LibraryContext CreateContext()
            => Pkcs11LibraryContext.Create(LibraryPath, ResolveSlotId(), new FixedPasswordCredentialProvider(Pin));

        internal static Pkcs11KekCipher CreateCipher(
            Pkcs11LibraryContext context,
            string keyLabel,
            bool createIfMissing = true)
            => Pkcs11KekCipher.Create(context, keyLabel, createIfMissing, KekOptions);

        internal static Pkcs11KekManager CreateManager(Pkcs11LibraryContext context, string keyLabel)
            => Pkcs11KekManager.Create(context, keyLabel, createIfMissing: true, KekOptions);

        internal static string NewKeyLabel(string prefix = "kms-softhsm-test")
            => $"{prefix}-{Guid.NewGuid():N}";

        private static string LibraryPath
            => Environment.GetEnvironmentVariable("PKCS11_LIBRARY_PATH")
               ?? throw new InvalidOperationException("PKCS11_LIBRARY_PATH 환경 변수가 설정되지 않았습니다.");

        private static ulong ResolveSlotId()
        {
            if (ulong.TryParse(Environment.GetEnvironmentVariable("PKCS11_SLOT_ID"), out ulong slotId))
                return slotId;

            Pkcs11InteropFactories factories = new();
            using IPkcs11Library library = factories.Pkcs11LibraryFactory.LoadPkcs11Library(
                factories,
                LibraryPath,
                AppType.MultiThreaded);

            foreach (ISlot slot in library.GetSlotList(SlotsType.WithTokenPresent))
            {
                ITokenInfo tokenInfo = slot.GetTokenInfo();
                if (tokenInfo.TokenFlags.TokenInitialized)
                    return slot.SlotId;
            }

            throw new InvalidOperationException(
                "초기화된 SoftHSM 토큰 슬롯을 찾을 수 없습니다. softhsm2-util --init-token 후 PKCS11_SLOT_ID를 설정하세요.");
        }

        private static byte[] GetRequiredBytes(string name)
        {
            string? value = Environment.GetEnvironmentVariable(name);
            if (string.IsNullOrEmpty(value))
                throw new InvalidOperationException($"{name} 환경 변수가 설정되지 않았습니다.");

            return Encoding.UTF8.GetBytes(value);
        }
    }
}

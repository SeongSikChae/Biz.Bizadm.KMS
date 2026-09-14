using Biz.Bizadm.KMS.Cipher;
using Biz.Bizadm.KMS.Protect.Cipher;

namespace Biz.Bizadm.KMSTest.Runtime.win.Cipher
{
    [TestClass]
    public sealed class OsKekCredentialProviderWinTests
    {
        [TestMethod]
        [OSCondition(OperatingSystems.Windows)]
        public void StoreGetRemove_RoundTrips()
        {
            IOsKekCredentialStore provider = OsKekCredentialProvider.CreateForCurrentOs(
                NewService(),
                "unit-test");
            RoundTrip(provider);
        }

        [TestMethod]
        [OSCondition(OperatingSystems.Windows)]
        public void CreateForCurrentOs_Windows_ReturnsWindowsProvider()
        {
            IOsKekCredentialStore provider = OsKekCredentialProvider.CreateForCurrentOs(
                NewService(),
                "unit-test");

            Assert.AreEqual(
                "Biz.Bizadm.KMS.Protect.Cipher.WindowsCredentialManagerKekCredentialProvider",
                provider.GetType().FullName);
        }

        [TestMethod]
        [OSCondition(OperatingSystems.Windows)]
        public void AesGcmKekCipher_AcceptsOsCredentialProvider()
        {
            IOsKekCredentialStore provider = OsKekCredentialProvider.CreateForCurrentOs(
                NewService(),
                "unit-test");
            byte[] password = "os-credential-password"u8.ToArray();
            byte[] salt = "0123456789abcdef"u8.ToArray();

            try
            {
                provider.StorePassword(password);

                using AesGcmKekCipher encryptor = AesGcmKekCipher.Create(provider, salt, 10_000);
                byte[] cipher = encryptor.Encrypt("hello"u8.ToArray());

                using AesGcmKekCipher decryptor = AesGcmKekCipher.Create(provider, salt, 10_000);
                CollectionAssert.AreEqual("hello"u8.ToArray(), decryptor.Decrypt(cipher));
            }
            finally
            {
                provider.RemovePassword();
            }
        }

        private static string NewService()
            => $"bizadm-kms://test/{Guid.NewGuid():N}";

        private static void RoundTrip(IOsKekCredentialStore provider)
        {
            byte[] password = "unit-test-password-bytes"u8.ToArray();

            try
            {
                provider.StorePassword(password);
                CollectionAssert.AreEqual(password, provider.GetPassword());
                Assert.IsTrue(provider.RemovePassword());
            }
            finally
            {
                provider.RemovePassword();
            }
        }
    }
}


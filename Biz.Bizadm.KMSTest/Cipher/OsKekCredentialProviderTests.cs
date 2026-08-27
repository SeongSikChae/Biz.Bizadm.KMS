using Biz.Bizadm.KMS.Cipher;
using Biz.Bizadm.KMS.Protect.Cipher;

namespace Biz.Bizadm.KMSTest.Cipher
{
    [TestClass]
    public sealed class OsKekCredentialProviderTests
    {
        [TestMethod]
        [OSCondition(OperatingSystems.Windows)]
        public void WindowsCredentialManager_StoreGetRemove_RoundTrips()
        {
            IOsKekCredentialStore provider = WindowsCredentialManagerKekCredentialProvider.Create(
                NewService(),
                "unit-test");
            RoundTrip(provider);
        }

        [TestMethod]
        [OSCondition(OperatingSystems.Windows)]
        public void CreateForCurrentOs_ReturnsPlatformProvider()
        {
            IOsKekCredentialStore provider = OsKekCredentialProvider.CreateForCurrentOs(
                NewService(),
                "unit-test");

            Assert.IsInstanceOfType<WindowsCredentialManagerKekCredentialProvider>(provider);
        }

        [TestMethod]
        [OSCondition(OperatingSystems.Windows)]
        public void AesGcmKekCipher_AcceptsOsCredentialProvider()
        {
            IOsKekCredentialStore provider = WindowsCredentialManagerKekCredentialProvider.Create(
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

using Biz.Bizadm.KMS.Cipher;
using System.Security.Cryptography;

namespace Biz.Bizadm.KMSTest.Cipher
{
    [TestClass]
    public sealed class KekCipherExtensionsTests
    {
        private const int Iterations = 10_000;

        private static readonly byte[] Password = "kms-rewrap-password"u8.ToArray();
        private static readonly byte[] Salt = [11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26];
        private static readonly byte[] NewSalt = [31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46];

        [TestMethod]
        public void RewrapDek_WithRotatedKek_PreservesDekPlaintext()
        {
            using AesGcmKekCipher oldKek = AesGcmKekCipher.Create(new FixedPasswordCredentialProvider(Password), Salt, Iterations);
            using AesGcmKekCipher newKek = AesGcmKekCipher.CreateRotated(
                new FixedPasswordCredentialProvider("new-password"u8.ToArray()),
                NewSalt,
                Iterations);

            byte[] dek = RandomNumberGenerator.GetBytes(32);
            byte[] wrapped = oldKek.Encrypt(dek);
            byte[] rewrapped = newKek.RewrapDek(oldKek, wrapped);

            CollectionAssert.AreEqual(dek, newKek.Decrypt(rewrapped));
        }

        [TestMethod]
        public void RewrapDek_WrongSourceKek_ThrowsCryptographicException()
        {
            using AesGcmKekCipher oldKek = AesGcmKekCipher.Create(new FixedPasswordCredentialProvider(Password), Salt, Iterations);
            using AesGcmKekCipher newKek = AesGcmKekCipher.CreateRotated(
                new FixedPasswordCredentialProvider("new-password"u8.ToArray()),
                NewSalt,
                Iterations);
            using AesGcmKekCipher wrongKek = AesGcmKekCipher.Create(
                new FixedPasswordCredentialProvider("other-password"u8.ToArray()),
                Salt,
                Iterations);

            byte[] wrapped = oldKek.Encrypt(RandomNumberGenerator.GetBytes(32));

            Assert.ThrowsExactly<AuthenticationTagMismatchException>(() => newKek.RewrapDek(wrongKek, wrapped));
        }
    }
}

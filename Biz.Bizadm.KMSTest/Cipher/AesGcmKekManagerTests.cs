using Biz.Bizadm.KMS.Cipher;
using System.Security.Cryptography;

namespace Biz.Bizadm.KMSTest.Cipher
{
    [TestClass]
    public sealed class AesGcmKekManagerTests
    {
        private const int Iterations = 10_000;

        private static readonly byte[] Password = "kms-manager-password"u8.ToArray();
        private static readonly byte[] Salt = [51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66];
        private static readonly byte[] NewSalt = [71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86];

        [TestMethod]
        public void Rotate_UpdatesCurrentAndKeepsOldKeyResolvable()
        {
            using AesGcmKekManager manager = AesGcmKekManager.Create(
                new FixedPasswordCredentialProvider(Password),
                Salt,
                Iterations);
            string oldKeyId = manager.Current.KeyId;

            AesGcmKekCipher rotated = manager.Rotate(
                new FixedPasswordCredentialProvider("rotated-password"u8.ToArray()),
                NewSalt,
                Iterations);

            Assert.AreEqual(rotated.KeyId, manager.Current.KeyId);
            Assert.AreNotEqual(oldKeyId, manager.Current.KeyId);
            Assert.IsTrue(manager.KnownKeyIds.Contains(oldKeyId));
            Assert.IsNotNull(manager.Resolve(oldKeyId));
        }

        [TestMethod]
        public void RewrapDekFile_UpdatesEnvelopeToCurrentKeyId()
        {
            string directory = CreateTempDirectory();
            FileInfo dekFile = new(Path.Combine(directory, "dek.bin"));
            byte[] plain = CreatePlain(48);

            using (AesGcmKekManager manager = AesGcmKekManager.Create(
                       new FixedPasswordCredentialProvider(Password),
                       Salt,
                       Iterations))
            {
                using AesGcmDekCipher dek = AesGcmDekCipher.Create(manager.Current, dekFile);
                byte[] ciphertext = dek.Encrypt(plain);
                string oldKeyId = manager.Current.KeyId;

                manager.Rotate(
                    new FixedPasswordCredentialProvider("rotated-password"u8.ToArray()),
                    NewSalt,
                    Iterations);
                manager.RewrapDekFile(dekFile);

                WrappedDekEnvelope envelope = WrappedDekEnvelope.Deserialize(File.ReadAllBytes(dekFile.FullName));
                Assert.AreEqual(manager.Current.KeyId, envelope.KeyId);
                Assert.AreNotEqual(oldKeyId, envelope.KeyId);

                using AesGcmDekCipher reloaded = AesGcmDekCipher.Create(manager.Current, dekFile);
                CollectionAssert.AreEqual(plain, reloaded.Decrypt(ciphertext));
            }
        }

        [TestMethod]
        public void Resolve_UnknownKeyId_ThrowsKeyNotFoundException()
        {
            using AesGcmKekManager manager = AesGcmKekManager.Create(
                new FixedPasswordCredentialProvider(Password),
                Salt,
                Iterations);

            Assert.ThrowsExactly<KeyNotFoundException>(() => manager.Resolve("unknown-key-id"));
        }

        [TestMethod]
        public void Release_RemovesOldKekFromRegistry()
        {
            using AesGcmKekManager manager = AesGcmKekManager.Create(
                new FixedPasswordCredentialProvider(Password),
                Salt,
                Iterations);
            string oldKeyId = manager.Current.KeyId;

            manager.Rotate(
                new FixedPasswordCredentialProvider("rotated-password"u8.ToArray()),
                NewSalt,
                Iterations);

            manager.Release(oldKeyId);

            Assert.IsFalse(manager.KnownKeyIds.Contains(oldKeyId));
            Assert.ThrowsExactly<KeyNotFoundException>(() => manager.Resolve(oldKeyId));
        }

        [TestMethod]
        public void Release_Current_ThrowsInvalidOperationException()
        {
            using AesGcmKekManager manager = AesGcmKekManager.Create(
                new FixedPasswordCredentialProvider(Password),
                Salt,
                Iterations);

            Assert.ThrowsExactly<InvalidOperationException>(() => manager.Release(manager.Current.KeyId));
        }

        private static string CreateTempDirectory()
        {
            string path = Path.Combine(Path.GetTempPath(), "Biz.Bizadm.KMSTest", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(path);
            return path;
        }

        private static byte[] CreatePlain(int length)
        {
            byte[] plain = new byte[length];
            if (length > 0)
                RandomNumberGenerator.Fill(plain);
            return plain;
        }
    }
}

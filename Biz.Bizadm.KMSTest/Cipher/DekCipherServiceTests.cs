using Biz.Bizadm.KMS.Cipher;

namespace Biz.Bizadm.KMSTest.Cipher
{
    [TestClass]
    public sealed class DekCipherServiceTests
    {
        [TestMethod]
        public void EncryptDecrypt_RoundTripsPlaintext()
        {
            using IDekCipherService service = new DekCipherService(CreateAesDek());

            string encrypted = service.Encrypt("hello-kms");
            Assert.IsTrue(encrypted.StartsWith("DEKENC:", StringComparison.Ordinal));
            Assert.AreEqual("hello-kms", service.Decrypt(encrypted));
        }

        [TestMethod]
        public async Task EncryptDecryptAsync_RoundTripsPlaintext()
        {
            using IDekCipherService service = new DekCipherService(CreateAesDek());

            string encrypted = await service.EncryptAsync("async-plain");
            Assert.IsTrue(service.StartsWithFromPrefix(encrypted));
            Assert.AreEqual("async-plain", await service.DecryptAsync(encrypted));
        }

        [TestMethod]
        public void StartsWithFromPrefix_DetectsPrefix()
        {
            using IDekCipherService service = new DekCipherService(IDekCipher.Null);

            Assert.IsTrue(service.StartsWithFromPrefix("DEKENC:abc"));
            Assert.IsFalse(service.StartsWithFromPrefix("plain"));
            Assert.ThrowsExactly<ArgumentNullException>(() => service.StartsWithFromPrefix(null!));
        }

        [TestMethod]
        public void Decrypt_WithoutPrefix_Throws()
        {
            using IDekCipherService service = new DekCipherService(IDekCipher.Null);

            Assert.ThrowsExactly<ArgumentException>(() => service.Decrypt("not-encrypted"));
            Assert.ThrowsExactly<ArgumentException>(() => service.DecryptAsync("not-encrypted").GetAwaiter().GetResult());
        }

        [TestMethod]
        public void NullCipher_PassthroughWithPrefix()
        {
            using IDekCipherService service = new DekCipherService(IDekCipher.Null);

            string encrypted = service.Encrypt("passthrough");
            Assert.IsTrue(encrypted.StartsWith("DEKENC:", StringComparison.Ordinal));
            Assert.AreEqual("passthrough", service.Decrypt(encrypted));
        }

        [TestMethod]
        public void Dispose_LeaveOpen_DoesNotDisposeUnderlyingCipher()
        {
            using AesGcmDekCipher dek = CreateAesDek();
            IDekCipherService service = new DekCipherService(dek, leaveOpen: true);
            string encrypted = service.Encrypt("keep-open");
            service.Dispose();

            CollectionAssert.AreEqual(
                System.Text.Encoding.UTF8.GetBytes("keep-open"),
                dek.Decrypt(Convert.FromBase64String(encrypted["DEKENC:".Length..])));
        }

        [TestMethod]
        public void Dispose_Default_DisposesUnderlyingCipher()
        {
            AesGcmDekCipher dek = CreateAesDek();
            new DekCipherService(dek).Dispose();

            Assert.ThrowsExactly<ObjectDisposedException>(() => dek.Encrypt([1]));
        }

        private static AesGcmDekCipher CreateAesDek()
        {
            string directory = Path.Combine(Path.GetTempPath(), "kms-dek-svc-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(directory);
            FileInfo dekFile = new(Path.Combine(directory, "dek.bin"));
            return AesGcmDekCipher.Create(IKekCipher.Null, dekFile);
        }
    }
}

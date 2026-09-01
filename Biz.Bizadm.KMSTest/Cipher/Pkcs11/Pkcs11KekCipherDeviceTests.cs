using Biz.Bizadm.KMS.Cipher;
using Biz.Bizadm.KMS.Pkcs11.Cipher;
using System.Security.Cryptography;

namespace Biz.Bizadm.KMSTest.Cipher.Pkcs11
{
    /// <summary>
    /// PKCS#11 디바이스 공통 시나리오. 백엔드별 프로파일은 <see cref="CreateCipher"/> 등으로 주입한다.
    /// </summary>
    public abstract class Pkcs11KekCipherDeviceTests
    {
        protected abstract Pkcs11LibraryContext CreateContext();

        protected abstract Pkcs11KekCipher CreateCipher(
            Pkcs11LibraryContext context,
            string keyLabel,
            bool createIfMissing = true);

        protected abstract string NewKeyLabel(string prefix = "kms-pkcs11-test");

        [TestMethod]
        [Timeout(120_000, CooperativeCancellation = true)]
        [DataRow(32)]
        [DataRow(64)]
        public void EncryptDecrypt_Roundtrip_ReturnsOriginalPlaintext(int length)
        {
            byte[] plain = CreatePlain(length);
            using Pkcs11LibraryContext context = CreateContext();
            string keyLabel = NewKeyLabel();

            using Pkcs11KekCipher cipher = CreateCipher(context, keyLabel);
            byte[] encrypted = cipher.Encrypt(plain);
            byte[] decrypted = cipher.Decrypt(encrypted);

            CollectionAssert.AreEqual(plain, decrypted);
        }

        [TestMethod]
        [Timeout(120_000, CooperativeCancellation = true)]
        public void Encrypt_SamePlaintext_BothDecryptToOriginal()
        {
            byte[] plain = CreatePlain(32);
            using Pkcs11LibraryContext context = CreateContext();
            string keyLabel = NewKeyLabel();

            using Pkcs11KekCipher cipher = CreateCipher(context, keyLabel);
            byte[] first = cipher.Encrypt(plain);
            byte[] second = cipher.Encrypt(plain);

            CollectionAssert.AreEqual(plain, cipher.Decrypt(first));
            CollectionAssert.AreEqual(plain, cipher.Decrypt(second));
        }

        [TestMethod]
        [Timeout(180_000, CooperativeCancellation = true)]
        public void Decrypt_WithNewInstanceSameLabel_Succeeds()
        {
            byte[] plain = CreatePlain(32);
            using Pkcs11LibraryContext context = CreateContext();
            string keyLabel = NewKeyLabel();

            byte[] encrypted;
            using (Pkcs11KekCipher encryptor = CreateCipher(context, keyLabel))
                encrypted = encryptor.Encrypt(plain);

            using Pkcs11KekCipher decryptor = CreateCipher(context, keyLabel, createIfMissing: false);
            byte[] decrypted = decryptor.Decrypt(encrypted);

            CollectionAssert.AreEqual(plain, decrypted);
        }

        [TestMethod]
        [Timeout(120_000, CooperativeCancellation = true)]
        public void Rotate_RewrapDek_PreservesPlaintext()
        {
            byte[] plain = CreatePlain(32);
            using Pkcs11LibraryContext context = CreateContext();
            string oldKeyLabel = NewKeyLabel("kms-pkcs11-old");
            string newKeyLabel = NewKeyLabel("kms-pkcs11-new");

            using Pkcs11KekCipher oldKek = CreateCipher(context, oldKeyLabel);
            byte[] wrapped = oldKek.Encrypt(plain);

            using Pkcs11KekCipher newKek = oldKek.Rotate(newKeyLabel);
            Assert.AreNotEqual(oldKek.KeyId, newKek.KeyId);

            byte[] rewrapped = newKek.RewrapDek(oldKek, wrapped);
            CollectionAssert.AreEqual(plain, newKek.Decrypt(rewrapped));
        }

        [TestMethod]
        [Timeout(120_000, CooperativeCancellation = true)]
        public void Create_WithEnvelope_RoundtripsThroughAesGcmDekCipher()
        {
            using Pkcs11LibraryContext context = CreateContext();
            string keyLabel = NewKeyLabel();
            FileInfo dekFile = new(Path.Combine(Path.GetTempPath(), $"kms-pkcs11-dek-{Guid.NewGuid():N}.bin"));

            try
            {
                using Pkcs11KekCipher kek = CreateCipher(context, keyLabel);
                using AesGcmDekCipher dek = AesGcmDekCipher.Create(kek, dekFile);

                byte[] plain = CreatePlain(48);
                byte[] encrypted = dek.Encrypt(plain);
                byte[] decrypted = dek.Decrypt(encrypted);

                CollectionAssert.AreEqual(plain, decrypted);
            }
            finally
            {
                DeleteQuietly(dekFile);
            }
        }

        [TestMethod]
        [Timeout(120_000, CooperativeCancellation = true)]
        public void Encrypt_AfterDispose_ThrowsObjectDisposedException()
        {
            using Pkcs11LibraryContext context = CreateContext();
            string keyLabel = NewKeyLabel();
            Pkcs11KekCipher cipher = CreateCipher(context, keyLabel);
            cipher.Dispose();

            Assert.ThrowsExactly<ObjectDisposedException>(() => cipher.Encrypt(CreatePlain(32)));
        }

        protected static byte[] CreatePlain(int length)
        {
            byte[] plain = new byte[length];
            if (length > 0)
                RandomNumberGenerator.Fill(plain);
            return plain;
        }

        protected static void DeleteQuietly(FileInfo file)
        {
            try
            {
                file.Refresh();
                if (file.Exists)
                    file.Delete();
            }
            catch (IOException)
            {
            }
        }
    }

    [TestClass]
    [TestCategory("Manual")]
    [DoNotParallelize]
    public sealed class Pkcs11KekCipherSoftHsmTests : Pkcs11KekCipherDeviceTests
    {
        [TestMethod]
        [Timeout(30_000, CooperativeCancellation = true)]
        public void Connect_SoftHsmContext_Succeeds()
        {
            using Pkcs11LibraryContext context = CreateContext();
            Assert.IsNotNull(context);
        }

        protected override Pkcs11LibraryContext CreateContext()
            => SoftHsmPkcs11TestProfile.CreateContext();

        protected override Pkcs11KekCipher CreateCipher(
            Pkcs11LibraryContext context,
            string keyLabel,
            bool createIfMissing = true)
            => SoftHsmPkcs11TestProfile.CreateCipher(context, keyLabel, createIfMissing);

        protected override string NewKeyLabel(string prefix = "kms-pkcs11-test")
            => SoftHsmPkcs11TestProfile.NewKeyLabel(prefix);
    }
}

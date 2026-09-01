using Biz.Bizadm.KMS.Cipher;
using Biz.Bizadm.KMS.Cipher.Tpm;
using System.Security.Cryptography;
using Tpm2Lib;

namespace Biz.Bizadm.KMSTest.Cipher.Tpm
{
    public abstract class TpmKekCipherDeviceTests
    {
        private const int AesBlockSize = 16;

        protected static readonly byte[] Password = "kms-tpm-test-password"u8.ToArray();

        protected abstract Tpm2Device CreateConnectedDevice();

        [TestMethod]
        [Timeout(120_000, CooperativeCancellation = true)]
        [DataRow(0)]
        [DataRow(1)]
        [DataRow(16)]
        [DataRow(32)]
        [DataRow(64)]
        [DataRow(256)]
        public void EncryptDecrypt_Roundtrip_ReturnsOriginalPlaintext(int length)
        {
            byte[] plain = CreatePlain(length);
            FileInfo kekFile = NewKekFile();

            try
            {
                using TpmKekCipher cipher = CreateCipher(kekFile);
                byte[] encrypted = cipher.Encrypt(plain);
                byte[] decrypted = cipher.Decrypt(encrypted);

                CollectionAssert.AreEqual(plain, decrypted);
            }
            finally
            {
                DeleteQuietly(kekFile);
            }
        }

        [TestMethod]
        [Timeout(120_000, CooperativeCancellation = true)]
        public void Encrypt_SamePlaintext_ProducesDifferentCiphertext()
        {
            byte[] plain = CreatePlain(32);
            FileInfo kekFile = NewKekFile();

            try
            {
                using TpmKekCipher cipher = CreateCipher(kekFile);
                byte[] first = cipher.Encrypt(plain);
                byte[] second = cipher.Encrypt(plain);

                CollectionAssert.AreNotEqual(first, second);
                CollectionAssert.AreEqual(plain, cipher.Decrypt(first));
                CollectionAssert.AreEqual(plain, cipher.Decrypt(second));
            }
            finally
            {
                DeleteQuietly(kekFile);
            }
        }

        [TestMethod]
        [Timeout(180_000, CooperativeCancellation = true)]
        public void Decrypt_WithNewInstanceSameCredentials_Succeeds()
        {
            byte[] plain = CreatePlain(64);
            FileInfo kekFile = NewKekFile();

            try
            {
                byte[] encrypted;
                using (TpmKekCipher encryptor = CreateCipher(kekFile))
                    encrypted = encryptor.Encrypt(plain);

                kekFile.Refresh();
                Assert.IsTrue(kekFile.Exists);

                using TpmKekCipher decryptor = CreateCipher(kekFile);
                byte[] decrypted = decryptor.Decrypt(encrypted);

                CollectionAssert.AreEqual(plain, decrypted);
            }
            finally
            {
                DeleteQuietly(kekFile);
            }
        }

        [TestMethod]
        [Timeout(180_000, CooperativeCancellation = true)]
        public void Constructor_WrongPassword_ThrowsWhenLoadingExistingBlob()
        {
            FileInfo kekFile = NewKekFile();

            try
            {
                using (TpmKekCipher cipher = CreateCipher(kekFile))
                    cipher.Encrypt(CreatePlain(16));

                Assert.Throws<TpmException>(() =>
                    TpmKekCipher.Create(CreateConnectedDevice(), new FixedPasswordCredentialProvider("other-password"u8.ToArray()), kekFile));
            }
            finally
            {
                DeleteQuietly(kekFile);
            }
        }

        [TestMethod]
        [Timeout(120_000, CooperativeCancellation = true)]
        public void Decrypt_TamperedCiphertext_DoesNotReturnOriginalPlaintext()
        {
            byte[] plain = CreatePlain(32);
            FileInfo kekFile = NewKekFile();

            try
            {
                using TpmKekCipher cipher = CreateCipher(kekFile);
                byte[] encrypted = cipher.Encrypt(plain);
                encrypted[^1] ^= 0xFF;

                byte[] decrypted = cipher.Decrypt(encrypted);
                CollectionAssert.AreNotEqual(plain, decrypted);
            }
            finally
            {
                DeleteQuietly(kekFile);
            }
        }

        [TestMethod]
        [Timeout(120_000, CooperativeCancellation = true)]
        public void Encrypt_OutputLength_IsIvPlusPlaintext()
        {
            byte[] plain = CreatePlain(48);
            FileInfo kekFile = NewKekFile();

            try
            {
                using TpmKekCipher cipher = CreateCipher(kekFile);
                byte[] encrypted = cipher.Encrypt(plain);
                Assert.HasCount(AesBlockSize + plain.Length, encrypted);
            }
            finally
            {
                DeleteQuietly(kekFile);
            }
        }

        [TestMethod]
        [Timeout(120_000, CooperativeCancellation = true)]
        [DataRow(0)]
        [DataRow(1)]
        [DataRow(AesBlockSize - 1)]
        public void Decrypt_TooShortPayload_ThrowsArgumentException(int length)
        {
            FileInfo kekFile = NewKekFile();

            try
            {
                using TpmKekCipher cipher = CreateCipher(kekFile);
                Assert.ThrowsExactly<ArgumentException>(() => cipher.Decrypt(new byte[length]));
            }
            finally
            {
                DeleteQuietly(kekFile);
            }
        }

        [TestMethod]
        [Timeout(120_000, CooperativeCancellation = true)]
        public void Encrypt_AfterDispose_ThrowsObjectDisposedException()
        {
            FileInfo kekFile = NewKekFile();

            try
            {
                TpmKekCipher cipher = CreateCipher(kekFile);
                cipher.Dispose();

                Assert.ThrowsExactly<ObjectDisposedException>(() => cipher.Encrypt(CreatePlain(8)));
            }
            finally
            {
                DeleteQuietly(kekFile);
            }
        }

        [TestMethod]
        [Timeout(120_000, CooperativeCancellation = true)]
        public void Decrypt_AfterDispose_ThrowsObjectDisposedException()
        {
            FileInfo kekFile = NewKekFile();

            try
            {
                TpmKekCipher cipher = CreateCipher(kekFile);
                byte[] encrypted = cipher.Encrypt(CreatePlain(8));
                cipher.Dispose();

                Assert.ThrowsExactly<ObjectDisposedException>(() => cipher.Decrypt(encrypted));
            }
            finally
            {
                DeleteQuietly(kekFile);
            }
        }

        [TestMethod]
        [Timeout(120_000, CooperativeCancellation = true)]
        public void Rotate_RewrapDek_PreservesPlaintext()
        {
            byte[] plain = CreatePlain(32);
            FileInfo oldKekFile = NewKekFile();
            FileInfo newKekFile = NewKekFile();
            FileInfo dekFile = new(Path.Combine(Path.GetTempPath(), $"kms-tpm-dek-{Guid.NewGuid():N}.bin"));

            try
            {
                using TpmKekCipher oldKek = CreateCipher(oldKekFile);
                byte[] wrapped = oldKek.Encrypt(plain);

                using TpmKekCipher newKek = oldKek.Rotate(newKekFile);
                Assert.AreNotEqual(oldKek.KeyId, newKek.KeyId);

                byte[] rewrapped = newKek.RewrapDek(oldKek, wrapped);
                CollectionAssert.AreEqual(plain, newKek.Decrypt(rewrapped));
            }
            finally
            {
                DeleteQuietly(oldKekFile);
                DeleteQuietly(newKekFile);
                DeleteQuietly(dekFile);
            }
        }

        [TestMethod]
        [Timeout(120_000, CooperativeCancellation = true)]
        public void Dispose_DoesNotCloseSharedDevice()
        {
            byte[] plain = CreatePlain(16);
            FileInfo kekFile1 = NewKekFile();
            FileInfo kekFile2 = NewKekFile();
            Tpm2Device device = CreateConnectedDevice();

            try
            {
                using (TpmKekCipher first = TpmKekCipher.Create(device, new FixedPasswordCredentialProvider(Password), kekFile1))
                {
                    byte[] encrypted = first.Encrypt(plain);
                }

                using TpmKekCipher second = TpmKekCipher.Create(device, new FixedPasswordCredentialProvider(Password), kekFile2);
                CollectionAssert.AreEqual(plain, second.Decrypt(second.Encrypt(plain)));
            }
            finally
            {
                DeleteQuietly(kekFile1);
                DeleteQuietly(kekFile2);
                device.Close();
            }
        }

        [TestMethod]
        [Timeout(120_000, CooperativeCancellation = true)]
        public void Dispose_CalledTwice_DoesNotThrow()
        {
            FileInfo kekFile = NewKekFile();

            try
            {
                TpmKekCipher cipher = CreateCipher(kekFile);
                cipher.Dispose();
                cipher.Dispose();
            }
            finally
            {
                DeleteQuietly(kekFile);
            }
        }

        protected TpmKekCipher CreateCipher(FileInfo kekBlobFile)
            => TpmKekCipher.Create(CreateConnectedDevice(), new FixedPasswordCredentialProvider(Password), kekBlobFile);

        protected static FileInfo NewKekFile()
            => new(Path.Combine(Path.GetTempPath(), $"kms-tpm-kek-{Guid.NewGuid():N}.blob"));

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

        protected static byte[] CreatePlain(int length)
        {
            byte[] plain = new byte[length];
            if (length > 0)
                RandomNumberGenerator.Fill(plain);
            return plain;
        }
    }

    [TestClass]
    [TestCategory("Manual")]
    [DoNotParallelize]
    [OSCondition(OperatingSystems.Windows)]
    public sealed class TpmKekCipherTbsDeviceTests : TpmKekCipherDeviceTests
    {
        [TestMethod]
        [Timeout(30_000, CooperativeCancellation = true)]
        public void Connect_TbsDevice_Succeeds()
        {
            using Tpm2Device device = CreateConnectedDevice();
            Assert.IsNotNull(device);
        }

        protected override Tpm2Device CreateConnectedDevice()
        {
            TbsDevice device = new();
            device.Connect();
            return device;
        }
    }
}

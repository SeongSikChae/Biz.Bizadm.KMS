using Biz.Bizadm.KMS.Cipher;
using System.Security.Cryptography;

namespace Biz.Bizadm.KMSTest.Cipher
{
    [TestClass]
    public sealed class AesGcmDekCipherTests
    {
        private const int Iterations = 10_000;

        private static readonly byte[] Password = "kms-dek-test-password"u8.ToArray();
        private static readonly byte[] Salt = [21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36];

        private static AesGcmKekCipher CreateKekCipher()
            => AesGcmKekCipher.Create(new FixedPasswordCredentialProvider(Password), Salt, Iterations);

        [TestMethod]
        public void Create_NewFile_PersistsAndReloadsSameDek()
        {
            string directory = CreateTempDirectory();
            FileInfo dekFile = new(Path.Combine(directory, "dek.bin"));

            byte[] plain = CreatePlain(64);
            byte[] encrypted;

            using (AesGcmDekCipher creator = AesGcmDekCipher.Create(CreateKekCipher(), dekFile))
            {
                Assert.IsTrue(File.Exists(dekFile.FullName));
                encrypted = creator.Encrypt(plain);
            }

            using AesGcmDekCipher reloaded = AesGcmDekCipher.Create(CreateKekCipher(), dekFile);
            CollectionAssert.AreEqual(plain, reloaded.Decrypt(encrypted));
        }

        [TestMethod]
        public void Create_ExistingFile_DoesNotOverwriteOnDisk()
        {
            string directory = CreateTempDirectory();
            FileInfo dekFile = new(Path.Combine(directory, "dek.bin"));

            using AesGcmDekCipher first = AesGcmDekCipher.Create(CreateKekCipher(), dekFile);
            byte[] onDiskAfterCreate = File.ReadAllBytes(dekFile.FullName);

            using AesGcmDekCipher second = AesGcmDekCipher.Create(CreateKekCipher(), dekFile);
            byte[] onDiskAfterReload = File.ReadAllBytes(dekFile.FullName);

            CollectionAssert.AreEqual(onDiskAfterCreate, onDiskAfterReload);

            byte[] plain = CreatePlain(32);
            byte[] encrypted = first.Encrypt(plain);
            CollectionAssert.AreEqual(plain, second.Decrypt(encrypted));
        }

        [TestMethod]
        public void Create_ConcurrentCreate_UsesSharedDek()
        {
            string directory = CreateTempDirectory();
            FileInfo dekFile = new(Path.Combine(directory, "dek.bin"));
            byte[] plain = CreatePlain(128);
            byte[]? referenceEncrypted = null;
            Exception? failure = null;
            int parallelism = Environment.ProcessorCount * 4;

            Parallel.For(0, parallelism, new ParallelOptions { MaxDegreeOfParallelism = parallelism }, _ =>
            {
                try
                {
                    using AesGcmDekCipher dek = AesGcmDekCipher.Create(CreateKekCipher(), dekFile);
                    byte[] encrypted = dek.Encrypt(plain);
                    Interlocked.CompareExchange(ref referenceEncrypted, encrypted, null);

                    byte[] decrypted = dek.Decrypt(encrypted);
                    if (!plain.AsSpan().SequenceEqual(decrypted))
                        throw new AssertFailedException("동시 생성된 DEK 인스턴스의 복호화 결과가 원문과 일치하지 않습니다.");
                }
                catch (Exception ex)
                {
                    Interlocked.CompareExchange(ref failure, ex, null);
                }
            });

            if (failure is not null)
                throw failure;

            Assert.IsNotNull(referenceEncrypted);

            using AesGcmDekCipher reloaded = AesGcmDekCipher.Create(CreateKekCipher(), dekFile);
            CollectionAssert.AreEqual(plain, reloaded.Decrypt(referenceEncrypted));
        }

        [TestMethod]
        public void Create_ConcurrentFirstCreate_AllInstancesMatchOnDiskEnvelope()
        {
            string directory = CreateTempDirectory();
            FileInfo dekFile = new(Path.Combine(directory, "dek.bin"));
            byte[]? onDiskEnvelope = null;
            Exception? failure = null;
            int parallelism = Environment.ProcessorCount * 4;

            Parallel.For(0, parallelism, new ParallelOptions { MaxDegreeOfParallelism = parallelism }, _ =>
            {
                try
                {
                    using AesGcmDekCipher dek = AesGcmDekCipher.Create(CreateKekCipher(), dekFile);
                    byte[] envelope = File.ReadAllBytes(dekFile.FullName);
                    Interlocked.CompareExchange(ref onDiskEnvelope, envelope, null);

                    byte[] plain = CreatePlain(16);
                    byte[] encrypted = dek.Encrypt(plain);
                    CollectionAssert.AreEqual(plain, dek.Decrypt(encrypted));
                }
                catch (Exception ex)
                {
                    Interlocked.CompareExchange(ref failure, ex, null);
                }
            });

            if (failure is not null)
                throw failure;

            Assert.IsNotNull(onDiskEnvelope);

            using AesGcmDekCipher reloaded = AesGcmDekCipher.Create(CreateKekCipher(), dekFile);
            byte[] plain = CreatePlain(32);
            byte[] encrypted = reloaded.Encrypt(plain);
            CollectionAssert.AreEqual(plain, reloaded.Decrypt(encrypted));
        }

        [TestMethod]
        public void Create_FromEncryptedKey_MatchesFileBackedInstance()
        {
            string directory = CreateTempDirectory();
            FileInfo dekFile = new(Path.Combine(directory, "dek.bin"));
            byte[] plain = CreatePlain(48);

            using AesGcmDekCipher fileBacked = AesGcmDekCipher.Create(CreateKekCipher(), dekFile);
            byte[] envelope = File.ReadAllBytes(dekFile.FullName);
            byte[] ciphertext = fileBacked.Encrypt(plain);

            using AesGcmDekCipher fromBytes = AesGcmDekCipher.Create(CreateKekCipher(), envelope);
            CollectionAssert.AreEqual(plain, fromBytes.Decrypt(ciphertext));
        }

        [TestMethod]
        public void Create_EnvelopeContainsKeyId()
        {
            string directory = CreateTempDirectory();
            FileInfo dekFile = new(Path.Combine(directory, "dek.bin"));

            using AesGcmKekCipher kek = CreateKekCipher();
            using AesGcmDekCipher _ = AesGcmDekCipher.Create(kek, dekFile);

            WrappedDekEnvelope envelope = WrappedDekEnvelope.Deserialize(File.ReadAllBytes(dekFile.FullName));
            Assert.AreEqual(kek.KeyId, envelope.KeyId);
        }

        [TestMethod]
        public void Create_KeyIdMismatch_ThrowsInvalidDataException()
        {
            string directory = CreateTempDirectory();
            FileInfo dekFile = new(Path.Combine(directory, "dek.bin"));

            using (AesGcmDekCipher _ = AesGcmDekCipher.Create(CreateKekCipher(), dekFile))
            {
            }

            using AesGcmKekCipher otherKek = AesGcmKekCipher.Create(
                new FixedPasswordCredentialProvider("other-password"u8.ToArray()),
                Salt,
                Iterations);

            Assert.ThrowsExactly<InvalidDataException>(() => AesGcmDekCipher.Create(otherKek, dekFile));
        }

        [TestMethod]
        public void Rewrap_UpdatesEnvelopeAndPreservesDek()
        {
            string directory = CreateTempDirectory();
            FileInfo dekFile = new(Path.Combine(directory, "dek.bin"));
            byte[] plain = CreatePlain(64);

            using AesGcmKekCipher oldKek = CreateKekCipher();
            using AesGcmDekCipher dek = AesGcmDekCipher.Create(oldKek, dekFile);
            byte[] ciphertext = dek.Encrypt(plain);

            using AesGcmKekCipher newKek = AesGcmKekCipher.CreateRotated(
                new FixedPasswordCredentialProvider("rotated-dek-password"u8.ToArray()),
                [91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106],
                Iterations);

            AesGcmDekCipher.Rewrap(oldKek, newKek, dekFile);

            WrappedDekEnvelope envelope = WrappedDekEnvelope.Deserialize(File.ReadAllBytes(dekFile.FullName));
            Assert.AreEqual(newKek.KeyId, envelope.KeyId);

            using AesGcmDekCipher reloaded = AesGcmDekCipher.Create(newKek, dekFile);
            CollectionAssert.AreEqual(plain, reloaded.Decrypt(ciphertext));
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

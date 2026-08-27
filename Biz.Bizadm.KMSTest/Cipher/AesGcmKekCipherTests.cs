using Biz.Bizadm.KMS.Cipher;
using System.Security.Cryptography;

namespace Biz.Bizadm.KMSTest.Cipher
{
    [TestClass]
    public sealed class AesGcmKekCipherTests
    {
        private const int NonceSize = 12;
        private const int TagSize = 16;
        private const int Iterations = 10_000;

        private static readonly byte[] Password = "kms-test-password"u8.ToArray();
        private static readonly byte[] Salt = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

        private static AesGcmKekCipher CreateCipher()
            => AesGcmKekCipher.Create(new FixedPasswordCredentialProvider(Password), Salt, Iterations);

        [TestMethod]
        [DataRow(0)]
        [DataRow(1)]
        [DataRow(16)]
        [DataRow(32)]
        [DataRow(256)]
        [DataRow(4096)]
        [DataRow(65536)]
        public void EncryptDecrypt_Roundtrip_ReturnsOriginalPlaintext(int length)
        {
            byte[] plain = CreatePlain(length);

            using AesGcmKekCipher cipher = CreateCipher();
            byte[] encrypted = cipher.Encrypt(plain);
            byte[] decrypted = cipher.Decrypt(encrypted);

            CollectionAssert.AreEqual(plain, decrypted);
        }

        [TestMethod]
        public void Encrypt_OutputLength_IsNoncePlusPlainPlusTag()
        {
            byte[] plain = CreatePlain(48);

            using AesGcmKekCipher cipher = CreateCipher();
            byte[] encrypted = cipher.Encrypt(plain);

            Assert.HasCount(NonceSize + plain.Length + TagSize, encrypted);
        }

        [TestMethod]
        public void Encrypt_SamePlaintext_ProducesDifferentCiphertext()
        {
            byte[] plain = CreatePlain(32);

            using AesGcmKekCipher cipher = CreateCipher();
            byte[] first = cipher.Encrypt(plain);
            byte[] second = cipher.Encrypt(plain);

            CollectionAssert.AreNotEqual(first, second);
            CollectionAssert.AreEqual(plain, cipher.Decrypt(first));
            CollectionAssert.AreEqual(plain, cipher.Decrypt(second));
        }

        [TestMethod]
        public void Decrypt_WithNewInstanceSameCredentials_Succeeds()
        {
            byte[] plain = CreatePlain(64);

            using AesGcmKekCipher encryptor = CreateCipher();
            byte[] encrypted = encryptor.Encrypt(plain);

            using AesGcmKekCipher decryptor = CreateCipher();
            byte[] decrypted = decryptor.Decrypt(encrypted);

            CollectionAssert.AreEqual(plain, decrypted);
        }

        [TestMethod]
        public void Decrypt_WrongPassword_ThrowsCryptographicException()
        {
            byte[] plain = CreatePlain(32);

            using AesGcmKekCipher encryptor = CreateCipher();
            byte[] encrypted = encryptor.Encrypt(plain);

            using AesGcmKekCipher decryptor = AesGcmKekCipher.Create(new FixedPasswordCredentialProvider("other-password"u8.ToArray()), Salt, Iterations);

            Assert.ThrowsExactly<AuthenticationTagMismatchException>(() => decryptor.Decrypt(encrypted));
        }

        [TestMethod]
        public void Decrypt_TamperedCiphertext_ThrowsCryptographicException()
        {
            using AesGcmKekCipher cipher = CreateCipher();
            byte[] encrypted = cipher.Encrypt(CreatePlain(32));
            encrypted[NonceSize]++;

            Assert.ThrowsExactly<AuthenticationTagMismatchException>(() => cipher.Decrypt(encrypted));
        }

        [TestMethod]
        public void Decrypt_TamperedTag_ThrowsCryptographicException()
        {
            using AesGcmKekCipher cipher = CreateCipher();
            byte[] encrypted = cipher.Encrypt(CreatePlain(32));
            encrypted[^1] ^= 0xFF;

            Assert.ThrowsExactly<AuthenticationTagMismatchException>(() => cipher.Decrypt(encrypted));
        }

        [TestMethod]
        public void Decrypt_TamperedNonce_ThrowsCryptographicException()
        {
            using AesGcmKekCipher cipher = CreateCipher();
            byte[] encrypted = cipher.Encrypt(CreatePlain(32));
            encrypted[0] ^= 0xFF;

            Assert.ThrowsExactly<AuthenticationTagMismatchException>(() => cipher.Decrypt(encrypted));
        }

        [TestMethod]
        [DataRow(0)]
        [DataRow(1)]
        [DataRow(NonceSize + TagSize - 1)]
        public void Decrypt_TooShortPayload_ThrowsArgumentException(int length)
        {
            using AesGcmKekCipher cipher = CreateCipher();
            byte[] encrypted = new byte[length];

            Assert.ThrowsExactly<ArgumentException>(() => cipher.Decrypt(encrypted));
        }

        [TestMethod]
        public void Encrypt_AfterDispose_ThrowsObjectDisposedException()
        {
            AesGcmKekCipher cipher = CreateCipher();
            cipher.Dispose();

            Assert.ThrowsExactly<ObjectDisposedException>(() => cipher.Encrypt(CreatePlain(8)));
        }

        [TestMethod]
        public void Decrypt_AfterDispose_ThrowsObjectDisposedException()
        {
            AesGcmKekCipher cipher = CreateCipher();
            byte[] encrypted = cipher.Encrypt(CreatePlain(8));
            cipher.Dispose();

            Assert.ThrowsExactly<ObjectDisposedException>(() => cipher.Decrypt(encrypted));
        }

        [TestMethod]
        public void Dispose_CalledTwice_DoesNotThrow()
        {
            AesGcmKekCipher cipher = CreateCipher();
            cipher.Dispose();
            cipher.Dispose();
        }

        [TestMethod]
        public void EncryptDecrypt_ConcurrentRoundtrip_Succeeds()
        {
            byte[] plain = CreatePlain(128);
            using AesGcmKekCipher cipher = CreateCipher();
            int parallelism = Environment.ProcessorCount * 4;
            const int iterationsPerTask = 200;
            Exception? failure = null;

            Parallel.For(0, parallelism, new ParallelOptions { MaxDegreeOfParallelism = parallelism }, _ =>
            {
                try
                {
                    for (int i = 0; i < iterationsPerTask; i++)
                    {
                        byte[] encrypted = cipher.Encrypt(plain);
                        byte[] decrypted = cipher.Decrypt(encrypted);
                        if (!plain.AsSpan().SequenceEqual(decrypted))
                            throw new AssertFailedException("복호화 결과가 원문과 일치하지 않습니다.");
                    }
                }
                catch (Exception ex)
                {
                    Interlocked.CompareExchange(ref failure, ex, null);
                }
            });

            if (failure is not null)
                throw failure;
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

using System.Security.Cryptography;
using Biz.Bizadm.KMS.NetFramework.Cipher;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Biz.Bizadm.KMS.NetFramework.Tests;

[TestClass]
public sealed class SoftwareKekDekTests
{
    [TestMethod]
    public void Pbkdf2AndKeyId_MatchFixedVector()
    {
        byte[] password = System.Text.Encoding.UTF8.GetBytes("password");
        byte[] salt = System.Text.Encoding.UTF8.GetBytes("salt");
        using var kek = AesGcmKekCipher.Create(new TestCredentialProvider(password), salt, 1);
        byte[] expectedKey = FromHex("120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b");
        byte[] expectedHash;
        using (SHA256 sha = SHA256.Create()) expectedHash = sha.ComputeHash(expectedKey);
        string expectedId = "aesgcm:" + BitConverter.ToString(expectedHash).Replace("-", string.Empty).ToLowerInvariant();

        Assert.AreEqual(expectedId, kek.KeyId);
        Assert.AreEqual("aesgcm:d6b653047d32ece1dfe935bf5f155e45149968f7a0bb9cb8bd335929395616e7", kek.KeyId);
        Array.Clear(password, 0, password.Length);
        Array.Clear(expectedKey, 0, expectedKey.Length);
        Array.Clear(expectedHash, 0, expectedHash.Length);
    }

    [TestMethod]
    public void SoftwareKekAndDek_EncryptDecryptAndRejectTampering()
    {
        byte[] password = System.Text.Encoding.UTF8.GetBytes("correct horse battery staple");
        using var kek = AesGcmKekCipher.Create(new TestCredentialProvider(password), new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 }, 1000);
        using var dek = AesGcmDekCipher.CreateRandom();
        byte[] plaintext = { 0, 1, 2, 3, 255 };

        CollectionAssert.AreEqual(plaintext, dek.Decrypt(dek.Encrypt(plaintext)));
        byte[] wrappedKey = kek.Encrypt(Enumerable.Range(0, 32).Select(static value => (byte)value).ToArray());
        CollectionAssert.AreEqual(Enumerable.Range(0, 32).Select(static value => (byte)value).ToArray(), kek.Decrypt(wrappedKey));
        wrappedKey[wrappedKey.Length - 1] ^= 0x01;
        Assert.ThrowsException<CryptographicException>(() => kek.Decrypt(wrappedKey));
    }

    [TestMethod]
    public async Task SoftwareKekAsyncFactoryAndCipherMethods_PreserveBehavior()
    {
        byte[] password = System.Text.Encoding.UTF8.GetBytes("async credential");
        var provider = new TestCredentialProvider(password);
        byte[] salt = { 8, 7, 6, 5, 4, 3, 2, 1 };
        using var kek = await AesGcmKekCipher.CreateAsync(provider, salt, 100);
        byte[] plain = { 42, 17, 0 };
        byte[] encrypted = await kek.EncryptAsync(plain);
        CollectionAssert.AreEqual(plain, await kek.DecryptAsync(encrypted));
        CollectionAssert.AreEqual(new byte[password.Length], provider.LastReturnedPassword!);
    }

    [TestMethod]
    public void CredentialBytes_AreClearedByFactory()
    {
        byte[] password = { 9, 8, 7, 6 };
        var provider = new TestCredentialProvider(password);
        using var kek = AesGcmKekCipher.Create(provider, new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 }, 1);
        CollectionAssert.AreEqual(new byte[password.Length], provider.LastReturnedPassword!);
        Assert.ThrowsException<ArgumentOutOfRangeException>(
            () => AesGcmKekCipher.Create(new TestCredentialProvider(new byte[] { 1 }), new byte[] { 1 }, 0));
    }

    private static byte[] FromHex(string value)
    {
        byte[] bytes = new byte[value.Length / 2];
        for (int i = 0; i < bytes.Length; i++)
        {
            bytes[i] = byte.Parse(value.Substring(i * 2, 2), System.Globalization.NumberStyles.HexNumber);
        }
        return bytes;
    }

    private sealed class TestCredentialProvider : IKekCredentialProvider
    {
        private readonly byte[] password;
        public byte[]? LastReturnedPassword { get; private set; }

        public TestCredentialProvider(byte[] password)
        {
            this.password = (byte[])password.Clone();
        }

        public byte[] GetPassword()
        {
            LastReturnedPassword = (byte[])password.Clone();
            return LastReturnedPassword;
        }

        public Task<byte[]> GetPasswordAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(GetPassword());
        }
    }
}

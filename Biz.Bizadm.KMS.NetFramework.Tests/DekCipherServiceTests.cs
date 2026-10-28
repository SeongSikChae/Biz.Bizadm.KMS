using Biz.Bizadm.KMS.NetFramework.Cipher;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Biz.Bizadm.KMS.NetFramework.Tests;

[TestClass]
public sealed class DekCipherServiceTests
{
    [TestMethod]
    public void EncryptDecrypt_RoundTripsPlaintext()
    {
        using IDekCipherService service = new DekCipherService(AesGcmDekCipher.CreateRandom());

        string encrypted = service.Encrypt("hello-kms");
        Assert.IsTrue(encrypted.StartsWith("DEKENC:", StringComparison.Ordinal));
        Assert.AreEqual("hello-kms", service.Decrypt(encrypted));
    }

    [TestMethod]
    public void EncryptDecryptAsync_RoundTripsPlaintext()
    {
        using IDekCipherService service = new DekCipherService(AesGcmDekCipher.CreateRandom());

        string encrypted = service.EncryptAsync("async-plain").GetAwaiter().GetResult();
        Assert.IsTrue(service.StartsWithFromPrefix(encrypted));
        Assert.AreEqual("async-plain", service.DecryptAsync(encrypted).GetAwaiter().GetResult());
    }

    [TestMethod]
    public void StartsWithFromPrefix_DetectsPrefix()
    {
        using IDekCipherService service = new DekCipherService(DekCipherFactory.CreateNull());

        Assert.IsTrue(service.StartsWithFromPrefix("DEKENC:abc"));
        Assert.IsFalse(service.StartsWithFromPrefix("plain"));
        Assert.ThrowsException<ArgumentNullException>(() => service.StartsWithFromPrefix(null!));
    }

    [TestMethod]
    public void Decrypt_WithoutPrefix_Throws()
    {
        using IDekCipherService service = new DekCipherService(DekCipherFactory.CreateNull());

        Assert.ThrowsException<ArgumentException>(() => service.Decrypt("not-encrypted"));
        Assert.ThrowsException<ArgumentException>(
            () => service.DecryptAsync("not-encrypted").GetAwaiter().GetResult());
    }

    [TestMethod]
    public void NullCipher_PassthroughWithPrefix()
    {
        using IDekCipherService service = new DekCipherService(DekCipherFactory.CreateNull());

        string encrypted = service.Encrypt("passthrough");
        Assert.IsTrue(encrypted.StartsWith("DEKENC:", StringComparison.Ordinal));
        Assert.AreEqual("passthrough", service.Decrypt(encrypted));
    }

    [TestMethod]
    public void Dispose_LeaveOpen_DoesNotDisposeUnderlyingCipher()
    {
        using AesGcmDekCipher dek = AesGcmDekCipher.CreateRandom();
        IDekCipherService service = new DekCipherService(dek, leaveOpen: true);
        string encrypted = service.Encrypt("keep-open");
        service.Dispose();

        byte[] cipherBytes = Convert.FromBase64String(encrypted.Substring("DEKENC:".Length));
        CollectionAssert.AreEqual(
            System.Text.Encoding.UTF8.GetBytes("keep-open"),
            dek.Decrypt(cipherBytes));
    }

    [TestMethod]
    public void Dispose_Default_DisposesUnderlyingCipher()
    {
        AesGcmDekCipher dek = AesGcmDekCipher.CreateRandom();
        new DekCipherService(dek).Dispose();

        Assert.ThrowsException<ObjectDisposedException>(() => dek.Encrypt(new byte[] { 1 }));
    }
}

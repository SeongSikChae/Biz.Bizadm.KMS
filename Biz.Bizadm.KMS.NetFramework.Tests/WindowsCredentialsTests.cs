using System.Text;
using Biz.Bizadm.KMS.NetFramework.Cipher;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Biz.Bizadm.KMS.NetFramework.Tests;

[TestClass]
public sealed class WindowsCredentialsTests
{
    [TestMethod]
    public void StoreGetRemove_RoundTripsPasswordBytes()
    {
        if (Environment.OSVersion.Platform != PlatformID.Win32NT)
        {
            Assert.Inconclusive("Windows Credential Manager requires Windows.");
        }

        IWindowsKekCredentialStore provider = WindowsCredentialManagerKekCredentialProvider.Create(
            NewService(),
            "unit-test");
        byte[] password = Encoding.UTF8.GetBytes("unit-test-password-bytes");

        try
        {
            provider.StorePassword(password);
            CollectionAssert.AreEqual(password, provider.GetPassword());
            Assert.IsTrue(provider.RemovePassword());
            Assert.ThrowsException<InvalidOperationException>(() => provider.GetPassword());
        }
        finally
        {
            provider.RemovePassword();
        }
    }

    [TestMethod]
    public void AesGcmKekCipher_AcceptsWindowsCredentialProvider()
    {
        if (Environment.OSVersion.Platform != PlatformID.Win32NT)
        {
            Assert.Inconclusive("Windows Credential Manager requires Windows.");
        }

        IWindowsKekCredentialStore provider = WindowsCredentialManagerKekCredentialProvider.Create(
            NewService(),
            "unit-test");
        byte[] password = Encoding.UTF8.GetBytes("os-credential-password");
        byte[] salt = Encoding.UTF8.GetBytes("0123456789abcdef");
        byte[] plain = Encoding.UTF8.GetBytes("hello");

        try
        {
            provider.StorePassword(password);

            using (AesGcmKekCipher encryptor = AesGcmKekCipher.Create(provider, salt, 10_000))
            {
                byte[] cipher = encryptor.Encrypt(plain);
                using (AesGcmKekCipher decryptor = AesGcmKekCipher.Create(provider, salt, 10_000))
                {
                    CollectionAssert.AreEqual(plain, decryptor.Decrypt(cipher));
                    Assert.AreEqual(encryptor.KeyId, decryptor.KeyId);
                }
            }
        }
        finally
        {
            provider.RemovePassword();
        }
    }

    [TestMethod]
    public void StorePassword_Empty_ThrowsArgumentException()
    {
        if (Environment.OSVersion.Platform != PlatformID.Win32NT)
        {
            Assert.Inconclusive("Windows Credential Manager requires Windows.");
        }

        IWindowsKekCredentialStore provider = WindowsCredentialManagerKekCredentialProvider.Create(
            NewService(),
            "unit-test");
        Assert.ThrowsException<ArgumentException>(() => provider.StorePassword(Array.Empty<byte>()));
    }

    private static string NewService()
        => "bizadm-kms://test/" + Guid.NewGuid().ToString("N");
}

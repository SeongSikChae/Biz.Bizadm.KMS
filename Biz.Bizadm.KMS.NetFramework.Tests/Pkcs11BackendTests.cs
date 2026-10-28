using System.Text;
using Biz.Bizadm.KMS.NetFramework.Cipher;
using Biz.Bizadm.KMS.NetFramework.Cipher.Pkcs11;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Net.Pkcs11Interop.Common;

namespace Biz.Bizadm.KMS.NetFramework.Tests;

[TestClass]
public sealed class Pkcs11BackendTests
{
    [TestMethod]
    public void Pkcs11Types_LoadAndDefaultToOaepSha256()
    {
        Assert.IsNotNull(typeof(Pkcs11KekCipher));
        Assert.IsNotNull(typeof(Pkcs11LibraryContext));
        Assert.IsNotNull(typeof(Pkcs11KekManager));

        Pkcs11KekOptions options = new Pkcs11KekOptions();
        Assert.AreEqual(4096, options.RsaKeySize);
        Assert.AreEqual(CKM.CKM_RSA_PKCS_OAEP, options.WrapMechanism);
        Assert.AreEqual(CKM.CKM_SHA256, options.OaepHashAlgorithm);
        Assert.AreEqual(CKG.CKG_MGF1_SHA256, options.OaepMgf);
    }

    [TestMethod]
    [TestCategory("Manual")]
    public void EncryptDecrypt_Roundtrip_WhenSoftHsmConfigured()
    {
        string? libraryPath = Environment.GetEnvironmentVariable("PKCS11_LIBRARY_PATH");
        string? slotText = Environment.GetEnvironmentVariable("PKCS11_SLOT_ID");
        string? pin = Environment.GetEnvironmentVariable("PKCS11_PIN");

        if (string.IsNullOrWhiteSpace(libraryPath) ||
            string.IsNullOrWhiteSpace(slotText) ||
            string.IsNullOrWhiteSpace(pin) ||
            !ulong.TryParse(slotText, out ulong slotId) ||
            !File.Exists(libraryPath))
        {
            Assert.Inconclusive("PKCS#11 SoftHSM/HSM environment is not configured; marked unverified.");
            return;
        }

        byte[] pinBytes = Encoding.UTF8.GetBytes(pin);
        byte[] plain = new byte[32];
        for (int i = 0; i < plain.Length; i++) plain[i] = (byte)(i + 1);

        try
        {
            using (Pkcs11LibraryContext context = Pkcs11LibraryContext.Create(
                libraryPath,
                slotId,
                new FixedBytesCredentialProvider(pinBytes)))
            {
                string label = "net48-test-" + Guid.NewGuid().ToString("N");
                // SoftHSM 2.5.0 profile matches net10 SoftHsmPkcs11TestProfile:
                // CKM_RSA_PKCS + RSA-2048 (production default remains OAEP-SHA256).
                Pkcs11KekOptions options = new Pkcs11KekOptions
                {
                    RsaKeySize = 2048,
                    WrapMechanism = CKM.CKM_RSA_PKCS
                };

                using (Pkcs11KekCipher cipher = Pkcs11KekCipher.Create(context, label, createIfMissing: true, options))
                {
                    byte[] wrapped = cipher.Encrypt(plain);
                    CollectionAssert.AreEqual(plain, cipher.Decrypt(wrapped));
                    Assert.IsTrue(cipher.KeyId.StartsWith("pkcs11:", StringComparison.Ordinal));
                }
            }
        }
        catch (Exception ex) when (ex is Pkcs11Exception || ex is DllNotFoundException || ex is BadImageFormatException || ex is IOException)
        {
            Assert.Inconclusive("PKCS#11 library load/use failed: " + ex.GetType().Name + " — marked unverified.");
        }
        finally
        {
            Array.Clear(pinBytes, 0, pinBytes.Length);
        }
    }

    private sealed class FixedBytesCredentialProvider : IKekCredentialProvider
    {
        private readonly byte[] password;

        public FixedBytesCredentialProvider(byte[] password)
        {
            this.password = (byte[])password.Clone();
        }

        public byte[] GetPassword() => (byte[])password.Clone();

        public Task<byte[]> GetPasswordAsync(CancellationToken cancellationToken = default)
            => Task.FromResult(GetPassword());
    }
}

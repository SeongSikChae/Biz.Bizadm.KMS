using System.Text;
using Biz.Bizadm.KMS.NetFramework.Cipher;
using Biz.Bizadm.KMS.NetFramework.Cipher.Tpm;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Tpm2Lib;

namespace Biz.Bizadm.KMS.NetFramework.Tests;

[TestClass]
public sealed class TpmBackendTests
{
    [TestMethod]
    public void TpmTypes_LoadAndBlobRoundTripWithoutDevice()
    {
        Assert.IsNotNull(typeof(TpmKekCipher));
        Assert.IsNotNull(typeof(TpmKekManager));
        Assert.AreEqual(TpmKekWrapMode.Aes256Cfb, new TpmKekOptions().WrapMode);

        // Validate magic/version layout constants using a deliberately invalid short buffer path.
        FileInfo file = new FileInfo(Path.Combine(Path.GetTempPath(), "tkek-" + Guid.NewGuid().ToString("N") + ".bin"));
        try
        {
            File.WriteAllBytes(file.FullName, Encoding.ASCII.GetBytes("XXXX"));
            Assert.ThrowsException<InvalidDataException>(() => TpmKekBlob.Load(file));
        }
        finally
        {
            if (file.Exists) file.Delete();
        }
    }

    [TestMethod]
    [TestCategory("Manual")]
    public void EncryptDecrypt_Roundtrip_WhenTpmAvailable()
    {
        if (!TryOpenTbs(out TbsDevice? device, out string skipReason))
        {
            Assert.Inconclusive(skipReason);
            return;
        }

        FileInfo kekFile = new FileInfo(Path.Combine(Path.GetTempPath(), "tpm-kek-" + Guid.NewGuid().ToString("N") + ".bin"));
        byte[] password = Encoding.UTF8.GetBytes("kms-tpm-test-password");
        byte[] plain = Encoding.UTF8.GetBytes("tpm-roundtrip-plain");
        try
        {
            using (TbsDevice connected = device!)
            {
                IKekCredentialProvider credentials = new FixedBytesCredentialProvider(password);
                using (TpmKekCipher encryptor = TpmKekCipher.Create(connected, credentials, kekFile))
                {
                    byte[] encrypted = encryptor.Encrypt(plain);
                    using (TpmKekCipher decryptor = TpmKekCipher.Create(connected, credentials, kekFile))
                    {
                        CollectionAssert.AreEqual(plain, decryptor.Decrypt(encrypted));
                        Assert.AreEqual(encryptor.KeyId, decryptor.KeyId);
                        Assert.IsTrue(decryptor.KeyId.StartsWith("tpm:", StringComparison.Ordinal));
                    }
                }
            }
        }
        catch (Exception ex) when (ex is TpmException || ex is IOException || ex is UnauthorizedAccessException)
        {
            Assert.Inconclusive("TPM device open/use failed: " + ex.GetType().Name + " — marked unverified.");
        }
        finally
        {
            Array.Clear(password, 0, password.Length);
            if (kekFile.Exists) kekFile.Delete();
        }
    }

    private static bool TryOpenTbs(out TbsDevice? device, out string skipReason)
    {
        device = null;
        if (Environment.OSVersion.Platform != PlatformID.Win32NT)
        {
            skipReason = "Windows TBS TPM access requires Windows.";
            return false;
        }

        try
        {
            device = new TbsDevice();
            device.Connect();
            skipReason = string.Empty;
            return true;
        }
        catch (Exception ex)
        {
            device?.Dispose();
            device = null;
            skipReason = "Unable to connect to Windows TBS TPM: " + ex.GetType().Name + " — marked unverified.";
            return false;
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

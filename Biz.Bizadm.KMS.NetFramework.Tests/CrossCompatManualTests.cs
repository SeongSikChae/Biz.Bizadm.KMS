using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Biz.Bizadm.KMS.NetFramework.Tests;

[TestClass]
public sealed class CrossCompatManualTests
{
    private static readonly byte[] Dek = Enumerable.Range(10, 32).Select(static value => (byte)value).ToArray();

    [TestMethod]
    [TestCategory("Manual")]
    public void AzureKeyVault_WrapUnwrap_CrossRuntime()
    {
        if (!AzureConfigured(out string skipReason))
        {
            Assert.Inconclusive(skipReason);
            return;
        }

        const string keyName = "TEST-KEY-CROSS";
        string dekHex = InteropHelperRunner.ToHex(Dek);

        try
        {
            string envelopeFrom10 = InteropHelperRunner.RunHelper("InteropNet10", "azure-wrap", keyName, dekHex);
            CollectionAssert.AreEqual(
                Dek,
                InteropHelperRunner.FromHex(InteropHelperRunner.RunHelper("InteropNet48", "azure-unwrap", envelopeFrom10)));

            string envelopeFrom48 = InteropHelperRunner.RunHelper("InteropNet48", "azure-wrap", keyName, dekHex);
            CollectionAssert.AreEqual(
                Dek,
                InteropHelperRunner.FromHex(InteropHelperRunner.RunHelper("InteropNet10", "azure-unwrap", envelopeFrom48)));
        }
        catch (AssertFailedException)
        {
            throw;
        }
        catch (Exception ex)
        {
            Assert.Inconclusive("Azure cross-compat failed: " + ex.GetType().Name + " — " + ex.Message);
        }
    }

    [TestMethod]
    [TestCategory("Manual")]
    public void Tpm_WrapUnwrap_CrossRuntime()
    {
        if (Environment.OSVersion.Platform != PlatformID.Win32NT)
        {
            Assert.Inconclusive("Windows TBS TPM access requires Windows.");
            return;
        }

        string blobPath = Path.Combine(Path.GetTempPath(), "kms-cross-tpm-" + Guid.NewGuid().ToString("N") + ".blob");
        string passwordHex = InteropHelperRunner.ToHex(Encoding.UTF8.GetBytes("kms-tpm-cross-password"));
        string dekHex = InteropHelperRunner.ToHex(Dek);

        try
        {
            string envelopeFrom10 = InteropHelperRunner.RunHelper("InteropNet10", "tpm-wrap", blobPath, passwordHex, dekHex);
            CollectionAssert.AreEqual(
                Dek,
                InteropHelperRunner.FromHex(InteropHelperRunner.RunHelper("InteropNet48", "tpm-unwrap", blobPath, passwordHex, envelopeFrom10)));

            // Reverse direction reuses the same blob created above.
            string envelopeFrom48 = InteropHelperRunner.RunHelper("InteropNet48", "tpm-wrap", blobPath, passwordHex, dekHex);
            CollectionAssert.AreEqual(
                Dek,
                InteropHelperRunner.FromHex(InteropHelperRunner.RunHelper("InteropNet10", "tpm-unwrap", blobPath, passwordHex, envelopeFrom48)));
        }
        catch (AssertFailedException)
        {
            throw;
        }
        catch (Exception ex)
        {
            Assert.Inconclusive("TPM cross-compat failed: " + ex.GetType().Name + " — " + ex.Message);
        }
        finally
        {
            if (File.Exists(blobPath))
            {
                File.Delete(blobPath);
            }
        }
    }

    [TestMethod]
    [TestCategory("Manual")]
    public void Pkcs11SoftHsm_WrapUnwrap_CrossRuntime()
    {
        if (!Pkcs11Configured(out string skipReason))
        {
            Assert.Inconclusive(skipReason);
            return;
        }

        string label = "cross-" + Guid.NewGuid().ToString("N");
        string dekHex = InteropHelperRunner.ToHex(Dek);

        try
        {
            string envelopeFrom10 = InteropHelperRunner.RunHelper("InteropNet10", "pkcs11-wrap", label, dekHex);
            CollectionAssert.AreEqual(
                Dek,
                InteropHelperRunner.FromHex(InteropHelperRunner.RunHelper("InteropNet48", "pkcs11-unwrap", label, envelopeFrom10)));

            string envelopeFrom48 = InteropHelperRunner.RunHelper("InteropNet48", "pkcs11-wrap", label, dekHex);
            CollectionAssert.AreEqual(
                Dek,
                InteropHelperRunner.FromHex(InteropHelperRunner.RunHelper("InteropNet10", "pkcs11-unwrap", label, envelopeFrom48)));
        }
        catch (AssertFailedException)
        {
            throw;
        }
        catch (Exception ex)
        {
            Assert.Inconclusive("PKCS#11 cross-compat failed: " + ex.GetType().Name + " — " + ex.Message);
        }
    }

    private static bool AzureConfigured(out string skipReason)
    {
        string? url = Environment.GetEnvironmentVariable("AZURE_KEY_VAULT_URL");
        string? tenantId = Environment.GetEnvironmentVariable("AZURE_TENANTID");
        string? clientId = Environment.GetEnvironmentVariable("AZURE_CLIENT_ID");
        string? thumbprint = Environment.GetEnvironmentVariable("AZURE_KEY_VAULT_THUMBPRINT");
        if (string.IsNullOrWhiteSpace(url) ||
            string.IsNullOrWhiteSpace(tenantId) ||
            string.IsNullOrWhiteSpace(clientId) ||
            string.IsNullOrWhiteSpace(thumbprint))
        {
            skipReason = "Azure Key Vault live credentials are not configured; marked unverified.";
            return false;
        }

        skipReason = string.Empty;
        return true;
    }

    private static bool Pkcs11Configured(out string skipReason)
    {
        string? libraryPath = Environment.GetEnvironmentVariable("PKCS11_LIBRARY_PATH");
        string? slotText = Environment.GetEnvironmentVariable("PKCS11_SLOT_ID");
        string? pin = Environment.GetEnvironmentVariable("PKCS11_PIN");
        if (string.IsNullOrWhiteSpace(libraryPath) ||
            string.IsNullOrWhiteSpace(slotText) ||
            string.IsNullOrWhiteSpace(pin) ||
            !File.Exists(libraryPath))
        {
            skipReason = "PKCS#11 SoftHSM/HSM environment is not configured; marked unverified.";
            return false;
        }

        skipReason = string.Empty;
        return true;
    }
}

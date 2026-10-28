using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Azure.Identity;
using Biz.Bizadm.KMS.NetFramework.Cipher;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Biz.Bizadm.KMS.NetFramework.Tests;

[TestClass]
public sealed class AzureKeyVaultTests
{
    [TestMethod]
    public void AzureTypes_LoadAndExposeExpectedKeyIdPrefix()
    {
        Assert.AreEqual(typeof(IKekCipher), typeof(AzureKeyVaultKekCipher).GetInterface(nameof(IKekCipher)));
        Assert.AreEqual(typeof(IKekCredentialProvider), typeof(AzureKeyVaultKekCredentialProvider).GetInterface(nameof(IKekCredentialProvider)));
        Assert.IsTrue(typeof(AzureKeyVaultKekCipher).Assembly.GetType("Biz.Bizadm.KMS.NetFramework.Cipher.AzureKeyVaultKekManager") is not null);
    }

    [TestMethod]
    [TestCategory("Manual")]
    public async Task EncryptDecrypt_Roundtrip_WhenAzureConfigured()
    {
        if (!TryCreateCredential(out ClientCertificateCredential? credential, out Uri? vaultUri, out string skipReason))
        {
            Assert.Inconclusive(skipReason);
            return;
        }

        using AzureKeyVaultKekCipher cipher = await AzureKeyVaultKekCipher.CreateAsync(
            vaultUri!,
            credential!,
            "TEST-KEY-NET48");

        byte[] dek = new byte[32];
        using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(dek);
        }

        try
        {
            byte[] wrapped = cipher.Encrypt(dek);
            CollectionAssert.AreEqual(dek, cipher.Decrypt(wrapped));
            Assert.IsTrue(cipher.KeyId.StartsWith("azurekv:TEST-KEY-NET48:", StringComparison.Ordinal));

            using AzureKeyVaultKekCipher rotated = await cipher.RotateAsync();
            byte[] rewrapped = rotated.RewrapDek(cipher, wrapped);
            Assert.AreNotEqual(cipher.KeyId, rotated.KeyId);
            CollectionAssert.AreEqual(dek, rotated.Decrypt(rewrapped));
        }
        finally
        {
            Array.Clear(dek, 0, dek.Length);
        }
    }

    private static bool TryCreateCredential(
        out ClientCertificateCredential? credential,
        out Uri? vaultUri,
        out string skipReason)
    {
        credential = null;
        vaultUri = null;

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

        if (!Uri.TryCreate(url, UriKind.Absolute, out vaultUri))
        {
            skipReason = "AZURE_KEY_VAULT_URL is not a valid absolute URI.";
            return false;
        }

        using X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
        X509Certificate2Collection certificates = store.Certificates.Find(
            X509FindType.FindByThumbprint,
            thumbprint,
            validOnly: false);
        X509Certificate2? certificate = certificates.OfType<X509Certificate2>().FirstOrDefault(x => x.HasPrivateKey);
        if (certificate is null)
        {
            skipReason = "No private-key certificate matching AZURE_KEY_VAULT_THUMBPRINT was found.";
            return false;
        }

        credential = new ClientCertificateCredential(tenantId, clientId, certificate);
        skipReason = string.Empty;
        return true;
    }
}

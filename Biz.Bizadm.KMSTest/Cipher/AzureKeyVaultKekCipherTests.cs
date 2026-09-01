using Azure.Identity;
using Biz.Bizadm.KMS.Cipher;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Biz.Bizadm.KMSTest.Cipher
{
    [TestClass]
    [TestCategory("Manual")]
    [DoNotParallelize]
    [OSCondition(OperatingSystems.Windows)]
    public sealed class AzureKeyVaultKekCipherTests
    {
        public TestContext TestContext { get; set; } = null!;

        [TestMethod]
        public async Task EncryptDecryptTest()
        {
            using X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

            X509Certificate2Collection certificates = store.Certificates.Find(
                X509FindType.FindByThumbprint, Environment.GetEnvironmentVariable("AZURE_KEY_VAULT_THUMBPRINT") ?? string.Empty, validOnly: false);

            using X509Certificate2 certificate = certificates.OfType<X509Certificate2>().FirstOrDefault(x => x.HasPrivateKey) ?? throw new InvalidOperationException($"개인 키가 포함된 인증서를 찾을 수 없습니다. {Environment.GetEnvironmentVariable("AZURE_KEY_VAULT_THUMBPRINT")}");

            ClientCertificateCredential credential = new ClientCertificateCredential(Environment.GetEnvironmentVariable("AZURE_TENANTID"), Environment.GetEnvironmentVariable("AZURE_CLIENT_ID"), certificate);

            using AzureKeyVaultKekCipher cipher = await AzureKeyVaultKekCipher.CreateAsync(
                new Uri(Environment.GetEnvironmentVariable("AZURE_KEY_VAULT_URL") ?? string.Empty),
                credential,
                "TEST-KEY",
                cancellationToken: TestContext.CancellationToken);

            byte[] dek = RandomNumberGenerator.GetBytes(32);
            byte[] wrapped = cipher.Encrypt(dek);
            string oldKeyId = cipher.KeyId;

            using AzureKeyVaultKekCipher rotated = await cipher.RotateAsync(TestContext.CancellationToken);
            byte[] rewrapped = rotated.RewrapDek(cipher, wrapped);

            Assert.AreNotEqual(oldKeyId, rotated.KeyId);
            CollectionAssert.AreEqual(dek, rotated.Decrypt(rewrapped));
        }
    }
}

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
    public sealed class AzureKeyVaultKekManagerTests
    {
        public TestContext TestContext { get; set; } = null!;

        [TestMethod]
        public async Task Rotate_RewrapDek_UpdatesEnvelope()
        {
            using X509Store store = new(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

            X509Certificate2Collection certificates = store.Certificates.Find(
                X509FindType.FindByThumbprint,
                Environment.GetEnvironmentVariable("AZURE_KEY_VAULT_THUMBPRINT") ?? string.Empty,
                validOnly: false);

            using X509Certificate2 certificate = certificates.OfType<X509Certificate2>()
                .FirstOrDefault(x => x.HasPrivateKey)
                ?? throw new InvalidOperationException("개인 키가 포함된 인증서를 찾을 수 없습니다.");

            ClientCertificateCredential credential = new(
                Environment.GetEnvironmentVariable("AZURE_TENANTID"),
                Environment.GetEnvironmentVariable("AZURE_CLIENT_ID"),
                certificate);

            string keyName = $"TEST-KEY-{Guid.NewGuid():N}";
            using AzureKeyVaultKekManager manager = await AzureKeyVaultKekManager.CreateAsync(
                new Uri(Environment.GetEnvironmentVariable("AZURE_KEY_VAULT_URL") ?? string.Empty),
                credential,
                keyName,
                cancellationToken: TestContext.CancellationToken);

            byte[] dek = RandomNumberGenerator.GetBytes(32);
            byte[] wrapped = manager.Current.Encrypt(dek);
            byte[] envelope = new WrappedDekEnvelope(manager.Current.KeyId, wrapped).Serialize();
            string oldKeyId = manager.Current.KeyId;

            await manager.RotateAsync(TestContext.CancellationToken);
            byte[] rewrapped = await manager.RewrapDekAsync(envelope, TestContext.CancellationToken);

            WrappedDekEnvelope updated = WrappedDekEnvelope.Deserialize(rewrapped);
            Assert.AreEqual(manager.Current.KeyId, updated.KeyId);
            Assert.AreNotEqual(oldKeyId, updated.KeyId);
            CollectionAssert.AreEqual(dek, manager.Current.Decrypt(updated.WrappedKey));
            Assert.IsTrue(manager.KnownKeyIds.Contains(oldKeyId));
        }
    }
}

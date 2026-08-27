using Azure.Identity;
using Biz.Bizadm.KMS.Cipher;
using System.Security.Cryptography.X509Certificates;

namespace Biz.Bizadm.KMSTest.Cipher
{
    [TestClass]
    [TestCategory("Manual")]
    [OSCondition(OperatingSystems.Windows)]
    public sealed class AzureKeyVaultKekCredentialProviderTests
    {
        [TestMethod]
        public void GetPasswordTest()
        {
            using X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

            X509Certificate2Collection certificates = store.Certificates.Find(
                X509FindType.FindByThumbprint, Environment.GetEnvironmentVariable("AZURE_KEY_VAULT_THUMBPRINT") ?? string.Empty, validOnly: false);

            using X509Certificate2 certificate = certificates.OfType<X509Certificate2>().FirstOrDefault(x => x.HasPrivateKey) ?? throw new InvalidOperationException($"개인 키가 포함된 인증서를 찾을 수 없습니다. {Environment.GetEnvironmentVariable("AZURE_KEY_VAULT_THUMBPRINT")}");

            ClientCertificateCredential credential = new ClientCertificateCredential(Environment.GetEnvironmentVariable("AZURE_TENANTID"), Environment.GetEnvironmentVariable("AZURE_CLIENT_ID"), certificate);

            AzureKeyVaultKekCredentialProvider provider = new AzureKeyVaultKekCredentialProvider(
                new Uri(Environment.GetEnvironmentVariable("AZURE_KEY_VAULT_URL") ?? string.Empty),
                credential,
                "TEST-SECRET");

            byte[] password = provider.GetPassword();
            Assert.HasCount(32, password);
        }
    }
}

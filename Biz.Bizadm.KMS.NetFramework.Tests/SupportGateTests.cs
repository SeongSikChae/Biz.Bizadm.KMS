using Biz.Bizadm.KMS.NetFramework.Cipher;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Biz.Bizadm.KMS.NetFramework.Tests;

[TestClass]
public sealed class SupportGateTests
{
    [TestMethod]
    public void FeatureSupport_RecordsVerifiedStatuses()
    {
        Assert.AreEqual(FeatureVerificationStatus.Supported, FeatureSupport.SoftwareAesGcm);
        Assert.AreEqual(FeatureVerificationStatus.Supported, FeatureSupport.SoftwareKekDek);
        Assert.AreEqual(FeatureVerificationStatus.Supported, FeatureSupport.KdeKEnvelope);
        Assert.AreEqual(FeatureVerificationStatus.Supported, FeatureSupport.WindowsCredentials);
        Assert.AreEqual(FeatureVerificationStatus.Supported, FeatureSupport.Tpm);
        Assert.AreEqual(FeatureVerificationStatus.Supported, FeatureSupport.AzureKeyVault);
        Assert.AreEqual(FeatureVerificationStatus.Supported, FeatureSupport.Pkcs11);
        Assert.AreEqual(FeatureVerificationStatus.Unsupported, FeatureSupport.LinuxMacOsCredentials);
    }

    [TestMethod]
    public void UnsupportedFeature_ThrowsNotImplementedExceptionBeforeSideEffects()
    {
        bool sideEffect = false;
        try
        {
            FeatureSupport.ThrowIfUnsupported(
                "LinuxMacOsCredentials",
                FeatureSupport.LinuxMacOsCredentials,
                "Linux/macOS credential stores are out of scope for the independent net48 project.");
            sideEffect = true;
            Assert.Fail("Expected UnsupportedFeatureException.");
        }
        catch (UnsupportedFeatureException ex)
        {
            Assert.IsFalse(sideEffect);
            Assert.IsInstanceOfType(ex, typeof(NotImplementedException));
            StringAssert.Contains(ex.Message, "LinuxMacOsCredentials");
            StringAssert.Contains(ex.Message, ".NET Framework 4.8");
        }
    }

    [TestMethod]
    public void UnsupportedAsyncContract_ReturnsFaultedTask()
    {
        Task<byte[]> task = Task.FromException<byte[]>(
            new UnsupportedFeatureException(
                "LinuxMacOsCredentials",
                "Linux/macOS credential stores are out of scope for the independent net48 project."));

        Assert.IsTrue(task.IsFaulted);
        Assert.IsInstanceOfType(task.Exception!.InnerException, typeof(UnsupportedFeatureException));
        Assert.IsNull(task.Exception.InnerException!.Data["plaintext"]);
    }
}

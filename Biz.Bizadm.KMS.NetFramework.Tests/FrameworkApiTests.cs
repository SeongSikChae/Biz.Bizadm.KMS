using Biz.Bizadm.KMS.NetFramework.Cipher;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Biz.Bizadm.KMS.NetFramework.Tests;

[TestClass]
public sealed class FrameworkApiTests
{
    [TestMethod]
    public void NullDekCipher_PassesThroughSameArrayForSyncAndAsyncCalls()
    {
        IDekCipher cipher = DekCipherFactory.CreateNull();
        byte[] value = { 1, 2, 3 };

        Assert.AreSame(value, cipher.Encrypt(value));
        Assert.AreSame(value, cipher.Decrypt(value));
        Assert.AreSame(value, cipher.EncryptAsync(value).GetAwaiter().GetResult());
        Assert.AreSame(value, cipher.DecryptAsync(value).GetAwaiter().GetResult());
        cipher.Dispose();
    }

    [TestMethod]
    public void NullDekCipher_RejectsNullAndHonorsCancellation()
    {
        IDekCipher cipher = DekCipherFactory.CreateNull();
        Assert.ThrowsException<ArgumentNullException>(() => cipher.Encrypt(null!));
        Assert.ThrowsException<ArgumentNullException>(() => cipher.Decrypt(null!));

        using (var source = new CancellationTokenSource())
        {
            source.Cancel();
            Assert.ThrowsException<OperationCanceledException>(
                () => cipher.EncryptAsync(new byte[0], source.Token).GetAwaiter().GetResult());
        }
    }

    [TestMethod]
    public void UnsupportedFeatureException_IsNotImplementedExceptionWithoutSecretData()
    {
        var exception = new UnsupportedFeatureException("test backend", "test reason");

        Assert.IsInstanceOfType<NotImplementedException>(exception);
        StringAssert.Contains(exception.Message, ".NET Framework 4.8");
        StringAssert.Contains(exception.Message, "test backend");
        StringAssert.Contains(exception.Message, "test reason");
        Assert.ThrowsException<ArgumentException>(() => new UnsupportedFeatureException("", "reason"));
    }
}

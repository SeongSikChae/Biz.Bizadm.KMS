using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Biz.Bizadm.KMS.NetFramework.Tests;

[TestClass]
public sealed class CrossCompatTests
{
    private static readonly byte[] Password = Encoding.UTF8.GetBytes("cross-compat-password");
    private static readonly byte[] Salt = Encoding.UTF8.GetBytes("0123456789abcdef");
    private const int Iterations = 1000;
    private static readonly byte[] Dek = Enumerable.Range(1, 32).Select(static value => (byte)value).ToArray();

    [TestMethod]
    public void DeriveKeyId_MatchesAcrossRuntimes()
    {
        string passwordHex = InteropHelperRunner.ToHex(Password);
        string saltHex = InteropHelperRunner.ToHex(Salt);
        string net10 = InteropHelperRunner.RunHelper("InteropNet10", "derive-keyid", passwordHex, saltHex, Iterations.ToString());
        string net48 = InteropHelperRunner.RunHelper("InteropNet48", "derive-keyid", passwordHex, saltHex, Iterations.ToString());
        Assert.AreEqual(net10, net48);
        Assert.IsTrue(net10.StartsWith("aesgcm:", StringComparison.Ordinal));
    }

    [TestMethod]
    public void WrapUnwrapDek_MatchesAcrossRuntimes()
    {
        string passwordHex = InteropHelperRunner.ToHex(Password);
        string saltHex = InteropHelperRunner.ToHex(Salt);
        string dekHex = InteropHelperRunner.ToHex(Dek);

        string envelopeFrom10 = InteropHelperRunner.RunHelper("InteropNet10", "wrap-dek", passwordHex, saltHex, Iterations.ToString(), dekHex);
        CollectionAssert.AreEqual(
            Dek,
            InteropHelperRunner.FromHex(InteropHelperRunner.RunHelper("InteropNet48", "unwrap-dek", passwordHex, saltHex, Iterations.ToString(), envelopeFrom10)));

        string envelopeFrom48 = InteropHelperRunner.RunHelper("InteropNet48", "wrap-dek", passwordHex, saltHex, Iterations.ToString(), dekHex);
        CollectionAssert.AreEqual(
            Dek,
            InteropHelperRunner.FromHex(InteropHelperRunner.RunHelper("InteropNet10", "unwrap-dek", passwordHex, saltHex, Iterations.ToString(), envelopeFrom48)));
    }

    [TestMethod]
    public void RewrapDek_CrossRuntimePreservesDek()
    {
        byte[] oldPassword = Encoding.UTF8.GetBytes("old-password");
        byte[] newPassword = Encoding.UTF8.GetBytes("new-password");
        byte[] oldSalt = Encoding.UTF8.GetBytes("old-salt-0123456");
        byte[] newSalt = Encoding.UTF8.GetBytes("new-salt-0123456");
        const int oldIterations = 500;
        const int newIterations = 700;

        string envelope = InteropHelperRunner.RunHelper(
            "InteropNet10",
            "wrap-dek",
            InteropHelperRunner.ToHex(oldPassword),
            InteropHelperRunner.ToHex(oldSalt),
            oldIterations.ToString(),
            InteropHelperRunner.ToHex(Dek));

        string rewrapped = InteropHelperRunner.RunHelper(
            "InteropNet48",
            "rewrap-dek",
            InteropHelperRunner.ToHex(oldPassword),
            InteropHelperRunner.ToHex(oldSalt),
            oldIterations.ToString(),
            InteropHelperRunner.ToHex(newPassword),
            InteropHelperRunner.ToHex(newSalt),
            newIterations.ToString(),
            envelope);

        CollectionAssert.AreEqual(
            Dek,
            InteropHelperRunner.FromHex(InteropHelperRunner.RunHelper(
                "InteropNet10",
                "unwrap-dek",
                InteropHelperRunner.ToHex(newPassword),
                InteropHelperRunner.ToHex(newSalt),
                newIterations.ToString(),
                rewrapped)));
    }

    [TestMethod]
    public void KdeKEnvelope_SerializeParse_MatchesAcrossRuntimes()
    {
        const string keyId = "abc";
        byte[] wrapped = { 0xAA, 0xBB };
        string wrappedHex = InteropHelperRunner.ToHex(wrapped);
        string expected = "4B44454B01000361626300000002AABB";

        string from10 = InteropHelperRunner.RunHelper("InteropNet10", "serialize-envelope", keyId, wrappedHex);
        string from48 = InteropHelperRunner.RunHelper("InteropNet48", "serialize-envelope", keyId, wrappedHex);
        Assert.AreEqual(expected, from10, ignoreCase: true);
        Assert.AreEqual(expected, from48, ignoreCase: true);

        string parsed10 = InteropHelperRunner.RunHelper("InteropNet10", "parse-envelope", from48);
        string parsed48 = InteropHelperRunner.RunHelper("InteropNet48", "parse-envelope", from10);
        Assert.AreEqual(keyId + "\n" + wrappedHex, parsed10, ignoreCase: true);
        Assert.AreEqual(keyId + "\n" + wrappedHex, parsed48, ignoreCase: true);
    }

    [TestMethod]
    public void WindowsCredential_StoreGet_MatchesAcrossRuntimes()
    {
        if (Environment.OSVersion.Platform != PlatformID.Win32NT)
        {
            Assert.Inconclusive("Windows Credential Manager requires Windows.");
        }

        string service = "bizadm-kms://cross-" + Guid.NewGuid().ToString("N");
        const string account = "unit-test";
        string passwordHex = InteropHelperRunner.ToHex(Encoding.UTF8.GetBytes("shared-os-password"));
        string saltHex = InteropHelperRunner.ToHex(Salt);

        try
        {
            InteropHelperRunner.RunHelper("InteropNet10", "store-cred", service, account, passwordHex);
            string from48 = InteropHelperRunner.RunHelper("InteropNet48", "get-cred", service, account);
            Assert.AreEqual(passwordHex, from48, ignoreCase: true);

            InteropHelperRunner.RunHelper("InteropNet48", "remove-cred", service, account);
            InteropHelperRunner.RunHelper("InteropNet48", "store-cred", service, account, passwordHex);
            string from10 = InteropHelperRunner.RunHelper("InteropNet10", "get-cred", service, account);
            Assert.AreEqual(passwordHex, from10, ignoreCase: true);

            string keyId10 = InteropHelperRunner.RunHelper("InteropNet10", "derive-keyid", passwordHex, saltHex, Iterations.ToString());
            string keyId48 = InteropHelperRunner.RunHelper("InteropNet48", "derive-keyid", passwordHex, saltHex, Iterations.ToString());
            Assert.AreEqual(keyId10, keyId48);
        }
        finally
        {
            try
            {
                InteropHelperRunner.RunHelper("InteropNet10", "remove-cred", service, account);
            }
            catch
            {
                // best-effort cleanup
            }

            try
            {
                InteropHelperRunner.RunHelper("InteropNet48", "remove-cred", service, account);
            }
            catch
            {
                // best-effort cleanup
            }
        }
    }
}

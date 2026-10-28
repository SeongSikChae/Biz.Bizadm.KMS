using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Text;

namespace Biz.Bizadm.KMS.NetFramework.Tests;

[TestClass]
public sealed class RuntimeSetupTests
{
    private static readonly byte[] ZeroKey = new byte[32];
    private static readonly byte[] ZeroNonce = new byte[12];

    [TestMethod]
    public void TestHost_RunsOnNetFrameworkClr()
    {
        Assert.AreEqual(4, Environment.Version.Major);
    }

    [TestMethod]
    public void Aes256Gcm_MatchesNistKnownAnswerVector()
    {
        byte[] plaintext = new byte[16];
        byte[] ciphertextAndTag = Encrypt(ZeroKey, ZeroNonce, plaintext);
        byte[] expected = FromHex("cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919");

        CollectionAssert.AreEqual(expected, ciphertextAndTag);
        CollectionAssert.AreEqual(plaintext, Decrypt(ZeroKey, ZeroNonce, ciphertextAndTag));
    }

    [TestMethod]
    public void Aes256Gcm_EmptyPlaintextMatchesNistKnownAnswerVector()
    {
        byte[] ciphertextAndTag = Encrypt(ZeroKey, ZeroNonce, Array.Empty<byte>());

        CollectionAssert.AreEqual(
            FromHex("530f8afbc74536b9a963b4f1c4cb738b"),
            ciphertextAndTag);
        CollectionAssert.AreEqual(Array.Empty<byte>(), Decrypt(ZeroKey, ZeroNonce, ciphertextAndTag));
    }

    [TestMethod]
    public void Aes256Gcm_RejectsModifiedTagAndWrongKey()
    {
        byte[] ciphertextAndTag = Encrypt(ZeroKey, ZeroNonce, new byte[] { 1, 2, 3 });
        ciphertextAndTag[ciphertextAndTag.Length - 1] ^= 1;

        Assert.ThrowsException<InvalidCipherTextException>(
            () => Decrypt(ZeroKey, ZeroNonce, ciphertextAndTag));
        Assert.ThrowsException<InvalidCipherTextException>(
            () => Decrypt(Enumerable.Repeat((byte)1, 32).ToArray(), ZeroNonce, Encrypt(ZeroKey, ZeroNonce, new byte[] { 1, 2, 3 })));
    }

    [TestMethod]
    public void Net10AndNet48_DecryptEachOthersCiphertext_AndRejectTampering()
    {
        byte[] key = Enumerable.Range(0, 32).Select(static value => (byte)value).ToArray();
        byte[] plaintext = Encoding.UTF8.GetBytes("net10 and net48 cross-runtime test");
        string keyHex = InteropHelperRunner.ToHex(key);
        string plainHex = InteropHelperRunner.ToHex(plaintext);

        string net10CiphertextHex = InteropHelperRunner.RunHelper("InteropNet10", "encrypt", keyHex, plainHex);
        byte[] net10Ciphertext = InteropHelperRunner.FromHex(net10CiphertextHex);
        CollectionAssert.AreEqual(plaintext, InteropHelperRunner.FromHex(InteropHelperRunner.RunHelper("InteropNet48", "decrypt", keyHex, net10CiphertextHex)));

        string net48CiphertextHex = InteropHelperRunner.RunHelper("InteropNet48", "encrypt", keyHex, plainHex);
        byte[] net48Ciphertext = InteropHelperRunner.FromHex(net48CiphertextHex);
        CollectionAssert.AreEqual(plaintext, InteropHelperRunner.FromHex(InteropHelperRunner.RunHelper("InteropNet10", "decrypt", keyHex, net48CiphertextHex)));

        net48Ciphertext[net48Ciphertext.Length - 1] ^= 0x80;
        InteropHelperRunner.AssertHelperFailure("InteropNet10", "decrypt", keyHex, InteropHelperRunner.ToHex(net48Ciphertext));
        InteropHelperRunner.AssertHelperFailure(
            "InteropNet48",
            "decrypt",
            keyHex,
            InteropHelperRunner.ToHex(net10Ciphertext.Select((value, index) => index == net10Ciphertext.Length - 1 ? (byte)(value ^ 0x01) : value).ToArray()));

        string emptyHex = InteropHelperRunner.RunHelper("InteropNet10", "encrypt", keyHex, string.Empty);
        CollectionAssert.AreEqual(Array.Empty<byte>(), InteropHelperRunner.FromHex(InteropHelperRunner.RunHelper("InteropNet48", "decrypt", keyHex, emptyHex)));
        emptyHex = InteropHelperRunner.RunHelper("InteropNet48", "encrypt", keyHex, string.Empty);
        CollectionAssert.AreEqual(Array.Empty<byte>(), InteropHelperRunner.FromHex(InteropHelperRunner.RunHelper("InteropNet10", "decrypt", keyHex, emptyHex)));
    }

    private static byte[] FromHex(string value) => InteropHelperRunner.FromHex(value);

    private static byte[] Encrypt(byte[] key, byte[] nonce, byte[] plaintext)
    {
        var cipher = new GcmBlockCipher(new AesEngine());
        cipher.Init(true, new AeadParameters(new KeyParameter(key), 128, nonce));
        byte[] output = new byte[cipher.GetOutputSize(plaintext.Length)];
        int length = cipher.ProcessBytes(plaintext, 0, plaintext.Length, output, 0);
        length += cipher.DoFinal(output, length);
        Array.Resize(ref output, length);
        return output;
    }

    private static byte[] Decrypt(byte[] key, byte[] nonce, byte[] ciphertextAndTag)
    {
        var cipher = new GcmBlockCipher(new AesEngine());
        cipher.Init(false, new AeadParameters(new KeyParameter(key), 128, nonce));
        byte[] output = new byte[cipher.GetOutputSize(ciphertextAndTag.Length)];
        int length = cipher.ProcessBytes(ciphertextAndTag, 0, ciphertextAndTag.Length, output, 0);
        length += cipher.DoFinal(output, length);
        Array.Resize(ref output, length);
        return output;
    }
}

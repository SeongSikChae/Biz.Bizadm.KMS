using Biz.Bizadm.KMS.NetFramework.Cipher;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Biz.Bizadm.KMS.NetFramework.Tests;

[TestClass]
public sealed class EnvelopeStorageTests
{
    [TestMethod]
    public void KdekSerialization_MatchesExpectedBigEndianFormatAndRoundTrips()
    {
        byte[] expected = { 0x4B, 0x44, 0x45, 0x4B, 0x01, 0x00, 0x03, 0x61, 0x62, 0x63, 0x00, 0x00, 0x00, 0x02, 0xAA, 0xBB };
        var envelope = new WrappedDekEnvelope("abc", new byte[] { 0xAA, 0xBB });

        CollectionAssert.AreEqual(expected, envelope.Serialize());
        WrappedDekEnvelope parsed = WrappedDekEnvelope.Deserialize(expected);
        Assert.AreEqual("abc", parsed.KeyId);
        CollectionAssert.AreEqual(new byte[] { 0xAA, 0xBB }, parsed.WrappedKey);
    }

    [TestMethod]
    public void KdekDeserialization_RejectsTruncationTrailingDataAndInvalidUtf8()
    {
        byte[] valid = new WrappedDekEnvelope("id", new byte[] { 1 }).Serialize();
        Assert.ThrowsException<InvalidDataException>(() => WrappedDekEnvelope.Deserialize(valid.Take(valid.Length - 1).ToArray()));
        Assert.ThrowsException<InvalidDataException>(() => WrappedDekEnvelope.Deserialize(valid.Concat(new byte[] { 0 }).ToArray()));
        byte[] invalidUtf8 = (byte[])valid.Clone();
        invalidUtf8[7] = 0xFF;
        Assert.ThrowsException<System.Text.DecoderFallbackException>(() => WrappedDekEnvelope.Deserialize(invalidUtf8));
    }

    [TestMethod]
    public async Task FileStorage_CreateRaceAndAtomicReplacementPreserveCompleteFiles()
    {
        string directory = Path.Combine(Path.GetTempPath(), "KmsNet48-" + Guid.NewGuid().ToString("N"));
        string path = Path.Combine(directory, "nested", "dek.bin");
        byte[] initial = new byte[] { 1, 2, 3, 4 };
        byte[] alternate = Enumerable.Repeat((byte)0xA5, 8192).ToArray();
        try
        {
            await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => DekEnvelopeStorage.CreateIfMissingAsync(path, initial)));
            CollectionAssert.AreEqual(initial, File.ReadAllBytes(path));

            for (int i = 0; i < 8; i++)
            {
                byte[] replacement = i % 2 == 0 ? alternate : initial;
                await DekEnvelopeStorage.ReplaceAtomicallyAsync(path, replacement);
                byte[] actual = await DekEnvelopeStorage.ReadAllBytesAsync(path);
                Assert.IsTrue(actual.SequenceEqual(initial) || actual.SequenceEqual(alternate));
            }

            byte[] before = File.ReadAllBytes(path);
            using var canceled = new CancellationTokenSource();
            canceled.Cancel();
            await Assert.ThrowsExceptionAsync<TaskCanceledException>(
                () => DekEnvelopeStorage.ReplaceAtomicallyAsync(path, alternate, canceled.Token));
            CollectionAssert.AreEqual(before, File.ReadAllBytes(path));
        }
        finally
        {
            if (Directory.Exists(directory)) Directory.Delete(directory, true);
        }
    }
}

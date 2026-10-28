using System.Security.Cryptography;
using Biz.Bizadm.KMS.NetFramework.Cipher;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Biz.Bizadm.KMS.NetFramework.Tests;

[TestClass]
public sealed class KeyLifecycleTests
{
    private static readonly byte[] SaltA = { 0, 1, 2, 3, 4, 5, 6, 7 };
    private static readonly byte[] SaltB = { 7, 6, 5, 4, 3, 2, 1, 0 };

    [TestMethod]
    public void Manager_RotatesRewrapsResolvesAndReleasesHistoricalKek()
    {
        using var manager = AesGcmKekManager.Create(new TestCredentialProvider("old password"), SaltA, 100);
        AesGcmKekCipher old = manager.Current;
        byte[] dek = Enumerable.Range(0, 32).Select(static value => (byte)value).ToArray();
        byte[] wrappedOldDek = old.Encrypt(dek);
        byte[] oldEnvelope = new WrappedDekEnvelope(old.KeyId, wrappedOldDek).Serialize();
        Array.Clear(wrappedOldDek, 0, wrappedOldDek.Length);

        AesGcmKekCipher current = manager.Rotate(new TestCredentialProvider("new password"), SaltB, 100);
        Assert.AreNotEqual(old.KeyId, current.KeyId);
        Assert.AreEqual(2, manager.KnownKeyIds.Count);
        CollectionAssert.AreEqual(dek, manager.Resolve(old.KeyId).Decrypt(WrappedDekEnvelope.Deserialize(oldEnvelope).WrappedKey));

        byte[] newEnvelope = manager.RewrapDek(oldEnvelope);
        WrappedDekEnvelope parsed = WrappedDekEnvelope.Deserialize(newEnvelope);
        Assert.AreEqual(current.KeyId, parsed.KeyId);
        byte[] unwrapped = current.Decrypt(parsed.WrappedKey);
        CollectionAssert.AreEqual(dek, unwrapped);
        Array.Clear(unwrapped, 0, unwrapped.Length);

        manager.Release(old.KeyId);
        Assert.AreEqual(1, manager.KnownKeyIds.Count);
        Assert.ThrowsException<KeyNotFoundException>(() => manager.Resolve(old.KeyId));
    }

    [TestMethod]
    public async Task ManagerAsync_RewrapFileAndDisposeAreSafe()
    {
        var manager = await AesGcmKekManager.CreateAsync(new TestCredentialProvider("old"), SaltA, 50);
        AesGcmKekCipher old = manager.Current;
        byte[] dek = new byte[32];
        using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(dek);
        string dir = Path.Combine(Path.GetTempPath(), "KmsLifecycle-" + Guid.NewGuid().ToString("N"));
        string path = Path.Combine(dir, "key.bin");
        try
        {
            byte[] wrapped = old.Encrypt(dek);
            byte[] oldEnvelope = new WrappedDekEnvelope(old.KeyId, wrapped).Serialize();
            Array.Clear(wrapped, 0, wrapped.Length);
            await DekEnvelopeStorage.CreateIfMissingAsync(path, oldEnvelope);
            Array.Clear(oldEnvelope, 0, oldEnvelope.Length);
            AesGcmKekCipher rotated = manager.Rotate(new TestCredentialProvider("new"), SaltB, 50);
            await manager.RewrapDekFileAsync(path);
            WrappedDekEnvelope stored = WrappedDekEnvelope.Deserialize(await DekEnvelopeStorage.ReadAllBytesAsync(path));
            Assert.AreEqual(rotated.KeyId, stored.KeyId);
            byte[] unwrapped = rotated.Decrypt(stored.WrappedKey);
            CollectionAssert.AreEqual(dek, unwrapped);
            Array.Clear(unwrapped, 0, unwrapped.Length);
        }
        finally
        {
            if (Directory.Exists(dir)) Directory.Delete(dir, true);
            Array.Clear(dek, 0, dek.Length);
        }

        manager.Dispose();
        manager.Dispose();
        Assert.ThrowsException<ObjectDisposedException>(() => _ = manager.Current);
        Assert.ThrowsException<ObjectDisposedException>(() => manager.Rotate(new TestCredentialProvider("x"), SaltA, 5));
    }

    [TestMethod]
    public void Manager_ConcurrentOperationsWithRotationRemainConsistent()
    {
        using var manager = AesGcmKekManager.Create(new TestCredentialProvider("key-0"), SaltA, 10);
        byte[] dek = Enumerable.Repeat((byte)0x33, 32).ToArray();
        Parallel.For(0, 80, i =>
        {
            if (i % 8 == 0)
            {
                manager.Rotate(new TestCredentialProvider("key-" + i), BitConverter.GetBytes(i).Concat(new byte[4]).ToArray(), 5);
            }
            else
            {
                AesGcmKekCipher current = manager.Current;
                byte[] envelope = new WrappedDekEnvelope(current.KeyId, current.Encrypt(dek)).Serialize();
                byte[] rewrapped = manager.RewrapDek(envelope);
                WrappedDekEnvelope parsed = WrappedDekEnvelope.Deserialize(rewrapped);
                CollectionAssert.AreEqual(dek, manager.Resolve(parsed.KeyId).Decrypt(parsed.WrappedKey));
            }
        });
    }

    private sealed class TestCredentialProvider : IKekCredentialProvider
    {
        private readonly byte[] password;
        public TestCredentialProvider(string password) => this.password = System.Text.Encoding.UTF8.GetBytes(password);
        public byte[] GetPassword() => (byte[])password.Clone();
        public Task<byte[]> GetPasswordAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(GetPassword());
        }
    }
}

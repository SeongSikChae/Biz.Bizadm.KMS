using Biz.Bizadm.KMS.Cipher;
using Biz.Bizadm.KMS.Pkcs11.Cipher;
using System.Security.Cryptography;

namespace Biz.Bizadm.KMSTest.Cipher.Pkcs11
{
    public abstract class Pkcs11KekManagerDeviceTests
    {
        protected abstract Pkcs11LibraryContext CreateContext();

        protected abstract Pkcs11KekManager CreateManager(Pkcs11LibraryContext context, string keyLabel);

        protected abstract string NewKeyLabel(string prefix);

        [TestMethod]
        [Timeout(180_000, CooperativeCancellation = true)]
        public void Rotate_RewrapDekFile_PreservesDek()
        {
            Pkcs11LibraryContext context = CreateContext();
            string keyLabel = NewKeyLabel("kms-pkcs11-manager");
            string rotatedKeyLabel = NewKeyLabel("kms-pkcs11-manager-rotated");
            FileInfo dekFile = new(Path.Combine(Path.GetTempPath(), $"kms-pkcs11-manager-dek-{Guid.NewGuid():N}.bin"));

            try
            {
                using Pkcs11KekManager manager = CreateManager(context, keyLabel);

                using Pkcs11KekCipher initial = (Pkcs11KekCipher)manager.Current;
                byte[] wrappedDek = initial.Encrypt(RandomNumberGenerator.GetBytes(32));
                byte[] envelope = new WrappedDekEnvelope(initial.KeyId, wrappedDek).Serialize();
                File.WriteAllBytes(dekFile.FullName, envelope);
                string oldKeyId = manager.Current.KeyId;

                Pkcs11KekCipher rotated = manager.Rotate(rotatedKeyLabel);
                manager.RewrapDekFile(dekFile);

                WrappedDekEnvelope updated = WrappedDekEnvelope.Deserialize(File.ReadAllBytes(dekFile.FullName));
                Assert.AreEqual(rotated.KeyId, updated.KeyId);
                Assert.AreNotEqual(oldKeyId, updated.KeyId);
                Assert.IsTrue(manager.KnownKeyIds.Contains(oldKeyId));

                manager.Release(oldKeyId);
                Assert.IsFalse(manager.KnownKeyIds.Contains(oldKeyId));
            }
            finally
            {
                DeleteQuietly(dekFile);
            }
        }

        protected static void DeleteQuietly(FileInfo file)
        {
            try
            {
                file.Refresh();
                if (file.Exists)
                    file.Delete();
            }
            catch (IOException)
            {
            }
        }
    }

    [TestClass]
    [TestCategory("Manual")]
    [DoNotParallelize]
    public sealed class Pkcs11KekManagerSoftHsmTests : Pkcs11KekManagerDeviceTests
    {
        protected override Pkcs11LibraryContext CreateContext()
            => SoftHsmPkcs11TestProfile.CreateContext();

        protected override Pkcs11KekManager CreateManager(Pkcs11LibraryContext context, string keyLabel)
            => SoftHsmPkcs11TestProfile.CreateManager(context, keyLabel);

        protected override string NewKeyLabel(string prefix)
            => SoftHsmPkcs11TestProfile.NewKeyLabel(prefix);
    }
}

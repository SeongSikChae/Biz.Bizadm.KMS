using Biz.Bizadm.KMS.Cipher.Tpm;
using System.Security.Cryptography;
using Tpm2Lib;

namespace Biz.Bizadm.KMSTest.Cipher.Tpm
{
    public abstract class TpmKekManagerDeviceTests
    {
        protected static readonly byte[] Password = "kms-tpm-manager-password"u8.ToArray();

        protected abstract Tpm2Device CreateConnectedDevice();

        [TestMethod]
        [Timeout(120_000, CooperativeCancellation = true)]
        public void Rotate_RewrapDekFile_PreservesDek()
        {
            FileInfo kekFile = NewKekFile();
            FileInfo rotatedKekFile = NewKekFile();
            FileInfo dekFile = new(Path.Combine(Path.GetTempPath(), $"kms-tpm-manager-dek-{Guid.NewGuid():N}.bin"));

            try
            {
                using TpmKekManager manager = TpmKekManager.Create(
                    CreateConnectedDevice(),
                    new FixedPasswordCredentialProvider(Password),
                    kekFile);

                using TpmKekCipher initial = (TpmKekCipher)manager.Current;
                byte[] wrappedDek = initial.Encrypt(RandomNumberGenerator.GetBytes(32));
                byte[] envelope = new Biz.Bizadm.KMS.Cipher.WrappedDekEnvelope(initial.KeyId, wrappedDek).Serialize();
                File.WriteAllBytes(dekFile.FullName, envelope);
                string oldKeyId = manager.Current.KeyId;

                TpmKekCipher rotated = manager.Rotate(rotatedKekFile);
                manager.RewrapDekFile(dekFile);

                Biz.Bizadm.KMS.Cipher.WrappedDekEnvelope updated =
                    Biz.Bizadm.KMS.Cipher.WrappedDekEnvelope.Deserialize(File.ReadAllBytes(dekFile.FullName));
                Assert.AreEqual(rotated.KeyId, updated.KeyId);
                Assert.AreNotEqual(oldKeyId, updated.KeyId);
                Assert.IsTrue(manager.KnownKeyIds.Contains(oldKeyId));

                manager.Release(oldKeyId);
                Assert.IsFalse(manager.KnownKeyIds.Contains(oldKeyId));
            }
            finally
            {
                DeleteQuietly(kekFile);
                DeleteQuietly(rotatedKekFile);
                DeleteQuietly(dekFile);
            }
        }

        protected static FileInfo NewKekFile()
            => new(Path.Combine(Path.GetTempPath(), $"kms-tpm-manager-kek-{Guid.NewGuid():N}.blob"));

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

        protected static byte[] CreatePlain(int length)
        {
            byte[] plain = new byte[length];
            if (length > 0)
                RandomNumberGenerator.Fill(plain);
            return plain;
        }
    }

    [TestClass]
    [TestCategory("Manual")]
    [DoNotParallelize]
    [OSCondition(OperatingSystems.Windows)]
    public sealed class TpmKekManagerTbsDeviceTests : TpmKekManagerDeviceTests
    {
        protected override Tpm2Device CreateConnectedDevice()
        {
            TbsDevice device = new();
            device.Connect();
            return device;
        }
    }
}

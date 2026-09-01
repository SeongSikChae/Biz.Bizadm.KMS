using Biz.Bizadm.KMS.Cipher;

namespace Biz.Bizadm.KMSTest.Cipher
{
    [TestClass]
    public sealed class WrappedDekEnvelopeTests
    {
        [TestMethod]
        public void SerializeDeserialize_Roundtrip_PreservesFields()
        {
            WrappedDekEnvelope envelope = new("aesgcm:abc:10000", [1, 2, 3, 4, 5]);
            byte[] serialized = envelope.Serialize();
            WrappedDekEnvelope restored = WrappedDekEnvelope.Deserialize(serialized);

            Assert.AreEqual(envelope.KeyId, restored.KeyId);
            CollectionAssert.AreEqual(envelope.WrappedKey, restored.WrappedKey);
        }

        [TestMethod]
        public void Deserialize_InvalidMagic_ThrowsInvalidDataException()
        {
            byte[] data = "XXXX"u8.ToArray();
            Assert.ThrowsExactly<InvalidDataException>(() => WrappedDekEnvelope.Deserialize(data));
        }

        [TestMethod]
        public void Deserialize_UnsupportedVersion_ThrowsInvalidDataException()
        {
            WrappedDekEnvelope envelope = new("test-key", [9]);
            byte[] serialized = envelope.Serialize();
            serialized[4] = 99;

            Assert.ThrowsExactly<InvalidDataException>(() => WrappedDekEnvelope.Deserialize(serialized));
        }
    }
}

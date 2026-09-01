using System.Buffers.Binary;
using System.Text;

namespace Biz.Bizadm.KMS.Cipher
{
    /// <summary>
    /// KEK KeyId와 wrap된 DEK를 담는 envelope.
    /// </summary>
    /// <param name="KeyId">wrap에 사용된 KEK의 KeyId.</param>
    /// <param name="WrappedKey">KEK로 wrap된 DEK ciphertext.</param>
    public readonly record struct WrappedDekEnvelope(string KeyId, byte[] WrappedKey)
    {
        private const byte Version = 1;
        private static ReadOnlySpan<byte> Magic => "KDEK"u8;

        /// <summary>
        /// envelope 바이트를 직렬화한다.
        /// </summary>
        /// <returns>직렬화된 envelope.</returns>
        public byte[] Serialize()
        {
            ArgumentException.ThrowIfNullOrEmpty(KeyId);
            ArgumentNullException.ThrowIfNull(WrappedKey);

            byte[] keyIdBytes = Encoding.UTF8.GetBytes(KeyId);
            if (keyIdBytes.Length > ushort.MaxValue)
                throw new InvalidOperationException("KeyId is too long.");

            byte[] output = new byte[Magic.Length + 1 + sizeof(ushort) + keyIdBytes.Length + sizeof(int) + WrappedKey.Length];
            int offset = 0;

            Magic.CopyTo(output);
            offset += Magic.Length;

            output[offset++] = Version;

            BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(offset), (ushort)keyIdBytes.Length);
            offset += sizeof(ushort);

            keyIdBytes.CopyTo(output, offset);
            offset += keyIdBytes.Length;

            BinaryPrimitives.WriteInt32BigEndian(output.AsSpan(offset), WrappedKey.Length);
            offset += sizeof(int);

            WrappedKey.CopyTo(output, offset);
            return output;
        }

        /// <summary>
        /// envelope 바이트를 역직렬화한다.
        /// </summary>
        /// <param name="data">직렬화된 envelope.</param>
        /// <returns>역직렬화된 envelope.</returns>
        public static WrappedDekEnvelope Deserialize(ReadOnlySpan<byte> data)
        {
            if (data.Length < Magic.Length + 1 + sizeof(ushort) + sizeof(int))
                throw new InvalidDataException("Envelope data is too short.");

            if (!data.Slice(0, Magic.Length).SequenceEqual(Magic))
                throw new InvalidDataException("Invalid envelope magic.");

            int offset = Magic.Length;

            byte version = data[offset++];
            if (version != Version)
                throw new InvalidDataException($"Unsupported envelope version: {version}.");

            ushort keyIdLength = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(offset));
            offset += sizeof(ushort);

            if (data.Length < offset + keyIdLength + sizeof(int))
                throw new InvalidDataException("Envelope data is truncated.");

            string keyId = Encoding.UTF8.GetString(data.Slice(offset, keyIdLength));
            offset += keyIdLength;

            int wrappedKeyLength = BinaryPrimitives.ReadInt32BigEndian(data.Slice(offset));
            offset += sizeof(int);

            if (wrappedKeyLength < 0 || data.Length < offset + wrappedKeyLength)
                throw new InvalidDataException("Envelope wrapped key length is invalid.");

            byte[] wrappedKey = data.Slice(offset, wrappedKeyLength).ToArray();
            return new WrappedDekEnvelope(keyId, wrappedKey);
        }
    }
}

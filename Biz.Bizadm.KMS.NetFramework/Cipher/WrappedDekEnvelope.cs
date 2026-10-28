using System.Text;

namespace Biz.Bizadm.KMS.NetFramework.Cipher;

/// <summary>
/// KDEK version 1 envelope containing a KEK KeyId and wrapped DEK bytes.
/// </summary>
public sealed class WrappedDekEnvelope
{
    private static readonly byte[] Magic = Encoding.ASCII.GetBytes("KDEK");
    private const byte Version = 1;

    public WrappedDekEnvelope(string keyId, byte[] wrappedKey)
    {
        if (string.IsNullOrEmpty(keyId)) throw new ArgumentException("KeyId must not be empty.", nameof(keyId));
        if (wrappedKey is null) throw new ArgumentNullException(nameof(wrappedKey));
        KeyId = keyId;
        WrappedKey = (byte[])wrappedKey.Clone();
    }

    public string KeyId { get; }
    public byte[] WrappedKey { get; }

    public byte[] Serialize()
    {
        byte[] keyIdBytes = Encoding.UTF8.GetBytes(KeyId);
        if (keyIdBytes.Length > ushort.MaxValue) throw new InvalidOperationException("KeyId is too long.");
        byte[] output = new byte[Magic.Length + 1 + 2 + keyIdBytes.Length + 4 + WrappedKey.Length];
        int offset = 0;
        Buffer.BlockCopy(Magic, 0, output, offset, Magic.Length);
        offset += Magic.Length;
        output[offset++] = Version;
        WriteUInt16BigEndian(output, offset, (ushort)keyIdBytes.Length);
        offset += 2;
        Buffer.BlockCopy(keyIdBytes, 0, output, offset, keyIdBytes.Length);
        offset += keyIdBytes.Length;
        WriteInt32BigEndian(output, offset, WrappedKey.Length);
        offset += 4;
        Buffer.BlockCopy(WrappedKey, 0, output, offset, WrappedKey.Length);
        return output;
    }

    public static WrappedDekEnvelope Deserialize(byte[] data)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));
        if (data.Length < 11) throw new InvalidDataException("Envelope data is too short.");
        for (int i = 0; i < Magic.Length; i++)
        {
            if (data[i] != Magic[i]) throw new InvalidDataException("Invalid envelope magic.");
        }
        if (data[4] != Version) throw new InvalidDataException("Unsupported envelope version: " + data[4] + ".");

        int offset = 5;
        ushort keyIdLength = ReadUInt16BigEndian(data, offset);
        offset += 2;
        if (data.Length < offset + keyIdLength + 4) throw new InvalidDataException("Envelope data is truncated.");
        string keyId = new UTF8Encoding(false, true).GetString(data, offset, keyIdLength);
        offset += keyIdLength;
        int wrappedKeyLength = ReadInt32BigEndian(data, offset);
        offset += 4;
        if (wrappedKeyLength < 0 || data.Length != offset + wrappedKeyLength)
            throw new InvalidDataException("Envelope wrapped key length is invalid.");
        byte[] wrappedKey = new byte[wrappedKeyLength];
        Buffer.BlockCopy(data, offset, wrappedKey, 0, wrappedKeyLength);
        return new WrappedDekEnvelope(keyId, wrappedKey);
    }

    private static void WriteUInt16BigEndian(byte[] output, int offset, ushort value)
    {
        output[offset] = (byte)(value >> 8);
        output[offset + 1] = (byte)value;
    }

    private static ushort ReadUInt16BigEndian(byte[] input, int offset)
        => (ushort)((input[offset] << 8) | input[offset + 1]);

    private static void WriteInt32BigEndian(byte[] output, int offset, int value)
    {
        output[offset] = (byte)(value >> 24);
        output[offset + 1] = (byte)(value >> 16);
        output[offset + 2] = (byte)(value >> 8);
        output[offset + 3] = (byte)value;
    }

    private static int ReadInt32BigEndian(byte[] input, int offset)
    {
        return unchecked((input[offset] << 24) | (input[offset + 1] << 16) | (input[offset + 2] << 8) | input[offset + 3]);
    }
}

using System.Text;
using Tpm2Lib;

namespace Biz.Bizadm.KMS.NetFramework.Cipher.Tpm;

/// <summary>
/// Independent TKEK v1 blob serializer for net48.
/// Layout matches net10: magic TKEK, version 1, little-endian length-prefixed public then private blocks.
/// </summary>
public sealed class TpmKekBlob
{
    private static readonly byte[] Magic = Encoding.ASCII.GetBytes("TKEK");
    private const byte Version = 1;

    public TpmKekBlob(TpmPrivate privateBlob, TpmPublic publicBlob)
    {
        Private = privateBlob ?? throw new ArgumentNullException(nameof(privateBlob));
        Public = publicBlob ?? throw new ArgumentNullException(nameof(publicBlob));
    }

    public TpmPrivate Private { get; }

    public TpmPublic Public { get; }

    public void Save(FileInfo file)
    {
        if (file is null) throw new ArgumentNullException(nameof(file));
        file.Directory?.Create();

        using (FileStream stream = file.Open(FileMode.Create, FileAccess.Write, FileShare.None))
        using (BinaryWriter writer = new BinaryWriter(stream))
        {
            writer.Write(Magic);
            writer.Write(Version);
            WriteBlock(writer, Marshaller.GetTpmRepresentation(Public));
            WriteBlock(writer, Marshaller.GetTpmRepresentation(Private));
        }
    }

    public static TpmKekBlob Load(FileInfo file)
    {
        if (file is null) throw new ArgumentNullException(nameof(file));

        using (FileStream stream = file.Open(FileMode.Open, FileAccess.Read, FileShare.Read))
        using (BinaryReader reader = new BinaryReader(stream))
        {
            byte[] magic = reader.ReadBytes(Magic.Length);
            if (magic.Length != Magic.Length || !magic.SequenceEqual(Magic))
                throw new InvalidDataException("Invalid KEK blob file.");

            byte version = reader.ReadByte();
            if (version != Version)
                throw new NotSupportedException("Unsupported KEK blob version: " + version + ".");

            byte[] publicBytes = ReadBlock(reader);
            byte[] privateBytes = ReadBlock(reader);
            if (stream.Position != stream.Length)
                throw new InvalidDataException("KEK blob file contains unexpected trailing data.");

            return new TpmKekBlob(
                Marshaller.FromTpmRepresentation<TpmPrivate>(privateBytes),
                Marshaller.FromTpmRepresentation<TpmPublic>(publicBytes));
        }
    }

    private static void WriteBlock(BinaryWriter writer, byte[] data)
    {
        writer.Write(data.Length);
        writer.Write(data);
    }

    private static byte[] ReadBlock(BinaryReader reader)
    {
        int length = reader.ReadInt32();
        if (length < 0)
            throw new InvalidDataException("Invalid KEK blob block length.");

        byte[] data = reader.ReadBytes(length);
        if (data.Length != length)
            throw new EndOfStreamException("Unexpected end of KEK blob file.");

        return data;
    }
}

using Tpm2Lib;

namespace Biz.Bizadm.KMS.Cipher.Tpm
{
    public sealed record TpmKekBlob(TpmPrivate Private, TpmPublic Public)
    {
        private static ReadOnlySpan<byte> Magic => "TKEK"u8;
        private const byte Version = 1;

        public void Save(FileInfo file)
        {
            ArgumentNullException.ThrowIfNull(file);
            ArgumentNullException.ThrowIfNull(Private);
            ArgumentNullException.ThrowIfNull(Public);

            file.Directory?.Create();

            using FileStream stream = file.Open(FileMode.Create, FileAccess.Write, FileShare.None);
            using BinaryWriter writer = new(stream);
            writer.Write(Magic);
            writer.Write(Version);
            WriteBlock(writer, Marshaller.GetTpmRepresentation(Public));
            WriteBlock(writer, Marshaller.GetTpmRepresentation(Private));
        }

        public static TpmKekBlob Load(FileInfo file)
        {
            ArgumentNullException.ThrowIfNull(file);

            using FileStream stream = file.Open(FileMode.Open, FileAccess.Read, FileShare.Read);
            using BinaryReader reader = new(stream);

            byte[] magic = reader.ReadBytes(Magic.Length);
            if (!Magic.SequenceEqual(magic))
                throw new InvalidDataException("Invalid KEK blob file.");

            byte version = reader.ReadByte();
            if (version != Version)
                throw new NotSupportedException($"Unsupported KEK blob version: {version}.");

            byte[] publicBytes = ReadBlock(reader);
            byte[] privateBytes = ReadBlock(reader);
            if (stream.Position != stream.Length)
                throw new InvalidDataException("KEK blob file contains unexpected trailing data.");

            return new TpmKekBlob(
                Marshaller.FromTpmRepresentation<TpmPrivate>(privateBytes),
                Marshaller.FromTpmRepresentation<TpmPublic>(publicBytes));
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
}

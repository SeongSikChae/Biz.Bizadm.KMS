using Tpm2Lib;

namespace Biz.Bizadm.KMS.Cipher.Tpm
{
    /// <summary>
    /// SRK로 wrap된 TPM KEK의 public/private 직렬화 blob.
    /// </summary>
    /// <param name="Private">SRK로 wrap된 KEK private 부분.</param>
    /// <param name="Public">KEK public 부분.</param>
    public sealed record TpmKekBlob(TpmPrivate Private, TpmPublic Public)
    {
        private static ReadOnlySpan<byte> Magic => "TKEK"u8;
        private const byte Version = 1;

        /// <summary>
        /// KEK blob을 파일에 저장한다.
        /// </summary>
        /// <param name="file">저장할 파일.</param>
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

        /// <summary>
        /// 파일에서 KEK blob을 로드한다.
        /// </summary>
        /// <param name="file">로드할 파일.</param>
        /// <returns>로드된 <see cref="TpmKekBlob"/>.</returns>
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

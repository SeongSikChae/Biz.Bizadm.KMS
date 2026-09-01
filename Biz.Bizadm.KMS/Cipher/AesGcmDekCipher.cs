using System.Security.Cryptography;

namespace Biz.Bizadm.KMS.Cipher
{
    /// <summary>
    /// 파일 또는 바이트로 보관된 DEK를 KEK로 wrap/unwrap하여 사용하는 AES-GCM DEK 암호.
    /// </summary>
    public sealed class AesGcmDekCipher : AbstractAesGcmCipher, IDekCipher
    {
        private const int KeySize = 32;

        /// <summary>
        /// DEK 파일이 있으면 로드하고, 없으면 새 DEK를 생성해 저장한 뒤 암호를 만든다.
        /// </summary>
        /// <param name="cipher">DEK를 wrap/unwrap할 KEK 암호.</param>
        /// <param name="f">암호화된 DEK를 저장·로드할 파일.</param>
        /// <returns>생성된 <see cref="AesGcmDekCipher"/>.</returns>
        public static AesGcmDekCipher Create(IKekCipher cipher, FileInfo f)
        {
            ArgumentNullException.ThrowIfNull(cipher);
            ArgumentNullException.ThrowIfNull(f);

            f.Refresh();
            if (f.Exists)
                return Create(cipher, File.ReadAllBytes(f.FullName));

            byte[] key = new byte[KeySize];
            RandomNumberGenerator.Fill(key);
            try
            {
                byte[] envelope = CreateEnvelope(cipher, key);
                f.Directory?.Create();
                try
                {
                    WriteAllBytesExclusiveCreate(f.FullName, envelope);
                    return new AesGcmDekCipher(key);
                }
                catch (IOException)
                {
                    CryptographicOperations.ZeroMemory(key);
                    return Create(cipher, File.ReadAllBytes(f.FullName));
                }
            }
            catch
            {
                CryptographicOperations.ZeroMemory(key);
                throw;
            }
        }

        /// <summary>
        /// KEK로 wrap된 DEK envelope 바이트에서 암호를 만든다.
        /// </summary>
        /// <param name="cipher">DEK를 unwrap할 KEK 암호.</param>
        /// <param name="envelopeBytes">직렬화된 DEK envelope.</param>
        /// <returns>생성된 <see cref="AesGcmDekCipher"/>.</returns>
        public static AesGcmDekCipher Create(IKekCipher cipher, byte[] envelopeBytes)
        {
            ArgumentNullException.ThrowIfNull(cipher);
            ArgumentNullException.ThrowIfNull(envelopeBytes);

            WrappedDekEnvelope envelope = WrappedDekEnvelope.Deserialize(envelopeBytes);
            ValidateKeyId(cipher, envelope.KeyId);
            return new AesGcmDekCipher(cipher.Decrypt(envelope.WrappedKey));
        }

        /// <summary>
        /// source KEK로 wrap된 envelope를 target KEK로 re-wrap한다.
        /// </summary>
        /// <param name="sourceKek">unwrap에 사용할 기존 KEK.</param>
        /// <param name="targetKek">wrap에 사용할 새 KEK.</param>
        /// <param name="envelopeBytes">기존 envelope 바이트.</param>
        /// <returns>새 envelope 바이트.</returns>
        public static byte[] Rewrap(IKekCipher sourceKek, IKekCipher targetKek, byte[] envelopeBytes)
        {
            ArgumentNullException.ThrowIfNull(sourceKek);
            ArgumentNullException.ThrowIfNull(targetKek);
            ArgumentNullException.ThrowIfNull(envelopeBytes);

            WrappedDekEnvelope envelope = WrappedDekEnvelope.Deserialize(envelopeBytes);
            ValidateKeyId(sourceKek, envelope.KeyId);

            byte[] rewrapped = targetKek.RewrapDek(sourceKek, envelope.WrappedKey);
            return new WrappedDekEnvelope(targetKek.KeyId, rewrapped).Serialize();
        }

        /// <summary>
        /// source KEK로 wrap된 DEK 파일을 target KEK로 re-wrap하고 원자적으로 갱신한다.
        /// </summary>
        /// <param name="sourceKek">unwrap에 사용할 기존 KEK.</param>
        /// <param name="targetKek">wrap에 사용할 새 KEK.</param>
        /// <param name="dekFile">DEK envelope 파일.</param>
        public static void Rewrap(IKekCipher sourceKek, IKekCipher targetKek, FileInfo dekFile)
        {
            ArgumentNullException.ThrowIfNull(sourceKek);
            ArgumentNullException.ThrowIfNull(targetKek);
            ArgumentNullException.ThrowIfNull(dekFile);

            byte[] envelopeBytes = File.ReadAllBytes(dekFile.FullName);
            byte[] rewrapped = Rewrap(sourceKek, targetKek, envelopeBytes);
            WriteAllBytesAtomic(dekFile.FullName, rewrapped);
        }

        /// <summary>
        /// source KEK로 wrap된 envelope를 target KEK로 비동기 re-wrap한다.
        /// </summary>
        /// <param name="sourceKek">unwrap에 사용할 기존 KEK.</param>
        /// <param name="targetKek">wrap에 사용할 새 KEK.</param>
        /// <param name="envelopeBytes">기존 envelope 바이트.</param>
        /// <param name="cancellationToken">작업 취소 토큰.</param>
        /// <returns>새 envelope 바이트.</returns>
        public static async Task<byte[]> RewrapAsync(
            IKekCipher sourceKek,
            IKekCipher targetKek,
            byte[] envelopeBytes,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(sourceKek);
            ArgumentNullException.ThrowIfNull(targetKek);
            ArgumentNullException.ThrowIfNull(envelopeBytes);

            WrappedDekEnvelope envelope = WrappedDekEnvelope.Deserialize(envelopeBytes);
            ValidateKeyId(sourceKek, envelope.KeyId);

            byte[] rewrapped = await targetKek.RewrapDekAsync(sourceKek, envelope.WrappedKey, cancellationToken)
                .ConfigureAwait(false);
            return new WrappedDekEnvelope(targetKek.KeyId, rewrapped).Serialize();
        }

        /// <summary>
        /// source KEK로 wrap된 DEK 파일을 target KEK로 비동기 re-wrap하고 원자적으로 갱신한다.
        /// </summary>
        /// <param name="sourceKek">unwrap에 사용할 기존 KEK.</param>
        /// <param name="targetKek">wrap에 사용할 새 KEK.</param>
        /// <param name="dekFile">DEK envelope 파일.</param>
        /// <param name="cancellationToken">작업 취소 토큰.</param>
        public static async Task RewrapAsync(
            IKekCipher sourceKek,
            IKekCipher targetKek,
            FileInfo dekFile,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(sourceKek);
            ArgumentNullException.ThrowIfNull(targetKek);
            ArgumentNullException.ThrowIfNull(dekFile);

            byte[] envelopeBytes = await File.ReadAllBytesAsync(dekFile.FullName, cancellationToken).ConfigureAwait(false);
            byte[] rewrapped = await RewrapAsync(sourceKek, targetKek, envelopeBytes, cancellationToken).ConfigureAwait(false);
            WriteAllBytesAtomic(dekFile.FullName, rewrapped);
        }

        private static byte[] CreateEnvelope(IKekCipher cipher, byte[] key)
        {
            byte[] wrappedKey = cipher.Encrypt(key);
            return new WrappedDekEnvelope(cipher.KeyId, wrappedKey).Serialize();
        }

        private static void ValidateKeyId(IKekCipher cipher, string storedKeyId)
        {
            if (!string.Equals(cipher.KeyId, storedKeyId, StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    $"Envelope KeyId '{storedKeyId}' does not match cipher KeyId '{cipher.KeyId}'.");
            }
        }

        internal static void WriteAllBytesExclusiveCreate(string path, byte[] data)
        {
            string? directory = Path.GetDirectoryName(path);
            if (string.IsNullOrEmpty(directory))
                throw new ArgumentException("Path must include a directory.", nameof(path));

            using FileStream stream = new(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            stream.Write(data);
        }

        internal static void WriteAllBytesAtomic(string path, byte[] data)
        {
            string? directory = Path.GetDirectoryName(path);
            if (string.IsNullOrEmpty(directory))
                throw new ArgumentException("Path must include a directory.", nameof(path));

            string tempPath = Path.Combine(directory, Path.GetRandomFileName());

            try
            {
                File.WriteAllBytes(tempPath, data);
                File.Move(tempPath, path, overwrite: true);
            }
            catch
            {
                try
                {
                    File.Delete(tempPath);
                }
                catch (IOException)
                {
                }
                catch (UnauthorizedAccessException)
                {
                }

                throw;
            }
        }

        private AesGcmDekCipher(byte[] key) : base(key)
        {
        }

        /// <inheritdoc />
        public override Task<byte[]> EncryptAsync(byte[] plain, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(Encrypt(plain));
        }

        /// <inheritdoc />
        public override Task<byte[]> DecryptAsync(byte[] encrypted, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(Decrypt(encrypted));
        }
    }
}

using System.Security.Cryptography;
using Tpm2Lib;

namespace Biz.Bizadm.KMS.Cipher.Tpm
{
    /// <summary>
    /// TPM 2.0 내부 AES-256-CFB KEK로 키 물질을 wrap/unwrap하는 암호.
    /// </summary>
    public sealed class TpmKekCipher : IKekCipher
    {
        private readonly Tpm2Device device;
        private readonly IKekCredentialProvider credentialProvider;
        private readonly Tpm2 tpm;

        private TpmHandle? srkHandle;
        private TpmHandle? kekHandle;
        private bool disposedValue;

        private const int AesBlockSize = 16;

        /// <inheritdoc />
        public string KeyId { get; }

        private TpmKekCipher(Tpm2Device device, IKekCredentialProvider credentialProvider, byte[] password, FileInfo kekBlobFile)
        {
            ArgumentNullException.ThrowIfNull(device);
            ArgumentNullException.ThrowIfNull(credentialProvider);
            ArgumentNullException.ThrowIfNull(password);
            ArgumentNullException.ThrowIfNull(kekBlobFile);

            this.device = device;
            this.credentialProvider = credentialProvider;

            TpmPublic keySpec = ApplyPassword(CreateDefaultSrkKeySpec(), password);
            tpm = new Tpm2(device);

            try
            {
                srkHandle = CreateSrk(tpm, keySpec);
                kekBlobFile.Refresh();
                if (kekBlobFile.Exists)
                {
                    TpmKekBlob kekBlob = TpmKekBlob.Load(kekBlobFile);
                    kekHandle = LoadKek(tpm, srkHandle, kekBlob);
                    KeyId = CreateKeyId(kekBlob.Public);
                }
                else
                {
                    TpmPrivate kekPrivate = tpm.Create(
                        srkHandle,
                        new SensitiveCreate(null, null),
                        CreateKekKeySpec(),
                        null,
                        [],
                        out TpmPublic kekPublic,
                        out _,
                        out _,
                        out _);

                    new TpmKekBlob(kekPrivate, kekPublic).Save(kekBlobFile);
                    kekHandle = tpm.Load(srkHandle, kekPrivate, kekPublic);
                    KeyId = CreateKeyId(kekPublic);
                }
            }
            catch
            {
                Flush(kekHandle);
                Flush(srkHandle);
                throw;
            }
        }

        /// <inheritdoc />
        public Task<byte[]> EncryptAsync(byte[] plain, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(Encrypt(plain));
        }

        /// <inheritdoc />
        public Task<byte[]> DecryptAsync(byte[] encrypted, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(Decrypt(encrypted));
        }

        /// <inheritdoc />
        public byte[] Encrypt(byte[] plain)
        {
            ObjectDisposedException.ThrowIf(disposedValue, this);
            ArgumentNullException.ThrowIfNull(plain);

            byte[] iv = new byte[AesBlockSize];
            RandomNumberGenerator.Fill(iv);
            byte[] cipher = tpm.EncryptDecrypt(Kek, 0, TpmAlgId.Cfb, iv, plain, out _);

            byte[] output = new byte[iv.Length + cipher.Length];
            Buffer.BlockCopy(iv, 0, output, 0, iv.Length);
            Buffer.BlockCopy(cipher, 0, output, iv.Length, cipher.Length);
            return output;
        }

        /// <inheritdoc />
        public byte[] Decrypt(byte[] encrypted)
        {
            ObjectDisposedException.ThrowIf(disposedValue, this);
            ArgumentNullException.ThrowIfNull(encrypted);
            if (encrypted.Length < AesBlockSize)
                throw new ArgumentException("Encrypted payload is shorter than the AES-CFB IV.", nameof(encrypted));

            byte[] iv = encrypted.AsSpan(0, AesBlockSize).ToArray();
            byte[] cipher = encrypted.AsSpan(AesBlockSize).ToArray();
            return tpm.EncryptDecrypt(Kek, 1, TpmAlgId.Cfb, iv, cipher, out _);
        }

        /// <summary>
        /// 동일 SRK 아래 새 KEK blob으로 로테이션된 <see cref="TpmKekCipher"/>를 생성한다.
        /// </summary>
        /// <param name="newKekBlobFile">새 KEK blob 저장 파일.</param>
        /// <returns>새 <see cref="TpmKekCipher"/>.</returns>
        public TpmKekCipher Rotate(FileInfo newKekBlobFile)
        {
            ObjectDisposedException.ThrowIf(disposedValue, this);
            ArgumentNullException.ThrowIfNull(newKekBlobFile);
            return Create(device, credentialProvider, newKekBlobFile);
        }

        private TpmHandle Kek
            => kekHandle ?? throw new InvalidOperationException("KEK is not loaded.");

        private static string CreateKeyId(TpmPublic publicKey)
        {
            byte[] publicBytes = Marshaller.GetTpmRepresentation(publicKey);
            return $"tpm:{Convert.ToHexString(SHA256.HashData(publicBytes)).ToLowerInvariant()}";
        }

        private void Flush(TpmHandle? handle)
        {
            if (handle is null)
                return;

            try
            {
                tpm.FlushContext(handle);
            }
            catch (Exception)
            {
            }
        }

        private void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    Flush(kekHandle);
                    kekHandle = null;
                    Flush(srkHandle);
                    srkHandle = null;
                    // Tpm2.Dispose()는 공유 Tpm2Device까지 Dispose하므로 호출하지 않는다.
                    // TPM 핸들 flush만 수행하고 device 수명은 호출부가 관리한다.
                }

                disposedValue = true;
            }
        }

        /// <inheritdoc />
        public void Dispose()
        {
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }

        private static TpmPublic CreateDefaultSrkKeySpec()
        {
            return new TpmPublic(
                TpmAlgId.Sha256,
                ObjectAttr.Restricted | ObjectAttr.Decrypt |
                ObjectAttr.FixedParent | ObjectAttr.FixedTPM |
                ObjectAttr.UserWithAuth | ObjectAttr.SensitiveDataOrigin | ObjectAttr.NoDA,
                null,
                new RsaParms(
                    new SymDefObject(TpmAlgId.Aes, 256, TpmAlgId.Cfb),
                    new NullAsymScheme(),
                    2048,
                    0),
                new Tpm2bPublicKeyRsa());
        }

        private static TpmPublic ApplyPassword(TpmPublic keySpec, byte[]? password)
        {
            if (password is null || password.Length == 0)
                return keySpec;

            byte[] seed = SHA256.HashData(password);
            return new TpmPublic(
                keySpec.nameAlg,
                keySpec.objectAttributes,
                keySpec.authPolicy,
                keySpec.parameters,
                CreateUnique(keySpec.type, seed));
        }

        private static IPublicIdUnion CreateUnique(TpmAlgId type, byte[] seed)
        {
            return type switch
            {
                TpmAlgId.Rsa => new Tpm2bPublicKeyRsa(seed),
                TpmAlgId.Keyedhash => new Tpm2bDigestKeyedhash(seed),
                TpmAlgId.Symcipher => new Tpm2bDigestSymcipher(seed),
                _ => throw new NotSupportedException($"Password-derived SRK is not supported for {type}.")
            };
        }

        private static TpmHandle LoadKek(Tpm2 tpm, TpmHandle srk, TpmKekBlob kekBlob)
        {
            ArgumentNullException.ThrowIfNull(tpm);
            ArgumentNullException.ThrowIfNull(srk);
            ArgumentNullException.ThrowIfNull(kekBlob);
            return LoadKek(tpm, srk, kekBlob.Private, kekBlob.Public);
        }

        private static TpmHandle LoadKek(Tpm2 tpm, TpmHandle srk, TpmPrivate kekPrivate, TpmPublic kekPublic)
        {
            ArgumentNullException.ThrowIfNull(tpm);
            ArgumentNullException.ThrowIfNull(srk);
            ArgumentNullException.ThrowIfNull(kekPrivate);
            ArgumentNullException.ThrowIfNull(kekPublic);

            return tpm.Load(srk, kekPrivate, kekPublic);
        }

        private static TpmHandle CreateSrk(Tpm2 tpm, TpmPublic keySpec)
        {
            return tpm.CreatePrimary(
                TpmRh.Owner,
                new SensitiveCreate(null, null),
                keySpec,
                null,
                [],
                out _,
                out _,
                out _,
                out _);
        }

        private static TpmPublic CreateKekKeySpec()
        {
            return new TpmPublic(
                TpmAlgId.Sha256,
                ObjectAttr.Decrypt | ObjectAttr.Encrypt |
                ObjectAttr.FixedParent | ObjectAttr.FixedTPM |
                ObjectAttr.UserWithAuth | ObjectAttr.SensitiveDataOrigin | ObjectAttr.NoDA,
                null,
                new SymDefObject(TpmAlgId.Aes, 256, TpmAlgId.Cfb),
                new Tpm2bDigestSymcipher());
        }

        /// <summary>
        /// TPM 디바이스와 자격 증명·KEK blob 파일로 <see cref="TpmKekCipher"/>를 생성한다.
        /// </summary>
        /// <param name="device">연결된 TPM 디바이스. 수명은 호출부가 관리하며, cipher Dispose 시 device는 닫히지 않는다.</param>
        /// <param name="credentialProvider">SRK 유도용 패스워드 제공자.</param>
        /// <param name="kekBlobFile">KEK blob 저장·로드 파일.</param>
        /// <returns>생성된 <see cref="TpmKekCipher"/>.</returns>
        public static TpmKekCipher Create(Tpm2Device device, IKekCredentialProvider credentialProvider, FileInfo kekBlobFile)
        {
            byte[] password = credentialProvider.GetPassword();
            try
            {
                return new TpmKekCipher(device, credentialProvider, password, kekBlobFile);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(password);
            }
        }
    }
}

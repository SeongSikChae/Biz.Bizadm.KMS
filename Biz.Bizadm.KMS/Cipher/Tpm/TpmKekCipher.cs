using System.Security.Cryptography;
using Tpm2Lib;

namespace Biz.Bizadm.KMS.Cipher.Tpm
{
    /// <summary>
    /// TPM 2.0 내부 KEK로 키 물질을 wrap/unwrap하는 암호.
    /// AES-256-CFB 또는 RSA-OAEP-256 모드를 지원한다.
    /// </summary>
    public sealed class TpmKekCipher : IKekCipher
    {
        private static readonly SchemeOaep OaepSha256 = new(TpmAlgId.Sha256);

        private readonly Tpm2Device device;
        private readonly IKekCredentialProvider credentialProvider;
        private readonly TpmKekOptions options;
        private readonly TpmKekWrapMode wrapMode;
        private readonly int rsaKeySize;
        private readonly Tpm2 tpm;

        private TpmHandle? srkHandle;
        private TpmHandle? kekHandle;
        private bool disposedValue;

        private const int AesBlockSize = 16;
        private const int OaepSha256HashSize = 32;

        /// <inheritdoc />
        public string KeyId { get; }

        private TpmKekCipher(
            Tpm2Device device,
            IKekCredentialProvider credentialProvider,
            byte[] password,
            FileInfo kekBlobFile,
            TpmKekOptions options)
        {
            ArgumentNullException.ThrowIfNull(device);
            ArgumentNullException.ThrowIfNull(credentialProvider);
            ArgumentNullException.ThrowIfNull(password);
            ArgumentNullException.ThrowIfNull(kekBlobFile);
            ArgumentNullException.ThrowIfNull(options);

            this.device = device;
            this.credentialProvider = credentialProvider;
            this.options = options;

            byte[] srkAuth = TpmKekAuth.DeriveSrkAuth(password);
            byte[] kekAuth = TpmKekAuth.DeriveKekAuth(password);
            try
            {
                TpmPublic keySpec = ApplyPassword(CreateDefaultSrkKeySpec(), password);
                tpm = new Tpm2(device);

                try
                {
                    srkHandle = CreateSrk(tpm, keySpec, srkAuth);
                    kekBlobFile.Refresh();
                    if (kekBlobFile.Exists)
                    {
                        TpmKekBlob kekBlob = TpmKekBlob.Load(kekBlobFile);
                        wrapMode = InferWrapMode(kekBlob.Public);
                        rsaKeySize = GetRsaKeySize(kekBlob.Public, options.RsaKeySize);
                        kekHandle = LoadKek(tpm, srkHandle, kekBlob, kekAuth);
                        KeyId = CreateKeyId(kekBlob.Public);
                    }
                    else
                    {
                        wrapMode = options.WrapMode;
                        rsaKeySize = options.RsaKeySize;
                        TpmPrivate kekPrivate = tpm.Create(
                            srkHandle,
                            new SensitiveCreate(kekAuth, null),
                            CreateKekKeySpec(options),
                            null,
                            [],
                            out TpmPublic kekPublic,
                            out _,
                            out _,
                            out _);

                        new TpmKekBlob(kekPrivate, kekPublic).Save(kekBlobFile);
                        kekHandle = tpm.Load(srkHandle, kekPrivate, kekPublic);
                        ApplyHandleAuth(kekHandle, kekAuth);
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
            finally
            {
                CryptographicOperations.ZeroMemory(srkAuth);
                CryptographicOperations.ZeroMemory(kekAuth);
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

            return wrapMode switch
            {
                TpmKekWrapMode.Aes256Cfb => EncryptAes(plain),
                TpmKekWrapMode.RsaOaep256 => EncryptRsa(plain),
                _ => throw new InvalidOperationException($"Unsupported wrap mode: {wrapMode}.")
            };
        }

        /// <inheritdoc />
        public byte[] Decrypt(byte[] encrypted)
        {
            ObjectDisposedException.ThrowIf(disposedValue, this);
            ArgumentNullException.ThrowIfNull(encrypted);

            return wrapMode switch
            {
                TpmKekWrapMode.Aes256Cfb => DecryptAes(encrypted),
                TpmKekWrapMode.RsaOaep256 => DecryptRsa(encrypted),
                _ => throw new InvalidOperationException($"Unsupported wrap mode: {wrapMode}.")
            };
        }

        /// <summary>
        /// 동일 SRK 아래 새 KEK blob으로 로테이션된 <see cref="TpmKekCipher"/>를 생성한다.
        /// </summary>
        /// <param name="newKekBlobFile">새 KEK blob 저장 파일.</param>
        /// <param name="options">wrap 모드·RSA 키 옵션. null이면 현재 옵션을 재사용한다.</param>
        /// <returns>새 <see cref="TpmKekCipher"/>.</returns>
        public TpmKekCipher Rotate(FileInfo newKekBlobFile, TpmKekOptions? options = null)
        {
            ObjectDisposedException.ThrowIf(disposedValue, this);
            ArgumentNullException.ThrowIfNull(newKekBlobFile);
            return Create(device, credentialProvider, newKekBlobFile, options ?? this.options);
        }

        private TpmHandle Kek
            => kekHandle ?? throw new InvalidOperationException("KEK is not loaded.");

        private byte[] EncryptAes(byte[] plain)
        {
            byte[] iv = new byte[AesBlockSize];
            RandomNumberGenerator.Fill(iv);
            byte[] cipher = tpm.EncryptDecrypt(Kek, 0, TpmAlgId.Cfb, iv, plain, out _);

            byte[] output = new byte[iv.Length + cipher.Length];
            Buffer.BlockCopy(iv, 0, output, 0, iv.Length);
            Buffer.BlockCopy(cipher, 0, output, iv.Length, cipher.Length);
            return output;
        }

        private byte[] DecryptAes(byte[] encrypted)
        {
            if (encrypted.Length < AesBlockSize)
                throw new ArgumentException("Encrypted payload is shorter than the AES-CFB IV.", nameof(encrypted));

            byte[] iv = encrypted.AsSpan(0, AesBlockSize).ToArray();
            byte[] cipher = encrypted.AsSpan(AesBlockSize).ToArray();
            return tpm.EncryptDecrypt(Kek, 1, TpmAlgId.Cfb, iv, cipher, out _);
        }

        private byte[] EncryptRsa(byte[] plain)
        {
            ValidateRsaPlaintextSize(plain.Length);
            return tpm.RsaEncrypt(Kek, plain, OaepSha256, null);
        }

        private byte[] DecryptRsa(byte[] encrypted)
        {
            return tpm.RsaDecrypt(Kek, encrypted, OaepSha256, null);
        }

        private void ValidateRsaPlaintextSize(int plaintextLength)
        {
            int maxPlaintextLength = GetMaxRsaOaepPlaintextSize(rsaKeySize);
            if (plaintextLength > maxPlaintextLength)
            {
                throw new ArgumentException(
                    $"Plaintext length {plaintextLength} exceeds RSA-OAEP maximum of {maxPlaintextLength} bytes for {rsaKeySize}-bit keys.",
                    "plain");
            }
        }

        private static int GetRsaKeySize(TpmPublic kekPublic, int fallbackKeySize)
        {
            if (kekPublic.type != TpmAlgId.Rsa)
                return fallbackKeySize;

            if (kekPublic.parameters is not RsaParms rsaParms)
                throw new InvalidDataException("RSA KEK public parameters are missing.");

            return rsaParms.keyBits;
        }

        private static int GetMaxRsaOaepPlaintextSize(int rsaKeySize)
            => rsaKeySize / 8 - 2 * OaepSha256HashSize - 2;

        private static TpmKekWrapMode InferWrapMode(TpmPublic kekPublic)
        {
            ArgumentNullException.ThrowIfNull(kekPublic);

            return kekPublic.type switch
            {
                TpmAlgId.Symcipher => TpmKekWrapMode.Aes256Cfb,
                TpmAlgId.Rsa => TpmKekWrapMode.RsaOaep256,
                _ => throw new NotSupportedException($"Unsupported TPM KEK type: {kekPublic.type}.")
            };
        }

        private static string CreateKeyId(TpmPublic publicKey)
        {
            byte[] publicBytes = Marshaller.GetTpmRepresentation(publicKey);
            return $"tpm:{Convert.ToHexString(SHA256.HashData(publicBytes)).ToLowerInvariant()}";
        }

        private static void ApplyHandleAuth(TpmHandle handle, byte[] auth)
        {
            handle.Auth = new AuthValue(auth);
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

        private static TpmHandle LoadKek(Tpm2 tpm, TpmHandle srk, TpmKekBlob kekBlob, byte[] kekAuth)
        {
            ArgumentNullException.ThrowIfNull(tpm);
            ArgumentNullException.ThrowIfNull(srk);
            ArgumentNullException.ThrowIfNull(kekBlob);
            ArgumentNullException.ThrowIfNull(kekAuth);

            TpmHandle handle = LoadKek(tpm, srk, kekBlob.Private, kekBlob.Public);
            ApplyHandleAuth(handle, kekAuth);
            return handle;
        }

        private static TpmHandle LoadKek(Tpm2 tpm, TpmHandle srk, TpmPrivate kekPrivate, TpmPublic kekPublic)
        {
            ArgumentNullException.ThrowIfNull(tpm);
            ArgumentNullException.ThrowIfNull(srk);
            ArgumentNullException.ThrowIfNull(kekPrivate);
            ArgumentNullException.ThrowIfNull(kekPublic);

            return tpm.Load(srk, kekPrivate, kekPublic);
        }

        private static TpmHandle CreateSrk(Tpm2 tpm, TpmPublic keySpec, byte[] srkAuth)
        {
            TpmHandle handle = tpm.CreatePrimary(
                TpmRh.Owner,
                new SensitiveCreate(srkAuth, null),
                keySpec,
                null,
                [],
                out _,
                out _,
                out _,
                out _);

            ApplyHandleAuth(handle, srkAuth);
            return handle;
        }

        private static TpmPublic CreateKekKeySpec(TpmKekOptions options)
        {
            return options.WrapMode switch
            {
                TpmKekWrapMode.Aes256Cfb => new TpmPublic(
                    TpmAlgId.Sha256,
                    ObjectAttr.Decrypt | ObjectAttr.Encrypt |
                    ObjectAttr.FixedParent | ObjectAttr.FixedTPM |
                    ObjectAttr.UserWithAuth | ObjectAttr.SensitiveDataOrigin | ObjectAttr.NoDA,
                    null,
                    new SymDefObject(TpmAlgId.Aes, 256, TpmAlgId.Cfb),
                    new Tpm2bDigestSymcipher()),
                TpmKekWrapMode.RsaOaep256 => new TpmPublic(
                    TpmAlgId.Sha256,
                    ObjectAttr.Decrypt |
                    ObjectAttr.FixedParent | ObjectAttr.FixedTPM |
                    ObjectAttr.UserWithAuth | ObjectAttr.SensitiveDataOrigin | ObjectAttr.NoDA,
                    null,
                    new RsaParms(
                        new SymDefObject(),
                        new SchemeOaep(TpmAlgId.Sha256),
                        (ushort)options.RsaKeySize,
                        0),
                    new Tpm2bPublicKeyRsa()),
                _ => throw new NotSupportedException($"Unsupported wrap mode: {options.WrapMode}.")
            };
        }

        /// <summary>
        /// TPM 디바이스와 자격 증명·KEK blob 파일로 <see cref="TpmKekCipher"/>를 생성한다.
        /// </summary>
        /// <param name="device">연결된 TPM 디바이스. 수명은 호출부가 관리하며, cipher Dispose 시 device는 닫히지 않는다.</param>
        /// <param name="credentialProvider">SRK·KEK authValue 유도용 패스워드 제공자. Create 시 1회만 사용한다.</param>
        /// <param name="kekBlobFile">KEK blob 저장·로드 파일.</param>
        /// <param name="options">wrap 모드·RSA 키 옵션.</param>
        /// <returns>생성된 <see cref="TpmKekCipher"/>.</returns>
        public static TpmKekCipher Create(
            Tpm2Device device,
            IKekCredentialProvider credentialProvider,
            FileInfo kekBlobFile,
            TpmKekOptions? options = null)
        {
            options ??= new TpmKekOptions();
            byte[] password = credentialProvider.GetPassword();
            try
            {
                return new TpmKekCipher(device, credentialProvider, password, kekBlobFile, options);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(password);
            }
        }
    }
}

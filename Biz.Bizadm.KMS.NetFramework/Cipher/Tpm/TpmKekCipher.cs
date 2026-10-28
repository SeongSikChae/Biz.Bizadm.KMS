using System.Security.Cryptography;
using Tpm2Lib;

namespace Biz.Bizadm.KMS.NetFramework.Cipher.Tpm;

/// <summary>
/// Independent TPM 2.0 KEK for net48. Wrap modes and blob/auth formats match the net10 implementation.
/// </summary>
public sealed class TpmKekCipher : IKekCipher
{
    private static readonly SchemeOaep OaepSha256 = new SchemeOaep(TpmAlgId.Sha256);

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

    public string KeyId { get; }

    private TpmKekCipher(
        Tpm2Device device,
        IKekCredentialProvider credentialProvider,
        byte[] password,
        FileInfo kekBlobFile,
        TpmKekOptions options)
    {
        this.device = device ?? throw new ArgumentNullException(nameof(device));
        this.credentialProvider = credentialProvider ?? throw new ArgumentNullException(nameof(credentialProvider));
        if (password is null) throw new ArgumentNullException(nameof(password));
        if (kekBlobFile is null) throw new ArgumentNullException(nameof(kekBlobFile));
        this.options = options ?? throw new ArgumentNullException(nameof(options));

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
                        Array.Empty<PcrSelection>(),
                        out TpmPublic kekPublic,
                        out CreationData _,
                        out byte[] _,
                        out TkCreation _);

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
            Array.Clear(srkAuth, 0, srkAuth.Length);
            Array.Clear(kekAuth, 0, kekAuth.Length);
        }
    }

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
            Array.Clear(password, 0, password.Length);
        }
    }

    public string GetKeyId() => KeyId;

    public Task<byte[]> EncryptAsync(byte[] plain, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(Encrypt(plain));
    }

    public Task<byte[]> DecryptAsync(byte[] encrypted, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(Decrypt(encrypted));
    }

    public byte[] Encrypt(byte[] plain)
    {
        if (disposedValue) throw new ObjectDisposedException(nameof(TpmKekCipher));
        if (plain is null) throw new ArgumentNullException(nameof(plain));

        return wrapMode switch
        {
            TpmKekWrapMode.Aes256Cfb => EncryptAes(plain),
            TpmKekWrapMode.RsaOaep256 => EncryptRsa(plain),
            _ => throw new InvalidOperationException("Unsupported wrap mode: " + wrapMode + ".")
        };
    }

    public byte[] Decrypt(byte[] encrypted)
    {
        if (disposedValue) throw new ObjectDisposedException(nameof(TpmKekCipher));
        if (encrypted is null) throw new ArgumentNullException(nameof(encrypted));

        return wrapMode switch
        {
            TpmKekWrapMode.Aes256Cfb => DecryptAes(encrypted),
            TpmKekWrapMode.RsaOaep256 => DecryptRsa(encrypted),
            _ => throw new InvalidOperationException("Unsupported wrap mode: " + wrapMode + ".")
        };
    }

    public TpmKekCipher Rotate(FileInfo newKekBlobFile, TpmKekOptions? rotateOptions = null)
    {
        if (disposedValue) throw new ObjectDisposedException(nameof(TpmKekCipher));
        if (newKekBlobFile is null) throw new ArgumentNullException(nameof(newKekBlobFile));
        return Create(device, credentialProvider, newKekBlobFile, rotateOptions ?? options);
    }

    public byte[] RewrapDek(IKekCipher source, byte[] wrappedDek)
        => KekCipherExtensions.RewrapDek(this, source, wrappedDek);

    public Task<byte[]> RewrapDekAsync(IKekCipher source, byte[] wrappedDek, CancellationToken cancellationToken = default)
        => KekCipherExtensions.RewrapDekAsync(this, source, wrappedDek, cancellationToken);

    public void Dispose()
    {
        if (disposedValue) return;
        Flush(kekHandle);
        kekHandle = null;
        Flush(srkHandle);
        srkHandle = null;
        disposedValue = true;
        GC.SuppressFinalize(this);
    }

    private TpmHandle Kek
        => kekHandle ?? throw new InvalidOperationException("KEK is not loaded.");

    private byte[] EncryptAes(byte[] plain)
    {
        byte[] iv = new byte[AesBlockSize];
        using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(iv);
        }

        byte[] cipher = tpm.EncryptDecrypt(Kek, (byte)0, TpmAlgId.Cfb, iv, plain, out byte[] _);
        byte[] output = new byte[iv.Length + cipher.Length];
        Buffer.BlockCopy(iv, 0, output, 0, iv.Length);
        Buffer.BlockCopy(cipher, 0, output, iv.Length, cipher.Length);
        return output;
    }

    private byte[] DecryptAes(byte[] encrypted)
    {
        if (encrypted.Length < AesBlockSize)
            throw new ArgumentException("Encrypted payload is shorter than the AES-CFB IV.", nameof(encrypted));

        byte[] iv = new byte[AesBlockSize];
        Buffer.BlockCopy(encrypted, 0, iv, 0, AesBlockSize);
        byte[] cipher = new byte[encrypted.Length - AesBlockSize];
        Buffer.BlockCopy(encrypted, AesBlockSize, cipher, 0, cipher.Length);
        return tpm.EncryptDecrypt(Kek, (byte)1, TpmAlgId.Cfb, iv, cipher, out byte[] _);
    }

    private byte[] EncryptRsa(byte[] plain)
    {
        ValidateRsaPlaintextSize(plain.Length);
        return tpm.RsaEncrypt(Kek, plain, OaepSha256, null);
    }

    private byte[] DecryptRsa(byte[] encrypted)
        => tpm.RsaDecrypt(Kek, encrypted, OaepSha256, null);

    private void ValidateRsaPlaintextSize(int plaintextLength)
    {
        int maxPlaintextLength = rsaKeySize / 8 - 2 * OaepSha256HashSize - 2;
        if (plaintextLength > maxPlaintextLength)
        {
            throw new ArgumentException(
                "Plaintext length " + plaintextLength + " exceeds RSA-OAEP maximum of " + maxPlaintextLength +
                " bytes for " + rsaKeySize + "-bit keys.",
                nameof(plaintextLength));
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

    private static TpmKekWrapMode InferWrapMode(TpmPublic kekPublic)
    {
        if (kekPublic is null) throw new ArgumentNullException(nameof(kekPublic));
        return kekPublic.type switch
        {
            TpmAlgId.Symcipher => TpmKekWrapMode.Aes256Cfb,
            TpmAlgId.Rsa => TpmKekWrapMode.RsaOaep256,
            _ => throw new NotSupportedException("Unsupported TPM KEK type: " + kekPublic.type + ".")
        };
    }

    private static string CreateKeyId(TpmPublic publicKey)
    {
        byte[] publicBytes = Marshaller.GetTpmRepresentation(publicKey);
        using (SHA256 sha = SHA256.Create())
        {
            byte[] hash = sha.ComputeHash(publicBytes);
            return "tpm:" + BitConverter.ToString(hash).Replace("-", string.Empty).ToLowerInvariant();
        }
    }

    private static void ApplyHandleAuth(TpmHandle handle, byte[] auth)
        => handle.Auth = new AuthValue(auth);

    private void Flush(TpmHandle? handle)
    {
        if (handle is null) return;
        try { tpm.FlushContext(handle); }
        catch (Exception) { }
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

        using (SHA256 sha = SHA256.Create())
        {
            byte[] seed = sha.ComputeHash(password);
            return new TpmPublic(
                keySpec.nameAlg,
                keySpec.objectAttributes,
                keySpec.authPolicy,
                keySpec.parameters,
                CreateUnique(keySpec.type, seed));
        }
    }

    private static IPublicIdUnion CreateUnique(TpmAlgId type, byte[] seed)
    {
        return type switch
        {
            TpmAlgId.Rsa => new Tpm2bPublicKeyRsa(seed),
            TpmAlgId.Keyedhash => new Tpm2bDigestKeyedhash(seed),
            TpmAlgId.Symcipher => new Tpm2bDigestSymcipher(seed),
            _ => throw new NotSupportedException("Password-derived SRK is not supported for " + type + ".")
        };
    }

    private static TpmHandle LoadKek(Tpm2 tpm, TpmHandle srk, TpmKekBlob kekBlob, byte[] kekAuth)
    {
        TpmHandle handle = tpm.Load(srk, kekBlob.Private, kekBlob.Public);
        ApplyHandleAuth(handle, kekAuth);
        return handle;
    }

    private static TpmHandle CreateSrk(Tpm2 tpm, TpmPublic keySpec, byte[] srkAuth)
    {
        TpmHandle handle = tpm.CreatePrimary(
            TpmRh.Owner,
            new SensitiveCreate(srkAuth, null),
            keySpec,
            null,
            Array.Empty<PcrSelection>(),
            out TpmPublic _,
            out CreationData _,
            out byte[] _,
            out TkCreation _);
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
            _ => throw new NotSupportedException("Unsupported wrap mode: " + options.WrapMode + ".")
        };
    }
}

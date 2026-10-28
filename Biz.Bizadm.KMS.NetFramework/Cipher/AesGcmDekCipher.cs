using System.Security.Cryptography;

namespace Biz.Bizadm.KMS.NetFramework.Cipher;

/// <summary>
/// AES-256-GCM DEK cipher with KDEK envelope creation and rewrap helpers.
/// </summary>
public sealed class AesGcmDekCipher : AbstractAesGcmCipher, IDekCipher
{
    private AesGcmDekCipher(byte[] key)
        : base(key)
    {
    }

    public static AesGcmDekCipher Create(byte[] key)
    {
        if (key is null) throw new ArgumentNullException(nameof(key));
        if (key.Length != 32) throw new ArgumentException("A DEK must contain exactly 32 bytes.", nameof(key));
        return new AesGcmDekCipher(key);
    }

    public static AesGcmDekCipher CreateRandom()
    {
        byte[] key = new byte[32];
        using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(key);
        try
        {
            return new AesGcmDekCipher(key);
        }
        finally
        {
            Array.Clear(key, 0, key.Length);
        }
    }

    public static AesGcmDekCipher Create(IKekCipher kek, byte[] envelopeBytes)
    {
        if (kek is null) throw new ArgumentNullException(nameof(kek));
        if (envelopeBytes is null) throw new ArgumentNullException(nameof(envelopeBytes));
        WrappedDekEnvelope envelope = WrappedDekEnvelope.Deserialize(envelopeBytes);
        if (!string.Equals(envelope.KeyId, kek.KeyId, StringComparison.Ordinal))
            throw new InvalidDataException("KDEK KeyId does not match the supplied KEK.");
        byte[] dek = kek.Decrypt(envelope.WrappedKey);
        try
        {
            return Create(dek);
        }
        finally
        {
            Array.Clear(dek, 0, dek.Length);
        }
    }

    public static byte[] CreateEnvelope(IKekCipher kek, byte[] dek)
    {
        if (kek is null) throw new ArgumentNullException(nameof(kek));
        if (dek is null) throw new ArgumentNullException(nameof(dek));
        if (dek.Length != 32) throw new ArgumentException("A DEK must contain exactly 32 bytes.", nameof(dek));
        byte[] wrapped = kek.Encrypt(dek);
        try
        {
            return new WrappedDekEnvelope(kek.KeyId, wrapped).Serialize();
        }
        finally
        {
            Array.Clear(wrapped, 0, wrapped.Length);
        }
    }

    public static byte[] CreateEnvelope(IKekCipher kek, AesGcmDekCipher dek)
    {
        if (dek is null) throw new ArgumentNullException(nameof(dek));
        byte[] keyMaterial = dek.ExportKeyMaterial();
        try
        {
            return CreateEnvelope(kek, keyMaterial);
        }
        finally
        {
            Array.Clear(keyMaterial, 0, keyMaterial.Length);
        }
    }

    public static async Task<byte[]> CreateEnvelopeAsync(
        IKekCipher kek,
        byte[] dek,
        CancellationToken cancellationToken = default)
    {
        if (kek is null) throw new ArgumentNullException(nameof(kek));
        if (dek is null) throw new ArgumentNullException(nameof(dek));
        if (dek.Length != 32) throw new ArgumentException("A DEK must contain exactly 32 bytes.", nameof(dek));
        byte[] wrapped = await kek.EncryptAsync(dek, cancellationToken).ConfigureAwait(false);
        try
        {
            return new WrappedDekEnvelope(kek.KeyId, wrapped).Serialize();
        }
        finally
        {
            Array.Clear(wrapped, 0, wrapped.Length);
        }
    }

    public static byte[] RewrapEnvelope(IKekCipher source, IKekCipher target, byte[] envelopeBytes)
    {
        if (source is null) throw new ArgumentNullException(nameof(source));
        if (target is null) throw new ArgumentNullException(nameof(target));
        if (envelopeBytes is null) throw new ArgumentNullException(nameof(envelopeBytes));
        WrappedDekEnvelope envelope = WrappedDekEnvelope.Deserialize(envelopeBytes);
        if (!string.Equals(envelope.KeyId, source.KeyId, StringComparison.Ordinal))
            throw new InvalidDataException("KDEK KeyId does not match the source KEK.");
        byte[] replacement = target.RewrapDek(source, envelope.WrappedKey);
        try
        {
            return new WrappedDekEnvelope(target.KeyId, replacement).Serialize();
        }
        finally
        {
            Array.Clear(replacement, 0, replacement.Length);
        }
    }

    public static AesGcmDekCipher CreateFromFile(IKekCipher kek, string path)
    {
        if (kek is null) throw new ArgumentNullException(nameof(kek));
        if (string.IsNullOrEmpty(path)) throw new ArgumentException("A file path is required.", nameof(path));
        if (File.Exists(path)) return Create(kek, DekEnvelopeStorage.ReadAllBytes(path));

        using (AesGcmDekCipher generated = CreateRandom())
        {
            byte[] keyMaterial = generated.ExportKeyMaterial();
            try
            {
                byte[] envelope = CreateEnvelope(kek, keyMaterial);
                try
                {
                    DekEnvelopeStorage.CreateIfMissing(path, envelope);
                }
                finally
                {
                    Array.Clear(envelope, 0, envelope.Length);
                }
            }
            finally
            {
                Array.Clear(keyMaterial, 0, keyMaterial.Length);
            }
        }
        return Create(kek, DekEnvelopeStorage.ReadAllBytes(path));
    }

    public static async Task<AesGcmDekCipher> CreateFromFileAsync(
        IKekCipher kek,
        string path,
        CancellationToken cancellationToken = default)
    {
        if (kek is null) throw new ArgumentNullException(nameof(kek));
        if (string.IsNullOrEmpty(path)) throw new ArgumentException("A file path is required.", nameof(path));
        if (File.Exists(path))
            return Create(kek, await DekEnvelopeStorage.ReadAllBytesAsync(path, cancellationToken).ConfigureAwait(false));

        using (AesGcmDekCipher generated = CreateRandom())
        {
            byte[] keyMaterial = generated.ExportKeyMaterial();
            try
            {
                byte[] envelope = await CreateEnvelopeAsync(kek, keyMaterial, cancellationToken).ConfigureAwait(false);
                try
                {
                    await DekEnvelopeStorage.CreateIfMissingAsync(path, envelope, cancellationToken).ConfigureAwait(false);
                }
                finally
                {
                    Array.Clear(envelope, 0, envelope.Length);
                }
            }
            finally
            {
                Array.Clear(keyMaterial, 0, keyMaterial.Length);
            }
        }
        return Create(kek, await DekEnvelopeStorage.ReadAllBytesAsync(path, cancellationToken).ConfigureAwait(false));
    }

    public static void RewrapFile(IKekCipher source, IKekCipher target, string path)
    {
        if (source is null) throw new ArgumentNullException(nameof(source));
        if (target is null) throw new ArgumentNullException(nameof(target));
        if (string.IsNullOrEmpty(path)) throw new ArgumentException("A file path is required.", nameof(path));
        byte[] original = DekEnvelopeStorage.ReadAllBytes(path);
        byte[] rewrapped = RewrapEnvelope(source, target, original);
        try
        {
            DekEnvelopeStorage.ReplaceAtomically(path, rewrapped);
        }
        finally
        {
            Array.Clear(original, 0, original.Length);
            Array.Clear(rewrapped, 0, rewrapped.Length);
        }
    }

    private byte[] ExportKeyMaterial()
    {
        return ExportKeyMaterialCopy();
    }
}

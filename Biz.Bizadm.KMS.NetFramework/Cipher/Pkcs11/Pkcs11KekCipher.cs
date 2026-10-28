using System.Security.Cryptography;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;

namespace Biz.Bizadm.KMS.NetFramework.Cipher.Pkcs11;

/// <summary>
/// Independent PKCS#11 RSA-OAEP KEK for net48.
/// KeyId format matches net10: pkcs11:{SHA256(modulus||exponent)} lowercase hex.
/// </summary>
public sealed class Pkcs11KekCipher : IKekCipher
{
    private readonly Pkcs11LibraryContext context;
    private readonly Pkcs11KekOptions options;
    private readonly string keyLabel;
    private readonly IObjectHandle publicKey;
    private readonly IObjectHandle privateKey;
    private bool disposedValue;

    public string KeyId { get; }

    private Pkcs11KekCipher(
        Pkcs11LibraryContext context,
        Pkcs11KekOptions options,
        string keyLabel,
        IObjectHandle publicKey,
        IObjectHandle privateKey,
        string keyId)
    {
        this.context = context;
        this.options = options;
        this.keyLabel = keyLabel;
        this.publicKey = publicKey;
        this.privateKey = privateKey;
        KeyId = keyId;
    }

    public static Pkcs11KekCipher Create(
        Pkcs11LibraryContext context,
        string keyLabel,
        bool createIfMissing = true,
        Pkcs11KekOptions? options = null)
    {
        if (context is null) throw new ArgumentNullException(nameof(context));
        if (string.IsNullOrWhiteSpace(keyLabel)) throw new ArgumentException("Key label is required.", nameof(keyLabel));
        options ??= new Pkcs11KekOptions();

        return context.Execute(session =>
        {
            if (TryFindKeyPair(session, keyLabel, out IObjectHandle foundPublic, out IObjectHandle foundPrivate))
            {
                return new Pkcs11KekCipher(
                    context,
                    options,
                    keyLabel,
                    foundPublic,
                    foundPrivate,
                    CreateKeyId(session, foundPublic));
            }

            if (!createIfMissing)
                throw new KeyNotFoundException("PKCS#11 KEK with label '" + keyLabel + "' was not found.");

            GenerateKeyPair(session, keyLabel, options, out IObjectHandle generatedPublic, out IObjectHandle generatedPrivate);
            return new Pkcs11KekCipher(
                context,
                options,
                keyLabel,
                generatedPublic,
                generatedPrivate,
                CreateKeyId(session, generatedPublic));
        });
    }

    public Pkcs11KekCipher Rotate(string newKeyLabel, Pkcs11KekOptions? rotateOptions = null)
    {
        if (disposedValue) throw new ObjectDisposedException(nameof(Pkcs11KekCipher));
        if (string.IsNullOrWhiteSpace(newKeyLabel)) throw new ArgumentException("Key label is required.", nameof(newKeyLabel));
        return Create(context, newKeyLabel, createIfMissing: true, rotateOptions ?? options);
    }

    public byte[] Encrypt(byte[] plain)
    {
        if (disposedValue) throw new ObjectDisposedException(nameof(Pkcs11KekCipher));
        if (plain is null) throw new ArgumentNullException(nameof(plain));

        return context.Execute(session =>
        {
            IMechanism mechanism = CreateWrapMechanism(session);
            IObjectHandle dekKey = CreateEphemeralAesKey(session, plain);
            try
            {
                return session.WrapKey(mechanism, publicKey, dekKey);
            }
            finally
            {
                session.DestroyObject(dekKey);
            }
        });
    }

    public byte[] Decrypt(byte[] encrypted)
    {
        if (disposedValue) throw new ObjectDisposedException(nameof(Pkcs11KekCipher));
        if (encrypted is null) throw new ArgumentNullException(nameof(encrypted));

        return context.Execute(session =>
        {
            IMechanism mechanism = CreateWrapMechanism(session);
            List<IObjectAttribute> template = CreateUnwrappedAesTemplate(session);
            IObjectHandle unwrapped = session.UnwrapKey(mechanism, privateKey, encrypted, template);
            try
            {
                List<IObjectAttribute> valueAttributes = session.GetAttributeValue(
                    unwrapped,
                    new List<CKA> { CKA.CKA_VALUE });
                return valueAttributes[0].GetValueAsByteArray()
                    ?? throw new CryptographicException("PKCS#11 unwrapped DEK value was empty.");
            }
            finally
            {
                session.DestroyObject(unwrapped);
            }
        });
    }

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

    public byte[] RewrapDek(IKekCipher source, byte[] wrappedDek)
        => KekCipherExtensions.RewrapDek(this, source, wrappedDek);

    public Task<byte[]> RewrapDekAsync(IKekCipher source, byte[] wrappedDek, CancellationToken cancellationToken = default)
        => KekCipherExtensions.RewrapDekAsync(this, source, wrappedDek, cancellationToken);

    public void Dispose()
    {
        if (disposedValue) return;
        disposedValue = true;
        GC.SuppressFinalize(this);
    }

    private IMechanism CreateWrapMechanism(ISession session)
    {
        if (options.WrapMechanism != CKM.CKM_RSA_PKCS_OAEP)
            return session.Factories.MechanismFactory.Create(options.WrapMechanism);

        byte[] label = options.OaepLabel ?? Array.Empty<byte>();
        var oaepParams = session.Factories.MechanismParamsFactory.CreateCkRsaPkcsOaepParams(
            ConvertUtils.UInt64FromCKM(options.OaepHashAlgorithm),
            ConvertUtils.UInt64FromCKG(options.OaepMgf),
            ConvertUtils.UInt64FromUInt32((uint)CKZ.CKZ_DATA_SPECIFIED),
            label);

        return session.Factories.MechanismFactory.Create(CKM.CKM_RSA_PKCS_OAEP, oaepParams);
    }

    private static IObjectHandle CreateEphemeralAesKey(ISession session, byte[] dekBytes)
    {
        List<IObjectAttribute> attributes = new List<IObjectAttribute>
        {
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_AES),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_VALUE, dekBytes),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, false),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, false),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_EXTRACTABLE, true),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_SENSITIVE, false),
        };
        return session.CreateObject(attributes);
    }

    private static List<IObjectAttribute> CreateUnwrappedAesTemplate(ISession session)
    {
        return new List<IObjectAttribute>
        {
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_AES),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, false),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, false),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_EXTRACTABLE, true),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_SENSITIVE, false),
        };
    }

    private static bool TryFindKeyPair(
        ISession session,
        string keyLabel,
        out IObjectHandle publicKey,
        out IObjectHandle privateKey)
    {
        List<IObjectAttribute> privateTemplate = new List<IObjectAttribute>
        {
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, keyLabel),
        };

        List<IObjectHandle> privateKeys = session.FindAllObjects(privateTemplate);
        if (privateKeys.Count == 0)
        {
            publicKey = null!;
            privateKey = null!;
            return false;
        }

        privateKey = privateKeys[0];
        List<IObjectAttribute> idAttributes = session.GetAttributeValue(privateKey, new List<CKA> { CKA.CKA_ID });
        byte[]? keyId = idAttributes[0].GetValueAsByteArray();
        if (keyId is null || keyId.Length == 0)
            throw new CryptographicException("PKCS#11 private key '" + keyLabel + "' has no CKA_ID.");

        List<IObjectAttribute> publicTemplate = new List<IObjectAttribute>
        {
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, keyId),
        };

        List<IObjectHandle> publicKeys = session.FindAllObjects(publicTemplate);
        if (publicKeys.Count == 0)
            throw new CryptographicException("PKCS#11 public key for label '" + keyLabel + "' was not found.");

        publicKey = publicKeys[0];
        return true;
    }

    private static void GenerateKeyPair(
        ISession session,
        string keyLabel,
        Pkcs11KekOptions options,
        out IObjectHandle publicKey,
        out IObjectHandle privateKey)
    {
        byte[] keyId = new byte[16];
        using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(keyId);
        }

        List<IObjectAttribute> publicTemplate = new List<IObjectAttribute>
        {
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, false),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, keyLabel),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, keyId),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_WRAP, true),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ENCRYPT, true),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_VERIFY, false),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_MODULUS_BITS, ConvertUtils.UInt32FromInt32(options.RsaKeySize)),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PUBLIC_EXPONENT, new byte[] { 0x01, 0x00, 0x01 }),
        };

        List<IObjectAttribute> privateTemplate = new List<IObjectAttribute>
        {
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, true),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, keyLabel),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, keyId),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_UNWRAP, true),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_DECRYPT, true),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_SENSITIVE, true),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_EXTRACTABLE, false),
        };

        IMechanism mechanism = session.Factories.MechanismFactory.Create(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN);
        session.GenerateKeyPair(mechanism, publicTemplate, privateTemplate, out publicKey, out privateKey);
    }

    private static string CreateKeyId(ISession session, IObjectHandle publicKey)
    {
        List<IObjectAttribute> attributes = session.GetAttributeValue(
            publicKey,
            new List<CKA> { CKA.CKA_MODULUS, CKA.CKA_PUBLIC_EXPONENT });

        byte[] modulus = attributes[0].GetValueAsByteArray()
            ?? throw new CryptographicException("PKCS#11 public key modulus was empty.");
        byte[] exponent = attributes[1].GetValueAsByteArray()
            ?? throw new CryptographicException("PKCS#11 public key exponent was empty.");

        byte[] publicMaterial = new byte[modulus.Length + exponent.Length];
        Buffer.BlockCopy(modulus, 0, publicMaterial, 0, modulus.Length);
        Buffer.BlockCopy(exponent, 0, publicMaterial, modulus.Length, exponent.Length);

        using (SHA256 sha = SHA256.Create())
        {
            byte[] hash = sha.ComputeHash(publicMaterial);
            return "pkcs11:" + BitConverter.ToString(hash).Replace("-", string.Empty).ToLowerInvariant();
        }
    }
}

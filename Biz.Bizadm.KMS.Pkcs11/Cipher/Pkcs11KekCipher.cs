using Biz.Bizadm.KMS.Cipher;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using System.Security.Cryptography;

namespace Biz.Bizadm.KMS.Pkcs11.Cipher
{
    /// <summary>
    /// PKCS#11 RSA KEK로 DEK를 wrap/unwrap하는 암호.
    /// </summary>
    public sealed class Pkcs11KekCipher : IKekCipher
    {
        private readonly Pkcs11LibraryContext context;
        private readonly Pkcs11KekOptions options;
        private readonly string keyLabel;
        private readonly IObjectHandle publicKey;
        private readonly IObjectHandle privateKey;
        private bool disposedValue;

        /// <inheritdoc />
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

        /// <summary>
        /// HSM에서 라벨로 KEK를 찾거나(없으면 생성) 사용 가능한 암호를 반환한다.
        /// </summary>
        /// <param name="context">로그인된 PKCS#11 컨텍스트.</param>
        /// <param name="keyLabel">HSM 키 라벨.</param>
        /// <param name="createIfMissing">키가 없을 때 생성할지 여부.</param>
        /// <param name="options">wrap 메커니즘·RSA 키 옵션.</param>
        /// <returns>생성된 <see cref="Pkcs11KekCipher"/>.</returns>
        public static Pkcs11KekCipher Create(
            Pkcs11LibraryContext context,
            string keyLabel,
            bool createIfMissing = true,
            Pkcs11KekOptions? options = null)
        {
            ArgumentNullException.ThrowIfNull(context);
            ArgumentException.ThrowIfNullOrWhiteSpace(keyLabel);
            options ??= new Pkcs11KekOptions();

            return context.Execute(session =>
            {
                if (TryFindKeyPair(session, keyLabel, out IObjectHandle? foundPublic, out IObjectHandle? foundPrivate))
                    return new Pkcs11KekCipher(
                        context,
                        options,
                        keyLabel,
                        foundPublic,
                        foundPrivate,
                        CreateKeyId(session, foundPublic));

                if (!createIfMissing)
                    throw new KeyNotFoundException($"PKCS#11 KEK with label '{keyLabel}' was not found.");

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

        /// <summary>
        /// HSM에 새 RSA KEK를 생성한 뒤 새 <see cref="Pkcs11KekCipher"/>를 반환한다.
        /// </summary>
        /// <param name="newKeyLabel">새 KEK 라벨.</param>
        /// <param name="options">wrap 메커니즘·RSA 키 옵션. null이면 현재 옵션을 재사용한다.</param>
        /// <returns>새 KEK를 사용하는 <see cref="Pkcs11KekCipher"/>.</returns>
        public Pkcs11KekCipher Rotate(string newKeyLabel, Pkcs11KekOptions? options = null)
        {
            ObjectDisposedException.ThrowIf(disposedValue, this);
            ArgumentException.ThrowIfNullOrWhiteSpace(newKeyLabel);
            return Create(context, newKeyLabel, createIfMissing: true, options ?? this.options);
        }

        /// <inheritdoc />
        public byte[] Encrypt(byte[] plain)
        {
            ObjectDisposedException.ThrowIf(disposedValue, this);
            ArgumentNullException.ThrowIfNull(plain);

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

        /// <inheritdoc />
        public byte[] Decrypt(byte[] encrypted)
        {
            ObjectDisposedException.ThrowIf(disposedValue, this);
            ArgumentNullException.ThrowIfNull(encrypted);

            return context.Execute(session =>
            {
                IMechanism mechanism = CreateWrapMechanism(session);
                List<IObjectAttribute> template = CreateUnwrappedAesTemplate(session);
                IObjectHandle unwrapped = session.UnwrapKey(mechanism, privateKey, encrypted, template);
                try
                {
                    List<IObjectAttribute> valueAttributes = session.GetAttributeValue(
                        unwrapped,
                        [CKA.CKA_VALUE]);
                    return valueAttributes[0].GetValueAsByteArray()
                        ?? throw new CryptographicException("PKCS#11 unwrapped DEK value was empty.");
                }
                finally
                {
                    session.DestroyObject(unwrapped);
                }
            });
        }

        /// <inheritdoc />
        public Task<byte[]> EncryptAsync(byte[] plain, CancellationToken cancellationToken = default)
            => Task.FromResult(Encrypt(plain));

        /// <inheritdoc />
        public Task<byte[]> DecryptAsync(byte[] encrypted, CancellationToken cancellationToken = default)
            => Task.FromResult(Decrypt(encrypted));

        /// <inheritdoc />
        public void Dispose()
        {
            if (disposedValue)
                return;

            disposedValue = true;
            GC.SuppressFinalize(this);
        }

        private IMechanism CreateWrapMechanism(ISession session)
        {
            if (options.WrapMechanism != CKM.CKM_RSA_PKCS_OAEP)
                return session.Factories.MechanismFactory.Create(options.WrapMechanism);

            byte[] label = options.OaepLabel ?? [];
            var oaepParams = session.Factories.MechanismParamsFactory.CreateCkRsaPkcsOaepParams(
                ConvertUtils.UInt64FromCKM(options.OaepHashAlgorithm),
                ConvertUtils.UInt64FromCKG(options.OaepMgf),
                ConvertUtils.UInt64FromUInt32((uint)CKZ.CKZ_DATA_SPECIFIED),
                label);

            return session.Factories.MechanismFactory.Create(CKM.CKM_RSA_PKCS_OAEP, oaepParams);
        }

        private static IObjectHandle CreateEphemeralAesKey(ISession session, byte[] dekBytes)
        {
            List<IObjectAttribute> attributes =
            [
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_AES),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_VALUE, dekBytes),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, false),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, false),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_EXTRACTABLE, true),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_SENSITIVE, false),
            ];

            return session.CreateObject(attributes);
        }

        private static List<IObjectAttribute> CreateUnwrappedAesTemplate(ISession session)
        {
            return
            [
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_AES),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, false),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, false),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_EXTRACTABLE, true),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_SENSITIVE, false),
            ];
        }

        private static bool TryFindKeyPair(
            ISession session,
            string keyLabel,
            out IObjectHandle publicKey,
            out IObjectHandle privateKey)
        {
            List<IObjectAttribute> privateTemplate =
            [
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, keyLabel),
            ];

            List<IObjectHandle> privateKeys = session.FindAllObjects(privateTemplate);
            if (privateKeys.Count == 0)
            {
                publicKey = null!;
                privateKey = null!;
                return false;
            }

            privateKey = privateKeys[0];
            List<IObjectAttribute> idAttributes = session.GetAttributeValue(privateKey, [CKA.CKA_ID]);
            byte[]? keyId = idAttributes[0].GetValueAsByteArray();
            if (keyId is null || keyId.Length == 0)
                throw new CryptographicException($"PKCS#11 private key '{keyLabel}' has no CKA_ID.");

            List<IObjectAttribute> publicTemplate =
            [
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, keyId),
            ];

            List<IObjectHandle> publicKeys = session.FindAllObjects(publicTemplate);
            if (publicKeys.Count == 0)
                throw new CryptographicException($"PKCS#11 public key for label '{keyLabel}' was not found.");

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
            byte[] keyId = RandomNumberGenerator.GetBytes(16);
            List<IObjectAttribute> publicTemplate =
            [
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, false),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, keyLabel),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, keyId),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_WRAP, true),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ENCRYPT, true),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_VERIFY, false),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_MODULUS_BITS, ConvertUtils.UInt32FromInt32(options.RsaKeySize)),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PUBLIC_EXPONENT, [0x01, 0x00, 0x01]),
            ];

            List<IObjectAttribute> privateTemplate =
            [
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, true),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, keyLabel),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, keyId),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_UNWRAP, true),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_DECRYPT, true),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_SENSITIVE, true),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_EXTRACTABLE, false),
            ];

            IMechanism mechanism = session.Factories.MechanismFactory.Create(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN);
            session.GenerateKeyPair(mechanism, publicTemplate, privateTemplate, out publicKey, out privateKey);
        }

        private static string CreateKeyId(ISession session, IObjectHandle publicKey)
        {
            List<IObjectAttribute> attributes = session.GetAttributeValue(
                publicKey,
                [CKA.CKA_MODULUS, CKA.CKA_PUBLIC_EXPONENT]);

            byte[] modulus = attributes[0].GetValueAsByteArray()
                ?? throw new CryptographicException("PKCS#11 public key modulus was empty.");
            byte[] exponent = attributes[1].GetValueAsByteArray()
                ?? throw new CryptographicException("PKCS#11 public key exponent was empty.");

            byte[] publicMaterial = new byte[modulus.Length + exponent.Length];
            Buffer.BlockCopy(modulus, 0, publicMaterial, 0, modulus.Length);
            Buffer.BlockCopy(exponent, 0, publicMaterial, modulus.Length, exponent.Length);

            return $"pkcs11:{Convert.ToHexString(SHA256.HashData(publicMaterial)).ToLowerInvariant()}";
        }
    }
}

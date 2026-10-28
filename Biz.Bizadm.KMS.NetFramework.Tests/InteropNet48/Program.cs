using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Azure.Identity;
using Biz.Bizadm.KMS.NetFramework.Cipher;
using Biz.Bizadm.KMS.NetFramework.Cipher.Pkcs11;
using Biz.Bizadm.KMS.NetFramework.Cipher.Tpm;
using Net.Pkcs11Interop.Common;
using Tpm2Lib;

if (args.Length < 1)
{
    PrintUsage();
    return 2;
}

try
{
    return await DispatchAsync(args).ConfigureAwait(false);
}
catch (Exception ex)
{
    Console.Error.WriteLine(ex.GetType().Name + ": " + ex.Message);
    return 1;
}

static async Task<int> DispatchAsync(string[] args)
{
    switch (args[0])
    {
        case "encrypt":
        case "decrypt":
            Require(args, 3);
            return RawAes(args[0], FromHex(args[1]), FromHex(args[2]));
        case "derive-keyid":
            Require(args, 4);
            return DeriveKeyId(FromHex(args[1]), FromHex(args[2]), int.Parse(args[3]));
        case "wrap-dek":
            Require(args, 5);
            return WrapDek(FromHex(args[1]), FromHex(args[2]), int.Parse(args[3]), FromHex(args[4]));
        case "unwrap-dek":
            Require(args, 5);
            return UnwrapDek(FromHex(args[1]), FromHex(args[2]), int.Parse(args[3]), FromHex(args[4]));
        case "rewrap-dek":
            Require(args, 8);
            return RewrapDek(
                FromHex(args[1]), FromHex(args[2]), int.Parse(args[3]),
                FromHex(args[4]), FromHex(args[5]), int.Parse(args[6]),
                FromHex(args[7]));
        case "serialize-envelope":
            Require(args, 3);
            return SerializeEnvelope(args[1], FromHex(args[2]));
        case "parse-envelope":
            Require(args, 2);
            return ParseEnvelope(FromHex(args[1]));
        case "store-cred":
            Require(args, 4);
            return StoreCred(args[1], args[2], FromHex(args[3]), args.Length > 4 ? args[4] : null);
        case "get-cred":
            Require(args, 3);
            return GetCred(args[1], args[2], args.Length > 3 ? args[3] : null);
        case "remove-cred":
            Require(args, 3);
            return RemoveCred(args[1], args[2], args.Length > 3 ? args[3] : null);
        case "azure-wrap":
            Require(args, 3);
            return await AzureWrapAsync(args[1], FromHex(args[2])).ConfigureAwait(false);
        case "azure-unwrap":
            Require(args, 2);
            return await AzureUnwrapAsync(FromHex(args[1])).ConfigureAwait(false);
        case "tpm-wrap":
            Require(args, 4);
            return TpmWrap(args[1], FromHex(args[2]), FromHex(args[3]));
        case "tpm-unwrap":
            Require(args, 4);
            return TpmUnwrap(args[1], FromHex(args[2]), FromHex(args[3]));
        case "pkcs11-wrap":
            Require(args, 3);
            return Pkcs11Wrap(args[1], FromHex(args[2]));
        case "pkcs11-unwrap":
            Require(args, 3);
            return Pkcs11Unwrap(args[1], FromHex(args[2]));
        default:
            PrintUsage();
            return 2;
    }
}

static void PrintUsage()
{
    Console.Error.WriteLine(
        "Usage: InteropNet48 <encrypt|decrypt|derive-keyid|wrap-dek|unwrap-dek|rewrap-dek|serialize-envelope|parse-envelope|store-cred|get-cred|remove-cred|azure-wrap|azure-unwrap|tpm-wrap|tpm-unwrap|pkcs11-wrap|pkcs11-unwrap> ...");
}

static void Require(string[] args, int minLength)
{
    if (args.Length < minLength)
    {
        throw new ArgumentException("Insufficient arguments for " + args[0] + ".");
    }
}

static int RawAes(string operation, byte[] key, byte[] input)
{
    using AesGcmDekCipher cipher = AesGcmDekCipher.Create(key);
    byte[] output = operation switch
    {
        "encrypt" => cipher.Encrypt(input),
        "decrypt" => cipher.Decrypt(input),
        _ => throw new ArgumentException("Unknown operation.")
    };
    Console.Write(ToHex(output));
    Array.Clear(output, 0, output.Length);
    return 0;
}

static int DeriveKeyId(byte[] password, byte[] salt, int iterations)
{
    using AesGcmKekCipher kek = AesGcmKekCipher.Create(new FixedCredentialProvider(password), salt, iterations);
    Console.Write(kek.KeyId);
    return 0;
}

static int WrapDek(byte[] password, byte[] salt, int iterations, byte[] dek)
{
    using AesGcmKekCipher kek = AesGcmKekCipher.Create(new FixedCredentialProvider(password), salt, iterations);
    byte[] envelope = AesGcmDekCipher.CreateEnvelope(kek, dek);
    try
    {
        Console.Write(ToHex(envelope));
        return 0;
    }
    finally
    {
        Array.Clear(envelope, 0, envelope.Length);
    }
}

static int UnwrapDek(byte[] password, byte[] salt, int iterations, byte[] envelopeBytes)
{
    using AesGcmKekCipher kek = AesGcmKekCipher.Create(new FixedCredentialProvider(password), salt, iterations);
    WrappedDekEnvelope envelope = WrappedDekEnvelope.Deserialize(envelopeBytes);
    if (!string.Equals(envelope.KeyId, kek.KeyId, StringComparison.Ordinal))
    {
        throw new InvalidDataException("KDEK KeyId does not match the supplied KEK.");
    }

    byte[] dek = kek.Decrypt(envelope.WrappedKey);
    try
    {
        Console.Write(ToHex(dek));
        return 0;
    }
    finally
    {
        Array.Clear(dek, 0, dek.Length);
    }
}

static int RewrapDek(
    byte[] oldPassword, byte[] oldSalt, int oldIterations,
    byte[] newPassword, byte[] newSalt, int newIterations,
    byte[] envelopeBytes)
{
    using AesGcmKekCipher source = AesGcmKekCipher.Create(new FixedCredentialProvider(oldPassword), oldSalt, oldIterations);
    using AesGcmKekCipher target = AesGcmKekCipher.Create(new FixedCredentialProvider(newPassword), newSalt, newIterations);
    byte[] rewrapped = AesGcmDekCipher.RewrapEnvelope(source, target, envelopeBytes);
    try
    {
        Console.Write(ToHex(rewrapped));
        return 0;
    }
    finally
    {
        Array.Clear(rewrapped, 0, rewrapped.Length);
    }
}

static int SerializeEnvelope(string keyId, byte[] wrapped)
{
    Console.Write(ToHex(new WrappedDekEnvelope(keyId, wrapped).Serialize()));
    return 0;
}

static int ParseEnvelope(byte[] envelopeBytes)
{
    WrappedDekEnvelope envelope = WrappedDekEnvelope.Deserialize(envelopeBytes);
    Console.Write(envelope.KeyId + "\n" + ToHex(envelope.WrappedKey));
    return 0;
}

static int StoreCred(string service, string account, byte[] password, string? @namespace)
{
    IWindowsKekCredentialStore store = WindowsCredentialManagerKekCredentialProvider.Create(service, account, @namespace);
    store.StorePassword(password);
    return 0;
}

static int GetCred(string service, string account, string? @namespace)
{
    IWindowsKekCredentialStore store = WindowsCredentialManagerKekCredentialProvider.Create(service, account, @namespace);
    byte[] password = store.GetPassword();
    try
    {
        Console.Write(ToHex(password));
        return 0;
    }
    finally
    {
        Array.Clear(password, 0, password.Length);
    }
}

static int RemoveCred(string service, string account, string? @namespace)
{
    IWindowsKekCredentialStore store = WindowsCredentialManagerKekCredentialProvider.Create(service, account, @namespace);
    store.RemovePassword();
    return 0;
}

static async Task<int> AzureWrapAsync(string keyName, byte[] dek)
{
    using AzureKeyVaultKekCipher kek = await CreateAzureCipherAsync(keyName, version: null).ConfigureAwait(false);
    byte[] envelope = AesGcmDekCipher.CreateEnvelope(kek, dek);
    try
    {
        Console.Write(ToHex(envelope));
        return 0;
    }
    finally
    {
        Array.Clear(envelope, 0, envelope.Length);
    }
}

static async Task<int> AzureUnwrapAsync(byte[] envelopeBytes)
{
    WrappedDekEnvelope envelope = WrappedDekEnvelope.Deserialize(envelopeBytes);
    ParseAzureKeyId(envelope.KeyId, out string keyName, out string version);
    using AzureKeyVaultKekCipher kek = await CreateAzureCipherAsync(keyName, version).ConfigureAwait(false);
    if (!string.Equals(envelope.KeyId, kek.KeyId, StringComparison.Ordinal))
    {
        throw new InvalidDataException("KDEK KeyId does not match the Azure KEK.");
    }

    byte[] dek = await kek.DecryptAsync(envelope.WrappedKey).ConfigureAwait(false);
    try
    {
        Console.Write(ToHex(dek));
        return 0;
    }
    finally
    {
        Array.Clear(dek, 0, dek.Length);
    }
}

static int TpmWrap(string blobPath, byte[] password, byte[] dek)
{
    using TbsDevice device = OpenTbs();
    using TpmKekCipher kek = TpmKekCipher.Create(device, new FixedCredentialProvider(password), new FileInfo(blobPath));
    byte[] envelope = AesGcmDekCipher.CreateEnvelope(kek, dek);
    try
    {
        Console.Write(ToHex(envelope));
        return 0;
    }
    finally
    {
        Array.Clear(envelope, 0, envelope.Length);
    }
}

static int TpmUnwrap(string blobPath, byte[] password, byte[] envelopeBytes)
{
    using TbsDevice device = OpenTbs();
    using TpmKekCipher kek = TpmKekCipher.Create(device, new FixedCredentialProvider(password), new FileInfo(blobPath));
    WrappedDekEnvelope envelope = WrappedDekEnvelope.Deserialize(envelopeBytes);
    if (!string.Equals(envelope.KeyId, kek.KeyId, StringComparison.Ordinal))
    {
        throw new InvalidDataException("KDEK KeyId does not match the TPM KEK.");
    }

    byte[] dek = kek.Decrypt(envelope.WrappedKey);
    try
    {
        Console.Write(ToHex(dek));
        return 0;
    }
    finally
    {
        Array.Clear(dek, 0, dek.Length);
    }
}

static int Pkcs11Wrap(string label, byte[] dek)
{
    using Pkcs11LibraryContext context = CreatePkcs11Context();
    using Pkcs11KekCipher kek = Pkcs11KekCipher.Create(context, label, createIfMissing: true, SoftHsmOptions());
    byte[] envelope = AesGcmDekCipher.CreateEnvelope(kek, dek);
    try
    {
        Console.Write(ToHex(envelope));
        return 0;
    }
    finally
    {
        Array.Clear(envelope, 0, envelope.Length);
    }
}

static int Pkcs11Unwrap(string label, byte[] envelopeBytes)
{
    using Pkcs11LibraryContext context = CreatePkcs11Context();
    using Pkcs11KekCipher kek = Pkcs11KekCipher.Create(context, label, createIfMissing: false, SoftHsmOptions());
    WrappedDekEnvelope envelope = WrappedDekEnvelope.Deserialize(envelopeBytes);
    if (!string.Equals(envelope.KeyId, kek.KeyId, StringComparison.Ordinal))
    {
        throw new InvalidDataException("KDEK KeyId does not match the PKCS#11 KEK.");
    }

    byte[] dek = kek.Decrypt(envelope.WrappedKey);
    try
    {
        Console.Write(ToHex(dek));
        return 0;
    }
    finally
    {
        Array.Clear(dek, 0, dek.Length);
    }
}

static async Task<AzureKeyVaultKekCipher> CreateAzureCipherAsync(string keyName, string? version)
{
    string? url = Environment.GetEnvironmentVariable("AZURE_KEY_VAULT_URL");
    string? tenantId = Environment.GetEnvironmentVariable("AZURE_TENANTID");
    string? clientId = Environment.GetEnvironmentVariable("AZURE_CLIENT_ID");
    string? thumbprint = Environment.GetEnvironmentVariable("AZURE_KEY_VAULT_THUMBPRINT");
    if (string.IsNullOrWhiteSpace(url) ||
        string.IsNullOrWhiteSpace(tenantId) ||
        string.IsNullOrWhiteSpace(clientId) ||
        string.IsNullOrWhiteSpace(thumbprint))
    {
        throw new InvalidOperationException("Azure Key Vault environment variables are not configured.");
    }

    using X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
    store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
    X509Certificate2Collection certificates = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false);
    X509Certificate2? certificate = certificates.OfType<X509Certificate2>().FirstOrDefault(x => x.HasPrivateKey);
    if (certificate is null)
    {
        throw new InvalidOperationException("No private-key certificate matching AZURE_KEY_VAULT_THUMBPRINT was found.");
    }

    ClientCertificateCredential credential = new ClientCertificateCredential(tenantId, clientId, certificate);
    return await AzureKeyVaultKekCipher.CreateAsync(new Uri(url), credential, keyName, version).ConfigureAwait(false);
}

static void ParseAzureKeyId(string keyId, out string keyName, out string version)
{
    string[] parts = keyId.Split(':');
    if (parts.Length != 3 || !string.Equals(parts[0], "azurekv", StringComparison.Ordinal))
    {
        throw new InvalidDataException("Invalid Azure KeyId: " + keyId);
    }

    keyName = parts[1];
    version = parts[2];
}

static TbsDevice OpenTbs()
{
    TbsDevice device = new TbsDevice();
    device.Connect();
    return device;
}

static Pkcs11LibraryContext CreatePkcs11Context()
{
    string? libraryPath = Environment.GetEnvironmentVariable("PKCS11_LIBRARY_PATH");
    string? slotText = Environment.GetEnvironmentVariable("PKCS11_SLOT_ID");
    string? pin = Environment.GetEnvironmentVariable("PKCS11_PIN");
    if (string.IsNullOrWhiteSpace(libraryPath) ||
        string.IsNullOrWhiteSpace(slotText) ||
        string.IsNullOrWhiteSpace(pin) ||
        !ulong.TryParse(slotText, out ulong slotId))
    {
        throw new InvalidOperationException("PKCS#11 SoftHSM environment variables are not configured.");
    }

    return Pkcs11LibraryContext.Create(libraryPath, slotId, new FixedCredentialProvider(Encoding.UTF8.GetBytes(pin)));
}

static Pkcs11KekOptions SoftHsmOptions()
{
    return new Pkcs11KekOptions
    {
        RsaKeySize = 2048,
        WrapMechanism = CKM.CKM_RSA_PKCS
    };
}

static byte[] FromHex(string value)
{
    if (string.IsNullOrEmpty(value))
    {
        return Array.Empty<byte>();
    }

    byte[] result = new byte[value.Length / 2];
    for (int i = 0; i < result.Length; i++)
    {
        result[i] = byte.Parse(value.Substring(i * 2, 2), System.Globalization.NumberStyles.HexNumber);
    }

    return result;
}

static string ToHex(byte[] value)
    => BitConverter.ToString(value).Replace("-", string.Empty);

internal sealed class FixedCredentialProvider : IKekCredentialProvider
{
    private readonly byte[] password;

    public FixedCredentialProvider(byte[] password)
    {
        this.password = (byte[])password.Clone();
    }

    public byte[] GetPassword() => (byte[])password.Clone();

    public Task<byte[]> GetPasswordAsync(CancellationToken cancellationToken = default)
        => Task.FromResult(GetPassword());
}

using Tpm2Lib;

namespace Biz.Bizadm.KMS.NetFramework.Cipher.Tpm;

/// <summary>
/// Manages TPM KEK versions for the independent net48 implementation.
/// </summary>
public sealed class TpmKekManager : IDisposable
{
    private readonly object sync = new object();
    private readonly Dictionary<string, TpmKekCipher> registry = new Dictionary<string, TpmKekCipher>(StringComparer.Ordinal);
    private readonly Tpm2Device device;
    private readonly IKekCredentialProvider credentialProvider;
    private TpmKekCipher current;
    private bool disposed;

    private TpmKekManager(Tpm2Device device, IKekCredentialProvider credentialProvider, TpmKekCipher initial)
    {
        this.device = device;
        this.credentialProvider = credentialProvider;
        current = initial;
        registry.Add(initial.KeyId, initial);
    }

    public static TpmKekManager Create(
        Tpm2Device device,
        IKekCredentialProvider credentialProvider,
        FileInfo kekBlobFile,
        TpmKekOptions? options = null)
    {
        TpmKekCipher cipher = TpmKekCipher.Create(device, credentialProvider, kekBlobFile, options);
        return new TpmKekManager(device, credentialProvider, cipher);
    }

    public TpmKekCipher Current
    {
        get
        {
            lock (sync)
            {
                ThrowIfDisposed();
                return current;
            }
        }
    }

    public IReadOnlyCollection<string> KnownKeyIds
    {
        get
        {
            lock (sync)
            {
                ThrowIfDisposed();
                return registry.Keys.ToArray();
            }
        }
    }

    public TpmKekCipher Resolve(string keyId)
    {
        if (string.IsNullOrEmpty(keyId)) throw new ArgumentException("A KeyId is required.", nameof(keyId));
        lock (sync)
        {
            ThrowIfDisposed();
            if (!registry.TryGetValue(keyId, out TpmKekCipher? cipher))
                throw new KeyNotFoundException("No KEK is registered for the requested KeyId.");
            return cipher;
        }
    }

    public TpmKekCipher Rotate(FileInfo newKekBlobFile, TpmKekOptions? options = null)
    {
        TpmKekCipher rotated;
        lock (sync)
        {
            ThrowIfDisposed();
            rotated = current.Rotate(newKekBlobFile, options);
            if (registry.ContainsKey(rotated.KeyId))
            {
                rotated.Dispose();
                throw new InvalidOperationException("A KEK with this KeyId is already registered.");
            }

            registry.Add(rotated.KeyId, rotated);
            current = rotated;
            return rotated;
        }
    }

    public TpmKekCipher LoadKey(FileInfo kekBlobFile, TpmKekOptions? options = null)
    {
        if (kekBlobFile is null) throw new ArgumentNullException(nameof(kekBlobFile));
        kekBlobFile.Refresh();
        if (!kekBlobFile.Exists)
            throw new FileNotFoundException("KEK blob file was not found.", kekBlobFile.FullName);

        TpmKekCipher cipher = TpmKekCipher.Create(device, credentialProvider, kekBlobFile, options);
        lock (sync)
        {
            try
            {
                ThrowIfDisposed();
                if (registry.ContainsKey(cipher.KeyId))
                    throw new InvalidOperationException("A KEK with this KeyId is already registered.");
                registry.Add(cipher.KeyId, cipher);
                return cipher;
            }
            catch
            {
                cipher.Dispose();
                throw;
            }
        }
    }

    public void Dispose()
    {
        if (disposed) return;
        lock (sync)
        {
            if (disposed) return;
            foreach (TpmKekCipher cipher in registry.Values)
                cipher.Dispose();
            registry.Clear();
            disposed = true;
        }
    }

    private void ThrowIfDisposed()
    {
        if (disposed) throw new ObjectDisposedException(nameof(TpmKekManager));
    }
}

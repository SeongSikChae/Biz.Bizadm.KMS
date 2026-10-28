namespace Biz.Bizadm.KMS.NetFramework.Cipher.Pkcs11;

/// <summary>
/// Manages PKCS#11 KEK labels for the independent net48 implementation.
/// </summary>
public sealed class Pkcs11KekManager : IDisposable
{
    private readonly object sync = new object();
    private readonly Dictionary<string, Pkcs11KekCipher> registry =
        new Dictionary<string, Pkcs11KekCipher>(StringComparer.Ordinal);
    private readonly Pkcs11LibraryContext context;
    private readonly bool ownsContext;
    private Pkcs11KekCipher current;
    private bool disposed;

    private Pkcs11KekManager(Pkcs11LibraryContext context, bool ownsContext, Pkcs11KekCipher initial)
    {
        this.context = context;
        this.ownsContext = ownsContext;
        current = initial;
        registry.Add(initial.KeyId, initial);
    }

    public static Pkcs11KekManager Create(
        Pkcs11LibraryContext context,
        string keyLabel,
        bool createIfMissing = true,
        Pkcs11KekOptions? options = null,
        bool ownsContext = false)
    {
        Pkcs11KekCipher cipher = Pkcs11KekCipher.Create(context, keyLabel, createIfMissing, options);
        return new Pkcs11KekManager(context, ownsContext, cipher);
    }

    public Pkcs11KekCipher Current
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

    public Pkcs11KekCipher Resolve(string keyId)
    {
        if (string.IsNullOrEmpty(keyId)) throw new ArgumentException("A KeyId is required.", nameof(keyId));
        lock (sync)
        {
            ThrowIfDisposed();
            if (!registry.TryGetValue(keyId, out Pkcs11KekCipher? cipher))
                throw new KeyNotFoundException("No KEK is registered for the requested KeyId.");
            return cipher;
        }
    }

    public Pkcs11KekCipher Rotate(string newKeyLabel, Pkcs11KekOptions? options = null)
    {
        Pkcs11KekCipher rotated = current.Rotate(newKeyLabel, options);
        lock (sync)
        {
            try
            {
                ThrowIfDisposed();
                if (registry.ContainsKey(rotated.KeyId))
                    throw new InvalidOperationException("A KEK with this KeyId is already registered.");
                registry.Add(rotated.KeyId, rotated);
                current = rotated;
                return rotated;
            }
            catch
            {
                rotated.Dispose();
                throw;
            }
        }
    }

    public Pkcs11KekCipher LoadKey(string keyLabel, Pkcs11KekOptions? options = null)
    {
        Pkcs11KekCipher cipher = Pkcs11KekCipher.Create(context, keyLabel, createIfMissing: false, options);
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
            foreach (Pkcs11KekCipher cipher in registry.Values)
                cipher.Dispose();
            registry.Clear();
            if (ownsContext)
                context.Dispose();
            disposed = true;
        }
    }

    private void ThrowIfDisposed()
    {
        if (disposed) throw new ObjectDisposedException(nameof(Pkcs11KekManager));
    }
}

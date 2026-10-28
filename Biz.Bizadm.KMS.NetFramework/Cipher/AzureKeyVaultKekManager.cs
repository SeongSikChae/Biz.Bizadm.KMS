using Azure.Core;

namespace Biz.Bizadm.KMS.NetFramework.Cipher;

/// <summary>
/// Manages Azure Key Vault KEK versions for the independent net48 implementation.
/// </summary>
public sealed class AzureKeyVaultKekManager : IDisposable
{
    private readonly object sync = new object();
    private readonly SemaphoreSlim asyncOperationGate = new SemaphoreSlim(1, 1);
    private readonly Dictionary<string, AzureKeyVaultKekCipher> registry =
        new Dictionary<string, AzureKeyVaultKekCipher>(StringComparer.Ordinal);
    private readonly Uri vaultUri;
    private readonly TokenCredential credential;
    private readonly string keyName;
    private AzureKeyVaultKekCipher current;
    private bool disposed;

    private AzureKeyVaultKekManager(
        Uri vaultUri,
        TokenCredential credential,
        string keyName,
        AzureKeyVaultKekCipher initial)
    {
        this.vaultUri = vaultUri;
        this.credential = credential;
        this.keyName = keyName;
        current = initial;
        registry.Add(initial.KeyId, initial);
    }

    public static async Task<AzureKeyVaultKekManager> CreateAsync(
        Uri uri,
        TokenCredential credential,
        string name,
        string? version = null,
        CancellationToken cancellationToken = default)
    {
        AzureKeyVaultKekCipher cipher = await AzureKeyVaultKekCipher
            .CreateAsync(uri, credential, name, version, cancellationToken)
            .ConfigureAwait(false);
        return new AzureKeyVaultKekManager(uri, credential, name, cipher);
    }

    public AzureKeyVaultKekCipher Current
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

    public AzureKeyVaultKekCipher Resolve(string keyId)
    {
        if (string.IsNullOrEmpty(keyId)) throw new ArgumentException("A KeyId is required.", nameof(keyId));
        lock (sync)
        {
            ThrowIfDisposed();
            if (!registry.TryGetValue(keyId, out AzureKeyVaultKekCipher? cipher))
                throw new KeyNotFoundException("No KEK is registered for the requested KeyId.");
            return cipher;
        }
    }

    public async Task<AzureKeyVaultKekCipher> RotateAsync(CancellationToken cancellationToken = default)
    {
        await asyncOperationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            AzureKeyVaultKekCipher source;
            lock (sync)
            {
                ThrowIfDisposed();
                source = current;
            }

            AzureKeyVaultKekCipher rotated = await source.RotateAsync(cancellationToken).ConfigureAwait(false);
            lock (sync)
            {
                ThrowIfDisposed();
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
        finally
        {
            asyncOperationGate.Release();
        }
    }

    public async Task<AzureKeyVaultKekCipher> LoadKeyAsync(string version, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(version)) throw new ArgumentException("A key version is required.", nameof(version));
        AzureKeyVaultKekCipher cipher = await AzureKeyVaultKekCipher
            .CreateAsync(vaultUri, credential, keyName, version, cancellationToken)
            .ConfigureAwait(false);

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

    public byte[] RewrapDek(byte[] envelopeBytes)
    {
        if (envelopeBytes is null) throw new ArgumentNullException(nameof(envelopeBytes));
        WrappedDekEnvelope envelope = WrappedDekEnvelope.Deserialize(envelopeBytes);
        asyncOperationGate.Wait();
        try
        {
            AzureKeyVaultKekCipher source;
            AzureKeyVaultKekCipher target;
            lock (sync)
            {
                ThrowIfDisposed();
                if (!registry.TryGetValue(envelope.KeyId, out source!))
                    throw new KeyNotFoundException("The envelope KeyId is not registered.");
                target = current;
            }

            byte[] rewrapped = target.RewrapDek(source, envelope.WrappedKey);
            return new WrappedDekEnvelope(target.KeyId, rewrapped).Serialize();
        }
        finally
        {
            asyncOperationGate.Release();
        }
    }

    public void Dispose()
    {
        if (disposed) return;
        asyncOperationGate.Wait();
        try
        {
            lock (sync)
            {
                if (disposed) return;
                foreach (AzureKeyVaultKekCipher cipher in registry.Values)
                    cipher.Dispose();
                registry.Clear();
                disposed = true;
            }
        }
        finally
        {
            asyncOperationGate.Release();
            asyncOperationGate.Dispose();
        }
    }

    private void ThrowIfDisposed()
    {
        if (disposed) throw new ObjectDisposedException(nameof(AzureKeyVaultKekManager));
    }
}

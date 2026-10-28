namespace Biz.Bizadm.KMS.NetFramework.Cipher;

/// <summary>
/// Manages the current software KEK and retained historical KEKs.
/// </summary>
public sealed class AesGcmKekManager : IDisposable
{
    private readonly object sync = new object();
    private readonly SemaphoreSlim asyncOperationGate = new SemaphoreSlim(1, 1);
    private readonly Dictionary<string, AesGcmKekCipher> registry = new Dictionary<string, AesGcmKekCipher>(StringComparer.Ordinal);
    private AesGcmKekCipher current;
    private bool disposed;

    private AesGcmKekManager(AesGcmKekCipher initial)
    {
        current = initial;
        registry.Add(initial.KeyId, initial);
    }

    public static AesGcmKekManager Create(IKekCredentialProvider credentialProvider, byte[] salt, int iterationCount)
        => new AesGcmKekManager(AesGcmKekCipher.Create(credentialProvider, salt, iterationCount));

    public static async Task<AesGcmKekManager> CreateAsync(
        IKekCredentialProvider credentialProvider,
        byte[] salt,
        int iterationCount,
        CancellationToken cancellationToken = default)
        => new AesGcmKekManager(await AesGcmKekCipher.CreateAsync(credentialProvider, salt, iterationCount, cancellationToken).ConfigureAwait(false));

    public AesGcmKekCipher Current
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

    public AesGcmKekCipher Resolve(string keyId)
    {
        if (string.IsNullOrEmpty(keyId)) throw new ArgumentException("A KeyId is required.", nameof(keyId));
        lock (sync)
        {
            ThrowIfDisposed();
            if (!registry.TryGetValue(keyId, out AesGcmKekCipher? cipher))
                throw new KeyNotFoundException("No KEK is registered for the requested KeyId.");
            return cipher;
        }
    }

    public AesGcmKekCipher LoadKey(IKekCredentialProvider credentialProvider, byte[] salt, int iterationCount)
    {
        AesGcmKekCipher cipher = AesGcmKekCipher.Create(credentialProvider, salt, iterationCount);
        lock (sync)
        {
            try
            {
                ThrowIfDisposed();
                if (registry.ContainsKey(cipher.KeyId)) throw new InvalidOperationException("A KEK with this KeyId is already registered.");
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

    public AesGcmKekCipher Rotate(IKekCredentialProvider credentialProvider, byte[] salt, int iterationCount)
    {
        AesGcmKekCipher next = AesGcmKekCipher.Create(credentialProvider, salt, iterationCount);
        lock (sync)
        {
            try
            {
                ThrowIfDisposed();
                if (registry.ContainsKey(next.KeyId)) throw new InvalidOperationException("A KEK with this KeyId is already registered.");
                registry.Add(next.KeyId, next);
                current = next;
                return next;
            }
            catch
            {
                next.Dispose();
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
            AesGcmKekCipher source;
            AesGcmKekCipher target;
            lock (sync)
            {
                ThrowIfDisposed();
                if (!registry.TryGetValue(envelope.KeyId, out source!)) throw new KeyNotFoundException("The envelope KeyId is not registered.");
                target = current;
            }
            byte[] rewrapped = target.RewrapDek(source, envelope.WrappedKey);
            try
            {
                return new WrappedDekEnvelope(target.KeyId, rewrapped).Serialize();
            }
            finally
            {
                Array.Clear(rewrapped, 0, rewrapped.Length);
            }
        }
        finally
        {
            asyncOperationGate.Release();
        }
    }

    public async Task<byte[]> RewrapDekAsync(byte[] envelopeBytes, CancellationToken cancellationToken = default)
    {
        if (envelopeBytes is null) throw new ArgumentNullException(nameof(envelopeBytes));
        WrappedDekEnvelope envelope = WrappedDekEnvelope.Deserialize(envelopeBytes);
        await asyncOperationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            AesGcmKekCipher source;
            AesGcmKekCipher target;
            lock (sync)
            {
                ThrowIfDisposed();
                if (!registry.TryGetValue(envelope.KeyId, out source!)) throw new KeyNotFoundException("The envelope KeyId is not registered.");
                target = current;
            }
            byte[] rewrapped = await target.RewrapDekAsync(source, envelope.WrappedKey, cancellationToken).ConfigureAwait(false);
            try
            {
                return new WrappedDekEnvelope(target.KeyId, rewrapped).Serialize();
            }
            finally
            {
                Array.Clear(rewrapped, 0, rewrapped.Length);
            }
        }
        finally
        {
            asyncOperationGate.Release();
        }
    }

    public void RewrapDekFile(string path)
    {
        byte[] original = DekEnvelopeStorage.ReadAllBytes(path);
        byte[] rewrapped = RewrapDek(original);
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

    public async Task RewrapDekFileAsync(string path, CancellationToken cancellationToken = default)
    {
        byte[] original = await DekEnvelopeStorage.ReadAllBytesAsync(path, cancellationToken).ConfigureAwait(false);
        byte[] rewrapped = await RewrapDekAsync(original, cancellationToken).ConfigureAwait(false);
        try
        {
            await DekEnvelopeStorage.ReplaceAtomicallyAsync(path, rewrapped, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            Array.Clear(original, 0, original.Length);
            Array.Clear(rewrapped, 0, rewrapped.Length);
        }
    }

    public void Release(string keyId)
    {
        if (string.IsNullOrEmpty(keyId)) throw new ArgumentException("A KeyId is required.", nameof(keyId));
        AesGcmKekCipher removed;
        lock (sync)
        {
            ThrowIfDisposed();
            if (!registry.TryGetValue(keyId, out removed!)) throw new KeyNotFoundException("No KEK is registered for the requested KeyId.");
            if (ReferenceEquals(removed, current)) throw new InvalidOperationException("Cannot release the current KEK.");
            registry.Remove(keyId);
        }
        removed.Dispose();
    }

    private void ThrowIfDisposed()
    {
        if (disposed) throw new ObjectDisposedException(nameof(AesGcmKekManager));
    }

    public void Dispose()
    {
        asyncOperationGate.Wait();
        try
        {
            AesGcmKekCipher[] ciphers;
            lock (sync)
            {
                if (disposed) return;
                disposed = true;
                ciphers = registry.Values.Distinct().ToArray();
                registry.Clear();
            }
            foreach (AesGcmKekCipher cipher in ciphers) cipher.Dispose();
        }
        finally
        {
            asyncOperationGate.Release();
        }
        GC.SuppressFinalize(this);
    }
}

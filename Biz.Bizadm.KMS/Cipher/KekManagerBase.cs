using System.Collections.ObjectModel;

namespace Biz.Bizadm.KMS.Cipher
{
    /// <summary>
    /// <see cref="IKekManager"/> 공통 구현 베이스.
    /// </summary>
    public abstract class KekManagerBase : IKekManager
    {
        private readonly Dictionary<string, IKekCipher> registry = new(StringComparer.Ordinal);
        private bool disposedValue;

        /// <inheritdoc />
        public IKekCipher Current { get; private set; }

        /// <inheritdoc />
        public IReadOnlyCollection<string> KnownKeyIds => new ReadOnlyCollection<string>(registry.Keys.ToList());

        /// <summary>
        /// 초기 KEK로 Manager를 초기화한다.
        /// </summary>
        /// <param name="initial">최초 Current KEK.</param>
        protected KekManagerBase(IKekCipher initial)
        {
            ArgumentNullException.ThrowIfNull(initial);
            Current = initial;
            Register(initial);
        }

        /// <summary>
        /// KEK를 레지스트리에 등록한다.
        /// </summary>
        /// <param name="cipher">등록할 KEK.</param>
        protected void Register(IKekCipher cipher)
        {
            ObjectDisposedException.ThrowIf(disposedValue, this);
            ArgumentNullException.ThrowIfNull(cipher);
            registry[cipher.KeyId] = cipher;
        }

        /// <summary>
        /// Current KEK를 교체한다.
        /// </summary>
        /// <param name="cipher">새 Current KEK.</param>
        protected void SetCurrent(IKekCipher cipher)
        {
            ObjectDisposedException.ThrowIf(disposedValue, this);
            ArgumentNullException.ThrowIfNull(cipher);
            Register(cipher);
            Current = cipher;
        }

        /// <inheritdoc />
        public IKekCipher Resolve(string keyId)
        {
            ObjectDisposedException.ThrowIf(disposedValue, this);
            ArgumentException.ThrowIfNullOrEmpty(keyId);

            if (!registry.TryGetValue(keyId, out IKekCipher? cipher) || cipher is null)
                throw new KeyNotFoundException($"KEK with KeyId '{keyId}' is not registered.");

            return cipher;
        }

        /// <inheritdoc />
        public byte[] RewrapDek(byte[] envelope)
        {
            ObjectDisposedException.ThrowIf(disposedValue, this);
            ArgumentNullException.ThrowIfNull(envelope);

            WrappedDekEnvelope parsed = WrappedDekEnvelope.Deserialize(envelope);
            IKekCipher source = Resolve(parsed.KeyId);
            byte[] rewrapped = Current.RewrapDek(source, parsed.WrappedKey);
            return new WrappedDekEnvelope(Current.KeyId, rewrapped).Serialize();
        }

        /// <inheritdoc />
        public async Task<byte[]> RewrapDekAsync(byte[] envelope, CancellationToken cancellationToken = default)
        {
            ObjectDisposedException.ThrowIf(disposedValue, this);
            ArgumentNullException.ThrowIfNull(envelope);

            WrappedDekEnvelope parsed = WrappedDekEnvelope.Deserialize(envelope);
            IKekCipher source = Resolve(parsed.KeyId);
            byte[] rewrapped = await Current.RewrapDekAsync(source, parsed.WrappedKey, cancellationToken)
                .ConfigureAwait(false);
            return new WrappedDekEnvelope(Current.KeyId, rewrapped).Serialize();
        }

        /// <inheritdoc />
        public void RewrapDekFile(FileInfo dekFile)
        {
            ObjectDisposedException.ThrowIf(disposedValue, this);
            ArgumentNullException.ThrowIfNull(dekFile);

            byte[] envelope = File.ReadAllBytes(dekFile.FullName);
            byte[] rewrapped = RewrapDek(envelope);
            AesGcmDekCipher.WriteAllBytesAtomic(dekFile.FullName, rewrapped);
        }

        /// <inheritdoc />
        public async Task RewrapDekFileAsync(FileInfo dekFile, CancellationToken cancellationToken = default)
        {
            ObjectDisposedException.ThrowIf(disposedValue, this);
            ArgumentNullException.ThrowIfNull(dekFile);

            byte[] envelope = await File.ReadAllBytesAsync(dekFile.FullName, cancellationToken).ConfigureAwait(false);
            byte[] rewrapped = await RewrapDekAsync(envelope, cancellationToken).ConfigureAwait(false);
            AesGcmDekCipher.WriteAllBytesAtomic(dekFile.FullName, rewrapped);
        }

        /// <inheritdoc />
        public void Release(string keyId)
        {
            ObjectDisposedException.ThrowIf(disposedValue, this);
            ArgumentException.ThrowIfNullOrEmpty(keyId);

            if (!registry.TryGetValue(keyId, out IKekCipher? cipher) || cipher is null)
                throw new KeyNotFoundException($"KEK with KeyId '{keyId}' is not registered.");

            if (ReferenceEquals(cipher, Current))
                throw new InvalidOperationException("Cannot release the current KEK.");

            registry.Remove(keyId);
            cipher.Dispose();
        }

        /// <inheritdoc />
        public void Dispose()
        {
            if (disposedValue)
                return;

            disposedValue = true;
            foreach (IKekCipher cipher in registry.Values)
                cipher.Dispose();

            registry.Clear();
            GC.SuppressFinalize(this);
        }
    }
}

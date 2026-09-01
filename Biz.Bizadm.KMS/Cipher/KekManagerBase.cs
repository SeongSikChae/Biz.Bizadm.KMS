using System.Collections.ObjectModel;

namespace Biz.Bizadm.KMS.Cipher
{
    /// <summary>
    /// <see cref="IKekManager"/> 공통 구현 베이스.
    /// </summary>
    public abstract class KekManagerBase : IKekManager
    {
        private readonly Dictionary<string, IKekCipher> registry = new(StringComparer.Ordinal);
        private readonly Lock sync = new();
        private bool disposedValue;

        /// <summary>
        /// Manager가 dispose되었는지 여부.
        /// </summary>
        protected bool IsDisposed => disposedValue;

        /// <inheritdoc />
        /// <remarks>내부에서 Current KEK를 읽거나 바꿀 때는 <see cref="CurrentUnsafe"/>를 사용한다.</remarks>
        public IKekCipher Current
        {
            get
            {
                lock (sync)
                {
                    ObjectDisposedException.ThrowIf(disposedValue, this);
                    return CurrentUnsafe;
                }
            }
        }

        /// <summary>
        /// Current KEK의 내부 저장소. <see cref="sync"/>를 잡은 상태에서만 읽기·쓰기한다.
        /// </summary>
        /// <remarks>
        /// public <see cref="Current"/>는 동일 lock을 다시 잡지만, lock 보호 구간 안에서는
        /// 이 필드에 직접 접근한다. 이름의 Unsafe는 C# unsafe 키워드가 아니라
        /// "락 없이 접근하면 스레드 안전하지 않다"는 계약을 나타낸다.
        /// </remarks>
        private IKekCipher CurrentUnsafe { get; set; }

        /// <inheritdoc />
        public IReadOnlyCollection<string> KnownKeyIds
        {
            get
            {
                lock (sync)
                {
                    ObjectDisposedException.ThrowIf(disposedValue, this);
                    return new ReadOnlyCollection<string>(registry.Keys.ToList());
                }
            }
        }

        /// <summary>
        /// 초기 KEK로 Manager를 초기화한다.
        /// </summary>
        /// <param name="initial">최초 Current KEK.</param>
        protected KekManagerBase(IKekCipher initial)
        {
            ArgumentNullException.ThrowIfNull(initial);
            lock (sync)
            {
                CurrentUnsafe = initial;
                registry[initial.KeyId] = initial;
            }
        }

        /// <summary>
        /// KEK를 레지스트리에 등록한다. <see cref="IKekManager.Current"/>는 바꾸지 않는다.
        /// </summary>
        /// <param name="cipher">등록할 KEK.</param>
        /// <exception cref="InvalidOperationException">동일 KeyId가 이미 등록된 경우.</exception>
        protected void Register(IKekCipher cipher)
        {
            ArgumentNullException.ThrowIfNull(cipher);
            try
            {
                lock (sync)
                {
                    ObjectDisposedException.ThrowIf(disposedValue, this);

                    if (registry.ContainsKey(cipher.KeyId))
                        throw new InvalidOperationException($"KEK with KeyId '{cipher.KeyId}' is already registered.");

                    registry[cipher.KeyId] = cipher;
                }
            }
            catch
            {
                cipher.Dispose();
                throw;
            }
        }

        /// <summary>
        /// Current KEK를 교체한다. 동일 KeyId가 이미 registry에 있으면 거부한다.
        /// </summary>
        /// <param name="cipher">새 Current KEK.</param>
        /// <exception cref="InvalidOperationException">동일 KeyId가 이미 등록된 경우.</exception>
        protected void SetCurrent(IKekCipher cipher)
        {
            ArgumentNullException.ThrowIfNull(cipher);
            try
            {
                lock (sync)
                {
                    ObjectDisposedException.ThrowIf(disposedValue, this);

                    if (registry.TryGetValue(cipher.KeyId, out IKekCipher? existing)
                        && !ReferenceEquals(existing, cipher))
                    {
                        throw new InvalidOperationException($"KEK with KeyId '{cipher.KeyId}' is already registered.");
                    }

                    registry[cipher.KeyId] = cipher;
                    CurrentUnsafe = cipher;
                }
            }
            catch
            {
                cipher.Dispose();
                throw;
            }
        }

        /// <inheritdoc />
        public IKekCipher Resolve(string keyId)
        {
            ArgumentException.ThrowIfNullOrEmpty(keyId);
            lock (sync)
            {
                ObjectDisposedException.ThrowIf(disposedValue, this);

                if (!registry.TryGetValue(keyId, out IKekCipher? cipher) || cipher is null)
                    throw new KeyNotFoundException($"KEK with KeyId '{keyId}' is not registered.");

                return cipher;
            }
        }

        /// <inheritdoc />
        public byte[] RewrapDek(byte[] envelope)
        {
            ArgumentNullException.ThrowIfNull(envelope);

            WrappedDekEnvelope parsed = WrappedDekEnvelope.Deserialize(envelope);
            lock (sync)
            {
                ObjectDisposedException.ThrowIf(disposedValue, this);

                if (!registry.TryGetValue(parsed.KeyId, out IKekCipher? source) || source is null)
                    throw new KeyNotFoundException($"KEK with KeyId '{parsed.KeyId}' is not registered.");

                IKekCipher current = CurrentUnsafe;
                byte[] rewrapped = current.RewrapDek(source, parsed.WrappedKey);
                return new WrappedDekEnvelope(current.KeyId, rewrapped).Serialize();
            }
        }

        /// <inheritdoc />
        public async Task<byte[]> RewrapDekAsync(byte[] envelope, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(envelope);

            WrappedDekEnvelope parsed = WrappedDekEnvelope.Deserialize(envelope);
            IKekCipher source;
            IKekCipher current;
            // async re-wrap은 lock 밖에서 수행; lock 안에서는 참조만 복사한다.
            lock (sync)
            {
                ObjectDisposedException.ThrowIf(disposedValue, this);

                if (!registry.TryGetValue(parsed.KeyId, out IKekCipher? resolved) || resolved is null)
                    throw new KeyNotFoundException($"KEK with KeyId '{parsed.KeyId}' is not registered.");

                source = resolved;
                current = CurrentUnsafe;
            }

            byte[] rewrapped = await current.RewrapDekAsync(source, parsed.WrappedKey, cancellationToken)
                .ConfigureAwait(false);
            return new WrappedDekEnvelope(current.KeyId, rewrapped).Serialize();
        }

        /// <inheritdoc />
        public void RewrapDekFile(FileInfo dekFile)
        {
            ArgumentNullException.ThrowIfNull(dekFile);

            byte[] envelope = File.ReadAllBytes(dekFile.FullName);
            byte[] rewrapped = RewrapDek(envelope);
            AesGcmDekCipher.WriteAllBytesAtomic(dekFile.FullName, rewrapped);
        }

        /// <inheritdoc />
        public async Task RewrapDekFileAsync(FileInfo dekFile, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(dekFile);

            byte[] envelope = await File.ReadAllBytesAsync(dekFile.FullName, cancellationToken).ConfigureAwait(false);
            byte[] rewrapped = await RewrapDekAsync(envelope, cancellationToken).ConfigureAwait(false);
            AesGcmDekCipher.WriteAllBytesAtomic(dekFile.FullName, rewrapped);
        }

        /// <inheritdoc />
        public void Release(string keyId)
        {
            ArgumentException.ThrowIfNullOrEmpty(keyId);

            IKekCipher cipher;
            lock (sync)
            {
                ObjectDisposedException.ThrowIf(disposedValue, this);

                if (!registry.TryGetValue(keyId, out IKekCipher? registered) || registered is null)
                    throw new KeyNotFoundException($"KEK with KeyId '{keyId}' is not registered.");

                if (ReferenceEquals(registered, CurrentUnsafe))
                    throw new InvalidOperationException("Cannot release the current KEK.");

                registry.Remove(keyId);
                cipher = registered;
            }

            cipher.Dispose();
        }

        /// <summary>
        /// 파생 Manager에서 추가 리소스 정리 전에 호출할 수 있는 dispose 훅.
        /// </summary>
        /// <param name="disposing">관리 리소스를 정리할지 여부.</param>
        protected virtual void Dispose(bool disposing)
        {
            if (disposedValue)
                return;

            if (disposing)
            {
                List<IKekCipher> toDispose;
                lock (sync)
                {
                    toDispose = registry.Values.ToList();
                    registry.Clear();
                }

                foreach (IKekCipher cipher in toDispose)
                    cipher.Dispose();
            }

            disposedValue = true;
        }

        /// <inheritdoc />
        public void Dispose()
        {
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }
    }
}

using System.Text;

namespace Biz.Bizadm.KMS.Cipher
{
    /// <summary>
    /// <see cref="IDekCipher"/>를 UTF-8 문자열 API로 감싸며,
    /// 암호문은 <c>DEKENC:</c> 접두사와 Base64로 인코딩한다.
    /// </summary>
    public sealed class DekCipherService : IDekCipherService
    {
        private const string PREFIX = "DEKENC:";

        private readonly IDekCipher dekCipher;
        private readonly bool leaveOpen;
        private bool disposed;

        /// <summary>
        /// 지정한 DEK 암호로 문자열 서비스를 만든다.
        /// </summary>
        /// <param name="dekCipher">데이터 암·복호화에 사용할 DEK.</param>
        /// <param name="leaveOpen">
        /// <see langword="true"/>이면 <see cref="Dispose"/> 시 <paramref name="dekCipher"/>를 해제하지 않는다.
        /// 기본값 <see langword="false"/>는 소유권을 이전한다.
        /// </param>
        public DekCipherService(IDekCipher dekCipher, bool leaveOpen = false)
        {
            ArgumentNullException.ThrowIfNull(dekCipher);
            this.dekCipher = dekCipher;
            this.leaveOpen = leaveOpen;
        }

        /// <inheritdoc />
        public bool StartsWithFromPrefix(string input)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            ArgumentNullException.ThrowIfNull(input);
            return input.StartsWith(PREFIX, StringComparison.Ordinal);
        }

        /// <inheritdoc />
        public string Encrypt(string plain)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            ArgumentNullException.ThrowIfNull(plain);

            byte[] plainBytes = Encoding.UTF8.GetBytes(plain);
            byte[] cipherBytes = dekCipher.Encrypt(plainBytes);
            return PREFIX + Convert.ToBase64String(cipherBytes);
        }

        /// <inheritdoc />
        public async Task<string> EncryptAsync(string plain, CancellationToken cancellationToken = default)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            ArgumentNullException.ThrowIfNull(plain);
            cancellationToken.ThrowIfCancellationRequested();

            byte[] plainBytes = Encoding.UTF8.GetBytes(plain);
            byte[] cipherBytes = await dekCipher.EncryptAsync(plainBytes, cancellationToken).ConfigureAwait(false);
            return PREFIX + Convert.ToBase64String(cipherBytes);
        }

        /// <inheritdoc />
        public string Decrypt(string encrypted)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            ArgumentNullException.ThrowIfNull(encrypted);
            if (!encrypted.StartsWith(PREFIX, StringComparison.Ordinal))
            {
                throw new ArgumentException("Encrypted value is missing the DEKENC: prefix.", nameof(encrypted));
            }

            byte[] cipherBytes = Convert.FromBase64String(encrypted.Substring(PREFIX.Length));
            byte[] plainBytes = dekCipher.Decrypt(cipherBytes);
            return Encoding.UTF8.GetString(plainBytes);
        }

        /// <inheritdoc />
        public async Task<string> DecryptAsync(string encrypted, CancellationToken cancellationToken = default)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            ArgumentNullException.ThrowIfNull(encrypted);
            cancellationToken.ThrowIfCancellationRequested();
            if (!encrypted.StartsWith(PREFIX, StringComparison.Ordinal))
            {
                throw new ArgumentException("Encrypted value is missing the DEKENC: prefix.", nameof(encrypted));
            }

            byte[] cipherBytes = Convert.FromBase64String(encrypted.Substring(PREFIX.Length));
            byte[] plainBytes = await dekCipher.DecryptAsync(cipherBytes, cancellationToken).ConfigureAwait(false);
            return Encoding.UTF8.GetString(plainBytes);
        }

        /// <inheritdoc />
        public void Dispose()
        {
            if (disposed)
            {
                return;
            }

            disposed = true;
            if (!leaveOpen)
            {
                dekCipher.Dispose();
            }
        }
    }
}

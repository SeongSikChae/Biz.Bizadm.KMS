using System.Text;

namespace Biz.Bizadm.KMS.NetFramework.Cipher;

/// <summary>
/// String facade over <see cref="IDekCipher"/> using UTF-8 plaintext and
/// <c>DEKENC:</c> + Base64 ciphertext.
/// </summary>
public sealed class DekCipherService : IDekCipherService
{
    private const string PREFIX = "DEKENC:";

    private readonly IDekCipher dekCipher;
    private readonly bool leaveOpen;
    private bool disposed;

    /// <param name="leaveOpen">
    /// When true, <see cref="Dispose"/> does not dispose <paramref name="dekCipher"/>.
    /// Default false transfers ownership.
    /// </param>
    public DekCipherService(IDekCipher dekCipher, bool leaveOpen = false)
    {
        if (dekCipher is null) throw new ArgumentNullException(nameof(dekCipher));
        this.dekCipher = dekCipher;
        this.leaveOpen = leaveOpen;
    }

    public bool StartsWithFromPrefix(string input)
    {
        ThrowIfDisposed();
        if (input is null) throw new ArgumentNullException(nameof(input));
        return input.StartsWith(PREFIX, StringComparison.Ordinal);
    }

    public string Encrypt(string plain)
    {
        ThrowIfDisposed();
        if (plain is null) throw new ArgumentNullException(nameof(plain));

        byte[] plainBytes = Encoding.UTF8.GetBytes(plain);
        byte[] cipherBytes = dekCipher.Encrypt(plainBytes);
        return PREFIX + Convert.ToBase64String(cipherBytes);
    }

    public Task<string> EncryptAsync(string plain, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        if (plain is null) throw new ArgumentNullException(nameof(plain));
        cancellationToken.ThrowIfCancellationRequested();

        byte[] plainBytes = Encoding.UTF8.GetBytes(plain);
        return EncryptAsyncCore(plainBytes, cancellationToken);
    }

    public string Decrypt(string encrypted)
    {
        ThrowIfDisposed();
        if (encrypted is null) throw new ArgumentNullException(nameof(encrypted));
        if (!encrypted.StartsWith(PREFIX, StringComparison.Ordinal))
        {
            throw new ArgumentException("Encrypted value is missing the DEKENC: prefix.", nameof(encrypted));
        }

        byte[] cipherBytes = Convert.FromBase64String(encrypted.Substring(PREFIX.Length));
        byte[] plainBytes = dekCipher.Decrypt(cipherBytes);
        return Encoding.UTF8.GetString(plainBytes);
    }

    public Task<string> DecryptAsync(string encrypted, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        if (encrypted is null) throw new ArgumentNullException(nameof(encrypted));
        cancellationToken.ThrowIfCancellationRequested();
        if (!encrypted.StartsWith(PREFIX, StringComparison.Ordinal))
        {
            throw new ArgumentException("Encrypted value is missing the DEKENC: prefix.", nameof(encrypted));
        }

        byte[] cipherBytes = Convert.FromBase64String(encrypted.Substring(PREFIX.Length));
        return DecryptAsyncCore(cipherBytes, cancellationToken);
    }

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

    private async Task<string> EncryptAsyncCore(byte[] plainBytes, CancellationToken cancellationToken)
    {
        byte[] cipherBytes = await dekCipher.EncryptAsync(plainBytes, cancellationToken).ConfigureAwait(false);
        return PREFIX + Convert.ToBase64String(cipherBytes);
    }

    private async Task<string> DecryptAsyncCore(byte[] cipherBytes, CancellationToken cancellationToken)
    {
        byte[] plainBytes = await dekCipher.DecryptAsync(cipherBytes, cancellationToken).ConfigureAwait(false);
        return Encoding.UTF8.GetString(plainBytes);
    }

    private void ThrowIfDisposed()
    {
        if (disposed) throw new ObjectDisposedException(nameof(DekCipherService));
    }
}

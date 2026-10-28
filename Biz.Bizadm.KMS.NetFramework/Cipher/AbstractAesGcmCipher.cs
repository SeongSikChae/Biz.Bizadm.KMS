using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace Biz.Bizadm.KMS.NetFramework.Cipher;

/// <summary>
/// AES-256-GCM implementation with nonce || ciphertext || tag encoding.
/// </summary>
public abstract class AbstractAesGcmCipher : ICipher
{
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private readonly object sync = new object();
    private readonly byte[] key;
    private bool disposed;

    protected AbstractAesGcmCipher(byte[] key)
    {
        if (key is null) throw new ArgumentNullException(nameof(key));
        if (key.Length != 32) throw new ArgumentException("AES-256 requires a 32-byte key.", nameof(key));
        this.key = (byte[])key.Clone();
    }

    public byte[] Encrypt(byte[] plain)
    {
        if (plain is null) throw new ArgumentNullException(nameof(plain));
        lock (sync)
        {
            ThrowIfDisposed();
            byte[] nonce = new byte[NonceSize];
            using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create()) rng.GetBytes(nonce);
            byte[] cipherAndTag = Transform(true, nonce, plain);
            byte[] output = new byte[nonce.Length + cipherAndTag.Length];
            Buffer.BlockCopy(nonce, 0, output, 0, nonce.Length);
            Buffer.BlockCopy(cipherAndTag, 0, output, nonce.Length, cipherAndTag.Length);
            Array.Clear(cipherAndTag, 0, cipherAndTag.Length);
            return output;
        }
    }

    public Task<byte[]> EncryptAsync(byte[] plain, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(Encrypt(plain));
    }

    public byte[] Decrypt(byte[] encrypted)
    {
        if (encrypted is null) throw new ArgumentNullException(nameof(encrypted));
        if (encrypted.Length < NonceSize + TagSize) throw new ArgumentException("Invalid encrypted data.", nameof(encrypted));
        lock (sync)
        {
            ThrowIfDisposed();
            byte[] nonce = new byte[NonceSize];
            Buffer.BlockCopy(encrypted, 0, nonce, 0, NonceSize);
            byte[] payload = new byte[encrypted.Length - NonceSize];
            Buffer.BlockCopy(encrypted, NonceSize, payload, 0, payload.Length);
            return Transform(false, nonce, payload);
        }
    }

    public Task<byte[]> DecryptAsync(byte[] encrypted, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(Decrypt(encrypted));
    }

    private byte[] Transform(bool forEncryption, byte[] nonce, byte[] input)
    {
        var cipher = new GcmBlockCipher(new AesEngine());
        cipher.Init(forEncryption, new AeadParameters(new KeyParameter(key), TagSize * 8, nonce));
        byte[] output = new byte[cipher.GetOutputSize(input.Length)];
        try
        {
            int length = cipher.ProcessBytes(input, 0, input.Length, output, 0);
            length += cipher.DoFinal(output, length);
            Array.Resize(ref output, length);
            return output;
        }
        catch (InvalidCipherTextException exception)
        {
            Array.Clear(output, 0, output.Length);
            throw new System.Security.Cryptography.CryptographicException("AES-GCM authentication failed.", exception);
        }
        catch
        {
            Array.Clear(output, 0, output.Length);
            throw;
        }
    }

    protected byte[] ExportKeyMaterialCopy()
    {
        lock (sync)
        {
            ThrowIfDisposed();
            return (byte[])key.Clone();
        }
    }

    private void ThrowIfDisposed()
    {
        if (disposed) throw new ObjectDisposedException(GetType().FullName);
    }

    public void Dispose()
    {
        lock (sync)
        {
            if (disposed) return;
            disposed = true;
            Array.Clear(key, 0, key.Length);
        }
        GC.SuppressFinalize(this);
    }
}

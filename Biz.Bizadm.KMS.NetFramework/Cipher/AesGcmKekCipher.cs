using System.Security.Cryptography;

namespace Biz.Bizadm.KMS.NetFramework.Cipher;

/// <summary>
/// Software KEK derived with PBKDF2-HMAC-SHA256.
/// </summary>
public sealed class AesGcmKekCipher : AbstractAesGcmCipher, IKekCipher
{
    public string KeyId { get; }

    private AesGcmKekCipher(byte[] key)
        : base(key)
    {
        using (SHA256 sha256 = SHA256.Create())
        {
            byte[] hash = sha256.ComputeHash(key);
            KeyId = "aesgcm:" + BitConverter.ToString(hash).Replace("-", string.Empty).ToLowerInvariant();
            Array.Clear(hash, 0, hash.Length);
        }
    }

    public static AesGcmKekCipher Create(IKekCredentialProvider credentialProvider, byte[] salt, int iterationCount)
    {
        if (credentialProvider is null) throw new ArgumentNullException(nameof(credentialProvider));
        if (salt is null) throw new ArgumentNullException(nameof(salt));
        byte[] password = credentialProvider.GetPassword();
        if (password is null) throw new InvalidOperationException("Credential provider returned a null password.");
        try
        {
            return CreateFromPassword(password, salt, iterationCount);
        }
        finally
        {
            Array.Clear(password, 0, password.Length);
        }
    }

    public static async Task<AesGcmKekCipher> CreateAsync(
        IKekCredentialProvider credentialProvider,
        byte[] salt,
        int iterationCount,
        CancellationToken cancellationToken = default)
    {
        if (credentialProvider is null) throw new ArgumentNullException(nameof(credentialProvider));
        if (salt is null) throw new ArgumentNullException(nameof(salt));
        byte[] password = await credentialProvider.GetPasswordAsync(cancellationToken).ConfigureAwait(false);
        if (password is null) throw new InvalidOperationException("Credential provider returned a null password.");
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            return CreateFromPassword(password, salt, iterationCount);
        }
        finally
        {
            Array.Clear(password, 0, password.Length);
        }
    }

    private static AesGcmKekCipher CreateFromPassword(byte[] password, byte[] salt, int iterationCount)
    {
        if (iterationCount <= 0) throw new ArgumentOutOfRangeException(nameof(iterationCount));
        byte[] key = Pbkdf2Sha256(password, salt, iterationCount, 32);
        try
        {
            return new AesGcmKekCipher(key);
        }
        finally
        {
            Array.Clear(key, 0, key.Length);
        }
    }

    private static byte[] Pbkdf2Sha256(byte[] password, byte[] salt, int iterationCount, int outputLength)
    {
        using (var hmac = new HMACSHA256(password))
        {
            byte[] output = new byte[outputLength];
            byte[] input = new byte[salt.Length + 4];
            Buffer.BlockCopy(salt, 0, input, 0, salt.Length);
            byte[] u = new byte[32];
            byte[] block = new byte[32];
            int outputOffset = 0;
            uint blockIndex = 1;

            try
            {
                while (outputOffset < outputLength)
                {
                    input[input.Length - 4] = (byte)(blockIndex >> 24);
                    input[input.Length - 3] = (byte)(blockIndex >> 16);
                    input[input.Length - 2] = (byte)(blockIndex >> 8);
                    input[input.Length - 1] = (byte)blockIndex;
                    byte[] first = hmac.ComputeHash(input);
                    Buffer.BlockCopy(first, 0, u, 0, u.Length);
                    Buffer.BlockCopy(first, 0, block, 0, block.Length);
                    Array.Clear(first, 0, first.Length);

                    for (int iteration = 1; iteration < iterationCount; iteration++)
                    {
                        byte[] next = hmac.ComputeHash(u);
                        Array.Clear(u, 0, u.Length);
                        Buffer.BlockCopy(next, 0, u, 0, u.Length);
                        for (int i = 0; i < block.Length; i++) block[i] ^= u[i];
                        Array.Clear(next, 0, next.Length);
                    }

                    int count = Math.Min(block.Length, outputLength - outputOffset);
                    Buffer.BlockCopy(block, 0, output, outputOffset, count);
                    outputOffset += count;
                    blockIndex++;
                }
                return output;
            }
            catch
            {
                Array.Clear(output, 0, output.Length);
                throw;
            }
            finally
            {
                Array.Clear(input, 0, input.Length);
                Array.Clear(u, 0, u.Length);
                Array.Clear(block, 0, block.Length);
            }
        }
    }

    public byte[] RewrapDek(IKekCipher source, byte[] wrappedDek)
        => KekCipherExtensions.RewrapDek(this, source, wrappedDek);

    public Task<byte[]> RewrapDekAsync(IKekCipher source, byte[] wrappedDek, CancellationToken cancellationToken = default)
        => KekCipherExtensions.RewrapDekAsync(this, source, wrappedDek, cancellationToken);
}

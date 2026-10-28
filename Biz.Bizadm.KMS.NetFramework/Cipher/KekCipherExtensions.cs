using System.Security.Cryptography;

namespace Biz.Bizadm.KMS.NetFramework.Cipher;

public static class KekCipherExtensions
{
    public static byte[] RewrapDek(this IKekCipher target, IKekCipher source, byte[] wrappedDek)
    {
        if (target is null) throw new ArgumentNullException(nameof(target));
        if (source is null) throw new ArgumentNullException(nameof(source));
        if (wrappedDek is null) throw new ArgumentNullException(nameof(wrappedDek));

        byte[] dek = source.Decrypt(wrappedDek);
        try
        {
            return target.Encrypt(dek);
        }
        finally
        {
            Array.Clear(dek, 0, dek.Length);
        }
    }

    public static async Task<byte[]> RewrapDekAsync(
        this IKekCipher target,
        IKekCipher source,
        byte[] wrappedDek,
        CancellationToken cancellationToken = default)
    {
        if (target is null) throw new ArgumentNullException(nameof(target));
        if (source is null) throw new ArgumentNullException(nameof(source));
        if (wrappedDek is null) throw new ArgumentNullException(nameof(wrappedDek));

        byte[] dek = await source.DecryptAsync(wrappedDek, cancellationToken).ConfigureAwait(false);
        try
        {
            return await target.EncryptAsync(dek, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            Array.Clear(dek, 0, dek.Length);
        }
    }
}

using System.Security.Cryptography;
using Biz.Bizadm.KMS.Cipher;

if (args.Length != 3)
{
    Console.Error.WriteLine("Usage: InteropNet10 <encrypt|decrypt> <key-hex> <input-hex>");
    return 2;
}

byte[] key = Convert.FromHexString(args[1]);
byte[] input = Convert.FromHexString(args[2]);
try
{
    using var cipher = new InteropCipher(key);
    byte[] output = args[0] switch
    {
        "encrypt" => cipher.Encrypt(input),
        "decrypt" => cipher.Decrypt(input),
        _ => throw new ArgumentException("Unknown operation.")
    };
    Console.Write(Convert.ToHexString(output));
    CryptographicOperations.ZeroMemory(output);
    return 0;
}
finally
{
    CryptographicOperations.ZeroMemory(key);
}

internal sealed class InteropCipher(byte[] key) : AbstractAesGcmCipher(key)
{
    public override Task<byte[]> EncryptAsync(byte[] plain, CancellationToken cancellationToken = default)
        => Task.FromResult(Encrypt(plain));

    public override Task<byte[]> DecryptAsync(byte[] encrypted, CancellationToken cancellationToken = default)
        => Task.FromResult(Decrypt(encrypted));
}

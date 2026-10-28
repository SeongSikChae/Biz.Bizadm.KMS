using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

if (args.Length != 3)
{
    Console.Error.WriteLine("Usage: InteropNet48 <encrypt|decrypt> <key-hex> <input-hex>");
    return 2;
}

byte[] key = FromHex(args[1]);
byte[] input = FromHex(args[2]);
try
{
    byte[] output = args[0] switch
    {
        "encrypt" => Transform(true, key, input),
        "decrypt" => Transform(false, key, input),
        _ => throw new ArgumentException("Unknown operation.")
    };
    Console.Write(ToHex(output));
    Array.Clear(output, 0, output.Length);
    return 0;
}
finally
{
    Array.Clear(key, 0, key.Length);
}

static byte[] Transform(bool encrypt, byte[] key, byte[] input)
{
    const int nonceSize = 12;
    const int tagSize = 16;
    GcmBlockCipher cipher = new GcmBlockCipher(new AesEngine());
    byte[] nonce;
    byte[] payload;

    if (encrypt)
    {
        nonce = new byte[nonceSize];
        using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create())
        {
            rng.GetBytes(nonce);
        }
        payload = input;
    }
    else
    {
        if (input.Length < nonceSize + tagSize)
        {
            throw new ArgumentException("Encrypted data is too short.");
        }
        nonce = new byte[nonceSize];
        Buffer.BlockCopy(input, 0, nonce, 0, nonceSize);
        payload = new byte[input.Length - nonceSize];
        Buffer.BlockCopy(input, nonceSize, payload, 0, payload.Length);
    }

    cipher.Init(encrypt, new AeadParameters(new KeyParameter(key), tagSize * 8, nonce));
    byte[] result = new byte[cipher.GetOutputSize(payload.Length)];
    int length = cipher.ProcessBytes(payload, 0, payload.Length, result, 0);
    length += cipher.DoFinal(result, length);

    if (encrypt)
    {
        byte[] combined = new byte[nonce.Length + length];
        Buffer.BlockCopy(nonce, 0, combined, 0, nonce.Length);
        Buffer.BlockCopy(result, 0, combined, nonce.Length, length);
        Array.Clear(result, 0, result.Length);
        return combined;
    }

    Array.Resize(ref result, length);
    return result;
}

static byte[] FromHex(string value)
{
    byte[] result = new byte[value.Length / 2];
    for (int i = 0; i < result.Length; i++)
    {
        result[i] = byte.Parse(value.Substring(i * 2, 2), System.Globalization.NumberStyles.HexNumber);
    }
    return result;
}

static string ToHex(byte[] value)
{
    return BitConverter.ToString(value).Replace("-", string.Empty);
}

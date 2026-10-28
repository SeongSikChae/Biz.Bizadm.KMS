using System.Reflection;
using System.Text;
using Biz.Bizadm.KMS.NetFramework.Cipher;

byte[] password = Encoding.UTF8.GetBytes("package-consumer-password");
byte[] salt = Encoding.UTF8.GetBytes("0123456789abcdef");
byte[] plain = Encoding.UTF8.GetBytes("consumer-ok");

try
{
    Assembly assembly = typeof(AesGcmKekCipher).Assembly;
    Console.WriteLine("ASSEMBLY=" + assembly.GetName().Name);
    Console.WriteLine("LOCATION=" + assembly.Location);

    IKekCredentialProvider credentials = new FixedPassword(password);
    using (AesGcmKekCipher cipher = AesGcmKekCipher.Create(credentials, salt, 10_000))
    {
        byte[] encrypted = cipher.Encrypt(plain);
        byte[] decrypted = cipher.Decrypt(encrypted);
        if (!plain.SequenceEqual(decrypted))
        {
            Console.Error.WriteLine("FAIL decrypt mismatch");
            return 2;
        }

        Console.WriteLine("KEYID=" + cipher.KeyId);
        Console.WriteLine("FEATURE_AES=" + FeatureSupport.SoftwareAesGcm);
        Console.WriteLine("OK");
        return 0;
    }
}
catch (Exception ex)
{
    Console.Error.WriteLine(ex);
    return 1;
}
finally
{
    Array.Clear(password, 0, password.Length);
}

sealed class FixedPassword : IKekCredentialProvider
{
    private readonly byte[] password;

    public FixedPassword(byte[] password) => this.password = (byte[])password.Clone();

    public byte[] GetPassword() => (byte[])password.Clone();

    public Task<byte[]> GetPasswordAsync(CancellationToken cancellationToken = default)
        => Task.FromResult(GetPassword());
}

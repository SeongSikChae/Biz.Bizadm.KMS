using System.Security.Cryptography;
using System.Text;

namespace Biz.Bizadm.KMS.NetFramework.Cipher.Tpm;

internal static class TpmKekAuth
{
    private static readonly byte[] SrkLabel = Encoding.UTF8.GetBytes("Biz.Bizadm.KMS.Tpm.Srk");
    private static readonly byte[] KekLabel = Encoding.UTF8.GetBytes("Biz.Bizadm.KMS.Tpm.Kek");

    internal static byte[] DeriveSrkAuth(byte[] password)
        => DeriveObjectAuth(password, SrkLabel);

    internal static byte[] DeriveKekAuth(byte[] password)
        => DeriveObjectAuth(password, KekLabel);

    private static byte[] DeriveObjectAuth(byte[] password, byte[] label)
    {
        if (password is null) throw new ArgumentNullException(nameof(password));
        using (HMACSHA256 hmac = new HMACSHA256(password))
        {
            return hmac.ComputeHash(label);
        }
    }
}

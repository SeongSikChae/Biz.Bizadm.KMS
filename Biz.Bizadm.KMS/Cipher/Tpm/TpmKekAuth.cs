using System.Security.Cryptography;

namespace Biz.Bizadm.KMS.Cipher.Tpm
{
    /// <summary>
    /// TPM 객체 authValue 유도. password는 Create 시 1회만 사용하고 즉시 폐기한다.
    /// </summary>
    internal static class TpmKekAuth
    {
        private static ReadOnlySpan<byte> SrkLabel => "Biz.Bizadm.KMS.Tpm.Srk"u8;
        private static ReadOnlySpan<byte> KekLabel => "Biz.Bizadm.KMS.Tpm.Kek"u8;

        internal static byte[] DeriveSrkAuth(byte[] password)
            => DeriveObjectAuth(password, SrkLabel);

        internal static byte[] DeriveKekAuth(byte[] password)
            => DeriveObjectAuth(password, KekLabel);

        private static byte[] DeriveObjectAuth(byte[] password, ReadOnlySpan<byte> label)
        {
            ArgumentNullException.ThrowIfNull(password);
            return HMACSHA256.HashData(password, label);
        }
    }
}

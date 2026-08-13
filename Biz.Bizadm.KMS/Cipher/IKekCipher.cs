namespace Biz.Bizadm.KMS.Cipher
{
    public interface IKekCipher : IDisposable
    {
        byte[] Encrypt(byte[] plain);

        byte[] Decrypt(byte[] encrypted);
    }
}

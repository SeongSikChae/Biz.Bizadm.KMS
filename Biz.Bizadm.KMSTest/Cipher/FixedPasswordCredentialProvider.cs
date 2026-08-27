using Biz.Bizadm.KMS.Cipher;

namespace Biz.Bizadm.KMSTest.Cipher
{
    internal sealed class FixedPasswordCredentialProvider(byte[] password) : IKekCredentialProvider
    {
        public byte[] GetPassword()
            => [.. password];

        public Task<byte[]> GetPasswordAsync(CancellationToken cancellationToken = default)
        {
            return Task.FromResult(GetPassword());
        }
    }
}

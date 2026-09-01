using Biz.Bizadm.KMS.Cipher;

namespace Biz.Bizadm.KMS.Pkcs11.Cipher
{
    /// <summary>
    /// <see cref="Pkcs11KekCipher"/> 기반 KEK Manager.
    /// </summary>
    public sealed class Pkcs11KekManager : KekManagerBase
    {
        private readonly Pkcs11LibraryContext context;
        private bool disposedValue;

        private Pkcs11KekManager(Pkcs11LibraryContext context, Pkcs11KekCipher initial) : base(initial)
        {
            this.context = context;
        }

        /// <summary>
        /// HSM에서 KEK를 로드(없으면 생성)한 뒤 Manager를 생성한다.
        /// </summary>
        /// <param name="context">로그인된 PKCS#11 컨텍스트. Manager가 수명을 관리한다.</param>
        /// <param name="keyLabel">HSM KEK 라벨.</param>
        /// <param name="createIfMissing">키가 없을 때 생성할지 여부.</param>
        /// <param name="options">wrap 메커니즘·RSA 키 옵션.</param>
        /// <returns>생성된 <see cref="Pkcs11KekManager"/>.</returns>
        public static Pkcs11KekManager Create(
            Pkcs11LibraryContext context,
            string keyLabel,
            bool createIfMissing = true,
            Pkcs11KekOptions? options = null)
        {
            Pkcs11KekCipher cipher = Pkcs11KekCipher.Create(context, keyLabel, createIfMissing, options);
            return new Pkcs11KekManager(context, cipher);
        }

        /// <summary>
        /// HSM에 새 RSA KEK를 생성하고 Current를 교체한다.
        /// </summary>
        /// <param name="newKeyLabel">새 KEK 라벨.</param>
        /// <param name="options">wrap 메커니즘·RSA 키 옵션. null이면 현재 옵션을 재사용한다.</param>
        /// <returns>새 Current KEK.</returns>
        public Pkcs11KekCipher Rotate(string newKeyLabel, Pkcs11KekOptions? options = null)
        {
            ObjectDisposedException.ThrowIf(disposedValue, this);
            Pkcs11KekCipher current = (Pkcs11KekCipher)Current;
            Pkcs11KekCipher rotated = current.Rotate(newKeyLabel, options);
            SetCurrent(rotated);
            return rotated;
        }

        /// <inheritdoc />
        public new void Dispose()
        {
            if (disposedValue)
                return;

            disposedValue = true;
            base.Dispose();
            context.Dispose();
            GC.SuppressFinalize(this);
        }
    }
}

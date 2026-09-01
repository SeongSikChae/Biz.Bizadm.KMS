using Biz.Bizadm.KMS.Cipher;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using System.Security.Cryptography;
using System.Text;

namespace Biz.Bizadm.KMS.Pkcs11.Cipher
{
    /// <summary>
    /// PKCS#11 라이브러리·슬롯·세션 수명과 직렬화된 HSM 호출을 관리한다.
    /// </summary>
    public sealed class Pkcs11LibraryContext : IDisposable
    {
        private readonly SemaphoreSlim gate = new(1, 1);
        private readonly Pkcs11InteropFactories factories;
        private readonly IPkcs11Library library;
        private readonly ISession session;
        private bool disposedValue;

        /// <summary>
        /// PKCS#11 팩토리. 세션 작업 시 사용한다.
        /// </summary>
        public Pkcs11InteropFactories Factories => factories;

        /// <summary>
        /// 로그인된 RW 세션.
        /// </summary>
        public ISession Session => session;

        private Pkcs11LibraryContext(
            Pkcs11InteropFactories factories,
            IPkcs11Library library,
            ISession session)
        {
            this.factories = factories;
            this.library = library;
            this.session = session;
        }

        /// <summary>
        /// PKCS#11 라이브러리를 로드하고 슬롯에 USER PIN으로 로그인한다.
        /// </summary>
        /// <param name="libraryPath">cryptoki DLL/SO 경로.</param>
        /// <param name="slotId">토큰이 있는 슬롯 ID.</param>
        /// <param name="pinProvider">USER PIN 제공자.</param>
        /// <param name="appType">PKCS#11 앱 타입. 기본 MultiThreaded.</param>
        /// <returns>생성된 컨텍스트.</returns>
        public static Pkcs11LibraryContext Create(
            string libraryPath,
            ulong slotId,
            IKekCredentialProvider pinProvider,
            AppType appType = AppType.MultiThreaded)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(libraryPath);
            ArgumentNullException.ThrowIfNull(pinProvider);

            byte[] pinBytes = pinProvider.GetPassword();
            try
            {
                string pin = Encoding.UTF8.GetString(pinBytes);
                Pkcs11InteropFactories factories = new();
                IPkcs11Library library = factories.Pkcs11LibraryFactory.LoadPkcs11Library(
                    factories,
                    libraryPath,
                    appType);

                ISlot slot = library.GetSlotList(SlotsType.WithTokenPresent)
                    .FirstOrDefault(candidate => candidate.SlotId == slotId)
                    ?? throw new InvalidOperationException($"PKCS#11 slot {slotId} with token was not found.");

                ISession session = slot.OpenSession(SessionType.ReadWrite);
                try
                {
                    session.Login(CKU.CKU_USER, pin);
                }
                catch
                {
                    session.Dispose();
                    library.Dispose();
                    throw;
                }

                return new Pkcs11LibraryContext(factories, library, session);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(pinBytes);
            }
        }

        /// <summary>
        /// HSM 세션 호출을 직렬화한다.
        /// </summary>
        /// <typeparam name="T">작업 결과 형식.</typeparam>
        /// <param name="action">세션에서 수행할 작업.</param>
        /// <returns>작업 결과.</returns>
        public T Execute<T>(Func<ISession, T> action)
        {
            ObjectDisposedException.ThrowIf(disposedValue, this);
            ArgumentNullException.ThrowIfNull(action);

            gate.Wait();
            try
            {
                return action(session);
            }
            finally
            {
                gate.Release();
            }
        }

        /// <summary>
        /// HSM 세션 호출을 직렬화한다.
        /// </summary>
        /// <param name="action">세션에서 수행할 작업.</param>
        public void Execute(Action<ISession> action)
        {
            Execute<object?>(session =>
            {
                action(session);
                return null;
            });
        }

        /// <inheritdoc />
        public void Dispose()
        {
            if (disposedValue)
                return;

            disposedValue = true;
            try
            {
                session.Logout();
            }
            catch (Pkcs11Exception)
            {
            }

            session.Dispose();
            library.Dispose();
            gate.Dispose();
            GC.SuppressFinalize(this);
        }
    }
}

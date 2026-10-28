using System.Security.Cryptography;
using System.Text;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;

namespace Biz.Bizadm.KMS.NetFramework.Cipher.Pkcs11;

/// <summary>
/// Independent PKCS#11 library/session context for net48.
/// </summary>
public sealed class Pkcs11LibraryContext : IDisposable
{
    private readonly SemaphoreSlim gate = new SemaphoreSlim(1, 1);
    private readonly Pkcs11InteropFactories factories;
    private readonly IPkcs11Library library;
    private readonly ISession session;
    private bool disposedValue;

    public Pkcs11InteropFactories Factories => factories;

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

    public static Pkcs11LibraryContext Create(
        string libraryPath,
        ulong slotId,
        IKekCredentialProvider pinProvider,
        AppType appType = AppType.MultiThreaded)
    {
        if (string.IsNullOrWhiteSpace(libraryPath)) throw new ArgumentException("Library path is required.", nameof(libraryPath));
        if (pinProvider is null) throw new ArgumentNullException(nameof(pinProvider));

        byte[] pinBytes = pinProvider.GetPassword();
        try
        {
            string pin = Encoding.UTF8.GetString(pinBytes);
            Pkcs11InteropFactories factories = new Pkcs11InteropFactories();
            IPkcs11Library library = factories.Pkcs11LibraryFactory.LoadPkcs11Library(
                factories,
                libraryPath,
                appType);

            ISlot? slot = library.GetSlotList(SlotsType.WithTokenPresent)
                .FirstOrDefault(candidate => candidate.SlotId == slotId);
            if (slot is null)
                throw new InvalidOperationException("PKCS#11 slot " + slotId + " with token was not found.");

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
            Array.Clear(pinBytes, 0, pinBytes.Length);
        }
    }

    public T Execute<T>(Func<ISession, T> action)
    {
        if (disposedValue) throw new ObjectDisposedException(nameof(Pkcs11LibraryContext));
        if (action is null) throw new ArgumentNullException(nameof(action));

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

    public void Execute(Action<ISession> action)
    {
        Execute<object?>(session =>
        {
            action(session);
            return null;
        });
    }

    public void Dispose()
    {
        if (disposedValue) return;
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

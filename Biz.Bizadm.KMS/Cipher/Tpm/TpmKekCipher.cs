using System.Security.Cryptography;
using Tpm2Lib;

namespace Biz.Bizadm.KMS.Cipher.Tpm
{
    public sealed class TpmKekCipher : IKekCipher
    {
        private readonly Tpm2 tpm;

        private TpmHandle? srkHandle;
        private TpmHandle? kekHandle;
        private bool disposedValue;

        // private static readonly SchemeOaep OaepSha256 = new(TpmAlgId.Sha256);
        private const int AesBlockSize = 16;

        public TpmKekCipher(Tpm2Device device, byte[] password, FileInfo kekBlobFile)
        {
            ArgumentNullException.ThrowIfNull(device);
            ArgumentNullException.ThrowIfNull(password);
            ArgumentNullException.ThrowIfNull(kekBlobFile);

            TpmPublic keySpec = ApplyPassword(CreateDefaultSrkKeySpec(), password);
            tpm = new Tpm2(device);

            try
            {
                srkHandle = CreateSrk(tpm, keySpec);
                kekBlobFile.Refresh();
                kekHandle = kekBlobFile.Exists
                    ? LoadKek(tpm, srkHandle, TpmKekBlob.Load(kekBlobFile))
                    : CreateKek(tpm, srkHandle, kekBlobFile);
            }
            catch
            {
                Flush(kekHandle);
                Flush(srkHandle);
                tpm.Dispose();
                throw;
            }
        }

        public byte[] Encrypt(byte[] plain)
        {
            if (disposedValue)
                throw new ObjectDisposedException(nameof(TpmKekCipher));
            ArgumentNullException.ThrowIfNull(plain);

            // return tpm.RsaEncrypt(Kek, plain, OaepSha256, null);
            byte[] iv = new byte[AesBlockSize];
            RandomNumberGenerator.Fill(iv);
            byte[] cipher = tpm.EncryptDecrypt(Kek, 0, TpmAlgId.Cfb, iv, plain, out _);

            byte[] output = new byte[iv.Length + cipher.Length];
            Buffer.BlockCopy(iv, 0, output, 0, iv.Length);
            Buffer.BlockCopy(cipher, 0, output, iv.Length, cipher.Length);
            return output;
        }

        public byte[] Decrypt(byte[] encrypted)
        {
            if (disposedValue)
                throw new ObjectDisposedException(nameof(TpmKekCipher));
            ArgumentNullException.ThrowIfNull(encrypted);
            if (encrypted.Length < AesBlockSize)
                throw new ArgumentException("Encrypted payload is shorter than the AES-CFB IV.", nameof(encrypted));

            // return tpm.RsaDecrypt(Kek, encrypted, OaepSha256, null);
            byte[] iv = encrypted.AsSpan(0, AesBlockSize).ToArray();
            byte[] cipher = encrypted.AsSpan(AesBlockSize).ToArray();
            return tpm.EncryptDecrypt(Kek, 1, TpmAlgId.Cfb, iv, cipher, out _);
        }

        private TpmHandle Kek
            => kekHandle ?? throw new InvalidOperationException("KEK is not loaded.");

        private void Flush(TpmHandle? handle)
        {
            if (handle is null)
                return;

            try
            {
                tpm.FlushContext(handle);
            }
            catch (Exception)
            {
            }
        }

        private void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    Flush(kekHandle);
                    kekHandle = null;
                    Flush(srkHandle);
                    srkHandle = null;
                    tpm.Dispose();
                }

                disposedValue = true;
            }
        }

        // // TODO: 비관리형 리소스를 해제하는 코드가 'Dispose(bool disposing)'에 포함된 경우에만 종료자를 재정의합니다.
        // ~TpmKekCipher()
        // {
        //     // 이 코드를 변경하지 마세요. 'Dispose(bool disposing)' 메서드에 정리 코드를 입력합니다.
        //     Dispose(disposing: false);
        // }

        public void Dispose()
        {
            // 이 코드를 변경하지 마세요. 'Dispose(bool disposing)' 메서드에 정리 코드를 입력합니다.
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }

        private static TpmPublic CreateDefaultSrkKeySpec()
        {
            return new TpmPublic(
                TpmAlgId.Sha256,
                ObjectAttr.Restricted | ObjectAttr.Decrypt |
                ObjectAttr.FixedParent | ObjectAttr.FixedTPM |
                ObjectAttr.UserWithAuth | ObjectAttr.SensitiveDataOrigin | ObjectAttr.NoDA,
                null,
                new RsaParms(
                    new SymDefObject(TpmAlgId.Aes, 256, TpmAlgId.Cfb),
                    new NullAsymScheme(),
                    2048,
                    0),
                new Tpm2bPublicKeyRsa());
        }

        private static TpmPublic ApplyPassword(TpmPublic keySpec, byte[]? password)
        {
            if (password is null || password.Length == 0)
                return keySpec;

            byte[] seed = SHA256.HashData(password);
            return new TpmPublic(
                keySpec.nameAlg,
                keySpec.objectAttributes,
                keySpec.authPolicy,
                keySpec.parameters,
                CreateUnique(keySpec.type, seed));
        }

        private static IPublicIdUnion CreateUnique(TpmAlgId type, byte[] seed)
        {
            return type switch
            {
                TpmAlgId.Rsa => new Tpm2bPublicKeyRsa(seed),
                TpmAlgId.Keyedhash => new Tpm2bDigestKeyedhash(seed),
                TpmAlgId.Symcipher => new Tpm2bDigestSymcipher(seed),
                _ => throw new NotSupportedException($"Password-derived SRK is not supported for {type}.")
            };
        }

        private static TpmHandle CreateKek(Tpm2 tpm, TpmHandle srk, FileInfo kekBlobFile)
        {
            ArgumentNullException.ThrowIfNull(tpm);
            ArgumentNullException.ThrowIfNull(srk);
            ArgumentNullException.ThrowIfNull(kekBlobFile);

            TpmPrivate kekPrivate = tpm.Create(
                srk,
                new SensitiveCreate(null, null),
                CreateKekKeySpec(),
                null,
                [],
                out TpmPublic kekPublic,
                out _,
                out _,
                out _);

            new TpmKekBlob(kekPrivate, kekPublic).Save(kekBlobFile);
            return tpm.Load(srk, kekPrivate, kekPublic);
        }

        private static TpmHandle LoadKek(Tpm2 tpm, TpmHandle srk, TpmKekBlob kekBlob)
        {
            ArgumentNullException.ThrowIfNull(tpm);
            ArgumentNullException.ThrowIfNull(srk);
            ArgumentNullException.ThrowIfNull(kekBlob);
            return LoadKek(tpm, srk, kekBlob.Private, kekBlob.Public);
        }

        private static TpmHandle LoadKek(Tpm2 tpm, TpmHandle srk, TpmPrivate kekPrivate, TpmPublic kekPublic)
        {
            ArgumentNullException.ThrowIfNull(tpm);
            ArgumentNullException.ThrowIfNull(srk);
            ArgumentNullException.ThrowIfNull(kekPrivate);
            ArgumentNullException.ThrowIfNull(kekPublic);

            return tpm.Load(srk, kekPrivate, kekPublic);
        }

        private static TpmHandle CreateSrk(Tpm2 tpm, TpmPublic keySpec)
        {
            return tpm.CreatePrimary(
                TpmRh.Owner,
                new SensitiveCreate(null, null),
                keySpec,
                null,
                [],
                out _,
                out _,
                out _,
                out _);
        }

        private static TpmPublic CreateKekKeySpec()
        {
            // return new TpmPublic(
            //     TpmAlgId.Sha256,
            //     ObjectAttr.Decrypt |
            //     ObjectAttr.FixedParent | ObjectAttr.FixedTPM |
            //     ObjectAttr.UserWithAuth | ObjectAttr.SensitiveDataOrigin | ObjectAttr.NoDA,
            //     null,
            //     new RsaParms(
            //         new SymDefObject(),
            //         new SchemeOaep(TpmAlgId.Sha256),
            //         2048,
            //         0),
            //     new Tpm2bPublicKeyRsa());
            return new TpmPublic(
                TpmAlgId.Sha256,
                ObjectAttr.Decrypt | ObjectAttr.Encrypt |
                ObjectAttr.FixedParent | ObjectAttr.FixedTPM |
                ObjectAttr.UserWithAuth | ObjectAttr.SensitiveDataOrigin | ObjectAttr.NoDA,
                null,
                new SymDefObject(TpmAlgId.Aes, 256, TpmAlgId.Cfb),
                new Tpm2bDigestSymcipher());
        }
    }
}

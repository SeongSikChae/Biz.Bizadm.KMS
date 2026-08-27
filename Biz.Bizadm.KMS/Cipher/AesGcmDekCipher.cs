using System.Security.Cryptography;

namespace Biz.Bizadm.KMS.Cipher
{
    /// <summary>
    /// 파일 또는 바이트로 보관된 DEK를 KEK로 wrap/unwrap하여 사용하는 AES-GCM DEK 암호.
    /// </summary>
    public sealed class AesGcmDekCipher : AbstractAesGcmCipher, IDekCipher
    {
        private const int KeySize = 32;

        /// <summary>
        /// DEK 파일이 있으면 로드하고, 없으면 새 DEK를 생성해 저장한 뒤 암호를 만든다.
        /// </summary>
        /// <param name="cipher">DEK를 wrap/unwrap할 KEK 암호.</param>
        /// <param name="f">암호화된 DEK를 저장·로드할 파일.</param>
        /// <returns>생성된 <see cref="AesGcmDekCipher"/>.</returns>
        public static AesGcmDekCipher Create(IKekCipher cipher, FileInfo f)
        {
            ArgumentNullException.ThrowIfNull(cipher);
            ArgumentNullException.ThrowIfNull(f);

            f.Refresh();
            if (f.Exists)
                return Create(cipher, File.ReadAllBytes(f.FullName));

            byte[] key = new byte[KeySize];
            RandomNumberGenerator.Fill(key);
            try
            {
                byte[] encrypted = cipher.Encrypt(key);
                f.Directory?.Create();
                try
                {
                    WriteAllBytesAtomic(f.FullName, encrypted);
                    return new AesGcmDekCipher(key);
                }
                catch (IOException) when (File.Exists(f.FullName))
                {
                    CryptographicOperations.ZeroMemory(key);
                    return Create(cipher, File.ReadAllBytes(f.FullName));
                }
            }
            catch
            {
                CryptographicOperations.ZeroMemory(key);
                throw;
            }
        }

        /// <summary>
        /// KEK로 wrap된 DEK 바이트에서 암호를 만든다.
        /// </summary>
        /// <param name="cipher">DEK를 unwrap할 KEK 암호.</param>
        /// <param name="encryptedKey">암호화된 DEK.</param>
        /// <returns>생성된 <see cref="AesGcmDekCipher"/>.</returns>
        public static AesGcmDekCipher Create(IKekCipher cipher, byte[] encryptedKey)
        {
            return new AesGcmDekCipher(cipher, encryptedKey);
        }

        private static void WriteAllBytesAtomic(string path, byte[] data)
        {
            string? directory = Path.GetDirectoryName(path);
            if (string.IsNullOrEmpty(directory))
                throw new ArgumentException("Path must include a directory.", nameof(path));

            string tempPath = Path.Combine(directory, Path.GetRandomFileName());

            try
            {
                File.WriteAllBytes(tempPath, data);
                File.Move(tempPath, path);
            }
            catch
            {
                try
                {
                    File.Delete(tempPath);
                }
                catch (IOException)
                {
                }
                catch (UnauthorizedAccessException)
                {
                }

                throw;
            }
        }

        private AesGcmDekCipher(IKekCipher cipher, byte[] encryptedKey) : this(cipher.Decrypt(encryptedKey))
        {
        }

        private AesGcmDekCipher(byte[] key) : base(key)
        {
        }
    }
}

using System.IO;

namespace Biz.Bizadm.KMS.NetFramework.Cipher;

/// <summary>
/// Reads and atomically creates or replaces serialized KDEK envelopes.
/// </summary>
public static class DekEnvelopeStorage
{
    public static async Task<byte[]> ReadAllBytesAsync(string path, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(path)) throw new ArgumentException("A file path is required.", nameof(path));
        using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, true))
        using (var output = new MemoryStream())
        {
            await stream.CopyToAsync(output, 81920, cancellationToken).ConfigureAwait(false);
            return output.ToArray();
        }
    }

    public static byte[] ReadAllBytes(string path)
    {
        if (string.IsNullOrEmpty(path)) throw new ArgumentException("A file path is required.", nameof(path));
        return File.ReadAllBytes(path);
    }

    public static async Task CreateIfMissingAsync(string path, byte[] data, CancellationToken cancellationToken = default)
    {
        Validate(path, data);
        string fullPath = Path.GetFullPath(path);
        string directory = Path.GetDirectoryName(fullPath)!;
        Directory.CreateDirectory(directory);
        string tempPath = Path.Combine(directory, Path.GetRandomFileName());
        try
        {
            await WriteTempAsync(tempPath, data, cancellationToken).ConfigureAwait(false);
            try
            {
                File.Move(tempPath, fullPath);
            }
            catch (IOException) when (File.Exists(fullPath))
            {
                TryDelete(tempPath);
            }
        }
        catch
        {
            TryDelete(tempPath);
            throw;
        }
    }

    public static async Task ReplaceAtomicallyAsync(string path, byte[] data, CancellationToken cancellationToken = default)
    {
        Validate(path, data);
        string fullPath = Path.GetFullPath(path);
        string directory = Path.GetDirectoryName(fullPath)!;
        Directory.CreateDirectory(directory);
        string tempPath = Path.Combine(directory, Path.GetRandomFileName());
        try
        {
            await WriteTempAsync(tempPath, data, cancellationToken).ConfigureAwait(false);
            if (File.Exists(fullPath))
            {
                string backupPath = tempPath + ".bak";
                try
                {
                    File.Replace(tempPath, fullPath, backupPath, true);
                    TryDelete(backupPath);
                }
                catch (PlatformNotSupportedException)
                {
                    File.Replace(tempPath, fullPath, null, true);
                }
            }
            else
            {
                try
                {
                    File.Move(tempPath, fullPath);
                }
                catch (IOException) when (File.Exists(fullPath))
                {
                    File.Replace(tempPath, fullPath, null, true);
                }
            }
        }
        catch
        {
            TryDelete(tempPath);
            throw;
        }
    }

    public static void CreateIfMissing(string path, byte[] data)
    {
        Validate(path, data);
        string fullPath = Path.GetFullPath(path);
        string directory = Path.GetDirectoryName(fullPath)!;
        Directory.CreateDirectory(directory);
        string tempPath = Path.Combine(directory, Path.GetRandomFileName());
        try
        {
            File.WriteAllBytes(tempPath, data);
            try
            {
                File.Move(tempPath, fullPath);
            }
            catch (IOException) when (File.Exists(fullPath))
            {
                TryDelete(tempPath);
            }
        }
        catch
        {
            TryDelete(tempPath);
            throw;
        }
    }

    public static void ReplaceAtomically(string path, byte[] data)
    {
        Validate(path, data);
        string fullPath = Path.GetFullPath(path);
        string directory = Path.GetDirectoryName(fullPath)!;
        Directory.CreateDirectory(directory);
        string tempPath = Path.Combine(directory, Path.GetRandomFileName());
        try
        {
            File.WriteAllBytes(tempPath, data);
            if (File.Exists(fullPath))
            {
                string backupPath = tempPath + ".bak";
                File.Replace(tempPath, fullPath, backupPath, true);
                TryDelete(backupPath);
            }
            else
            {
                try
                {
                    File.Move(tempPath, fullPath);
                }
                catch (IOException) when (File.Exists(fullPath))
                {
                    File.Replace(tempPath, fullPath, null, true);
                }
            }
        }
        catch
        {
            TryDelete(tempPath);
            throw;
        }
    }

    private static void Validate(string path, byte[] data)
    {
        if (string.IsNullOrEmpty(path)) throw new ArgumentException("A file path is required.", nameof(path));
        if (data is null) throw new ArgumentNullException(nameof(data));
    }

    private static async Task WriteTempAsync(string path, byte[] data, CancellationToken cancellationToken)
    {
        using (var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, true))
        {
            await stream.WriteAsync(data, 0, data.Length, cancellationToken).ConfigureAwait(false);
            await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
}

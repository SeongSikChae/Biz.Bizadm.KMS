using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Diagnostics;
using System.Text;

namespace Biz.Bizadm.KMS.NetFramework.Tests;

[TestClass]
public sealed class RuntimeSetupTests
{
    private static readonly byte[] ZeroKey = new byte[32];
    private static readonly byte[] ZeroNonce = new byte[12];
    private static readonly string RepoRoot = FindRepoRoot();

    [TestMethod]
    public void TestHost_RunsOnNetFrameworkClr()
    {
        Assert.AreEqual(4, Environment.Version.Major);
    }

    [TestMethod]
    public void Aes256Gcm_MatchesNistKnownAnswerVector()
    {
        byte[] plaintext = new byte[16];
        byte[] ciphertextAndTag = Encrypt(ZeroKey, ZeroNonce, plaintext);
        byte[] expected = FromHex("cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919");

        CollectionAssert.AreEqual(expected, ciphertextAndTag);
        CollectionAssert.AreEqual(plaintext, Decrypt(ZeroKey, ZeroNonce, ciphertextAndTag));
    }

    [TestMethod]
    public void Aes256Gcm_EmptyPlaintextMatchesNistKnownAnswerVector()
    {
        byte[] ciphertextAndTag = Encrypt(ZeroKey, ZeroNonce, Array.Empty<byte>());

        CollectionAssert.AreEqual(
            FromHex("530f8afbc74536b9a963b4f1c4cb738b"),
            ciphertextAndTag);
        CollectionAssert.AreEqual(Array.Empty<byte>(), Decrypt(ZeroKey, ZeroNonce, ciphertextAndTag));
    }

    [TestMethod]
    public void Aes256Gcm_RejectsModifiedTagAndWrongKey()
    {
        byte[] ciphertextAndTag = Encrypt(ZeroKey, ZeroNonce, new byte[] { 1, 2, 3 });
        ciphertextAndTag[ciphertextAndTag.Length - 1] ^= 1;

        Assert.ThrowsException<InvalidCipherTextException>(
            () => Decrypt(ZeroKey, ZeroNonce, ciphertextAndTag));
        Assert.ThrowsException<InvalidCipherTextException>(
            () => Decrypt(Enumerable.Repeat((byte)1, 32).ToArray(), ZeroNonce, Encrypt(ZeroKey, ZeroNonce, new byte[] { 1, 2, 3 })));
    }

    [TestMethod]
    public void Net10AndNet48_DecryptEachOthersCiphertext_AndRejectTampering()
    {
        byte[] key = Enumerable.Range(0, 32).Select(static value => (byte)value).ToArray();
        byte[] plaintext = Encoding.UTF8.GetBytes("net10 and net48 cross-runtime test");
        string keyHex = ToHex(key);
        string plainHex = ToHex(plaintext);

        string net10CiphertextHex = RunHelper("InteropNet10", "encrypt", keyHex, plainHex);
        byte[] net10Ciphertext = FromHex(net10CiphertextHex);
        CollectionAssert.AreEqual(plaintext, FromHex(RunHelper("InteropNet48", "decrypt", keyHex, net10CiphertextHex)));

        string net48CiphertextHex = RunHelper("InteropNet48", "encrypt", keyHex, plainHex);
        byte[] net48Ciphertext = FromHex(net48CiphertextHex);
        CollectionAssert.AreEqual(plaintext, FromHex(RunHelper("InteropNet10", "decrypt", keyHex, net48CiphertextHex)));

        net48Ciphertext[net48Ciphertext.Length - 1] ^= 0x80;
        AssertHelperFailure("InteropNet10", "decrypt", keyHex, ToHex(net48Ciphertext));
        AssertHelperFailure("InteropNet48", "decrypt", keyHex, ToHex(net10Ciphertext.Select((value, index) => index == net10Ciphertext.Length - 1 ? (byte)(value ^ 0x01) : value).ToArray()));

        string emptyHex = RunHelper("InteropNet10", "encrypt", keyHex, string.Empty);
        CollectionAssert.AreEqual(Array.Empty<byte>(), FromHex(RunHelper("InteropNet48", "decrypt", keyHex, emptyHex)));
        emptyHex = RunHelper("InteropNet48", "encrypt", keyHex, string.Empty);
        CollectionAssert.AreEqual(Array.Empty<byte>(), FromHex(RunHelper("InteropNet10", "decrypt", keyHex, emptyHex)));
    }

    private static void AssertHelperFailure(string projectName, params string[] arguments)
    {
        ProcessResult result = RunProcess(GetHelperDll(projectName), arguments);
        Assert.AreNotEqual(0, result.ExitCode, $"{projectName} should reject modified ciphertext. stdout: {result.Stdout}; stderr: {result.Stderr}");
    }

    private static string RunHelper(string projectName, params string[] arguments)
    {
        ProcessResult result = RunProcess(GetHelperDll(projectName), arguments);
        Assert.AreEqual(0, result.ExitCode, $"{projectName} failed. stdout: {result.Stdout}; stderr: {result.Stderr}");
        return result.Stdout.Trim();
    }

    private static string GetHelperDll(string projectName)
    {
        string framework = projectName == "InteropNet10" ? "net10.0" : "net48";
        string extension = projectName == "InteropNet48" ? ".exe" : ".dll";
        return Path.Combine(RepoRoot, "Biz.Bizadm.KMS.NetFramework.Tests", projectName, "bin", "Debug", framework, projectName + extension);
    }

    private static ProcessResult RunProcess(string executable, string[] arguments)
    {
        bool isNetFrameworkExe = executable.EndsWith(".exe", StringComparison.OrdinalIgnoreCase);
        var startInfo = new ProcessStartInfo
        {
            FileName = isNetFrameworkExe ? executable : "dotnet",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        string quotedArguments = string.Join(" ", arguments.Select(static argument => "\"" + argument + "\""));
        startInfo.Arguments = isNetFrameworkExe ? quotedArguments : "\"" + executable + "\" " + quotedArguments;

        using Process process = Process.Start(startInfo) ?? throw new InvalidOperationException("Could not start helper process.");
        string stdout = process.StandardOutput.ReadToEnd();
        string stderr = process.StandardError.ReadToEnd();
        process.WaitForExit();
        return new ProcessResult(process.ExitCode, stdout, stderr);
    }

    private static string FindRepoRoot()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "Biz.Bizadm.KMS.slnx")))
            {
                return directory.FullName;
            }
            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException("Could not find the repository root from test output directory.");
    }

    private static string ToHex(byte[] value)
    {
        return BitConverter.ToString(value).Replace("-", string.Empty);
    }

    private sealed class ProcessResult
    {
        public ProcessResult(int exitCode, string stdout, string stderr)
        {
            ExitCode = exitCode;
            Stdout = stdout;
            Stderr = stderr;
        }

        public int ExitCode { get; }
        public string Stdout { get; }
        public string Stderr { get; }
    }

    private static byte[] FromHex(string value)
    {
        byte[] bytes = new byte[value.Length / 2];
        for (int i = 0; i < bytes.Length; i++)
        {
            bytes[i] = byte.Parse(value.Substring(i * 2, 2), System.Globalization.NumberStyles.HexNumber);
        }

        return bytes;
    }

    private static byte[] Encrypt(byte[] key, byte[] nonce, byte[] plaintext)
    {
        var cipher = new GcmBlockCipher(new AesEngine());
        cipher.Init(true, new AeadParameters(new KeyParameter(key), 128, nonce));
        byte[] output = new byte[cipher.GetOutputSize(plaintext.Length)];
        int length = cipher.ProcessBytes(plaintext, 0, plaintext.Length, output, 0);
        length += cipher.DoFinal(output, length);
        Array.Resize(ref output, length);
        return output;
    }

    private static byte[] Decrypt(byte[] key, byte[] nonce, byte[] ciphertextAndTag)
    {
        var cipher = new GcmBlockCipher(new AesEngine());
        cipher.Init(false, new AeadParameters(new KeyParameter(key), 128, nonce));
        byte[] output = new byte[cipher.GetOutputSize(ciphertextAndTag.Length)];
        int length = cipher.ProcessBytes(ciphertextAndTag, 0, ciphertextAndTag.Length, output, 0);
        length += cipher.DoFinal(output, length);
        Array.Resize(ref output, length);
        return output;
    }
}

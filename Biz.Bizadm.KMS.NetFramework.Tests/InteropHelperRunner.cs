using System.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Biz.Bizadm.KMS.NetFramework.Tests;

internal static class InteropHelperRunner
{
    private static readonly string RepoRoot = FindRepoRoot();

    public static string RunHelper(string projectName, params string[] arguments)
    {
        ProcessResult result = RunProcess(GetHelperPath(projectName), arguments);
        Assert.AreEqual(0, result.ExitCode, $"{projectName} failed. stdout: {result.Stdout}; stderr: {result.Stderr}");
        return result.Stdout.Trim();
    }

    public static void AssertHelperFailure(string projectName, params string[] arguments)
    {
        ProcessResult result = RunProcess(GetHelperPath(projectName), arguments);
        Assert.AreNotEqual(0, result.ExitCode, $"{projectName} should fail. stdout: {result.Stdout}; stderr: {result.Stderr}");
    }

    public static ProcessResult RunProcess(string executable, string[] arguments)
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

    public static string GetHelperPath(string projectName)
    {
        string framework = projectName == "InteropNet10" ? "net10.0" : "net48";
        string extension = projectName == "InteropNet48" ? ".exe" : ".dll";
        string configuration = DetectConfiguration();
        string path = Path.Combine(
            RepoRoot,
            "Biz.Bizadm.KMS.NetFramework.Tests",
            projectName,
            "bin",
            configuration,
            framework,
            projectName + extension);
        if (File.Exists(path))
        {
            return path;
        }

        string fallback = Path.Combine(
            RepoRoot,
            "Biz.Bizadm.KMS.NetFramework.Tests",
            projectName,
            "bin",
            configuration == "Debug" ? "Release" : "Debug",
            framework,
            projectName + extension);
        if (File.Exists(fallback))
        {
            return fallback;
        }

        throw new FileNotFoundException("Interop helper not found at " + path + " or " + fallback);
    }

    public static string ToHex(byte[] value)
        => BitConverter.ToString(value).Replace("-", string.Empty);

    public static byte[] FromHex(string value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return Array.Empty<byte>();
        }

        byte[] bytes = new byte[value.Length / 2];
        for (int i = 0; i < bytes.Length; i++)
        {
            bytes[i] = byte.Parse(value.Substring(i * 2, 2), System.Globalization.NumberStyles.HexNumber);
        }

        return bytes;
    }

    private static string DetectConfiguration()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null)
        {
            if (string.Equals(directory.Name, "Debug", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(directory.Name, "Release", StringComparison.OrdinalIgnoreCase))
            {
                return directory.Name;
            }

            directory = directory.Parent;
        }

        return "Debug";
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

    public sealed class ProcessResult
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
}

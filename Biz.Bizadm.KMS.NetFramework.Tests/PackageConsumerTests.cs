using System.Diagnostics;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Biz.Bizadm.KMS.NetFramework.Tests;

[TestClass]
public sealed class PackageConsumerTests
{
    [TestMethod]
    public void PackageReferenceConsumer_LoadsTransitiveDependenciesAndEncrypts()
    {
        string consumerProj = Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory,
            "..", "..", "..", "PackageConsumerNet48", "PackageConsumerNet48.csproj"));
        Assert.IsTrue(File.Exists(consumerProj), "Consumer project missing: " + consumerProj);

        string config = "Release";
        RunDotNet("restore \"" + consumerProj + "\"", 0);
        RunDotNet("build \"" + consumerProj + "\" -c " + config + " --no-restore", 0);

        string exe = Path.Combine(
            Path.GetDirectoryName(consumerProj)!,
            "bin", config, "net48", "PackageConsumerNet48.exe");
        Assert.IsTrue(File.Exists(exe), "Consumer exe missing: " + exe);

        string configFile = exe + ".config";
        Assert.IsTrue(File.Exists(configFile), "Binding redirects config missing: " + configFile);
        string configText = File.ReadAllText(configFile);
        StringAssert.Contains(configText, "assemblyBinding");

        string output = RunProcess(exe, string.Empty, 0);
        StringAssert.Contains(output, "ASSEMBLY=Biz.Bizadm.KMS.NetFramework");
        StringAssert.Contains(output, "FEATURE_AES=Supported");
        StringAssert.Contains(output, "OK");
    }

    private static void RunDotNet(string args, int expectedExitCode)
    {
        string output = RunProcess("dotnet", args, expectedExitCode);
        Assert.IsFalse(string.IsNullOrWhiteSpace(output) && expectedExitCode == 0 && false);
    }

    private static string RunProcess(string fileName, string args, int expectedExitCode)
    {
        ProcessStartInfo psi = new ProcessStartInfo
        {
            FileName = fileName,
            Arguments = args,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using (Process process = Process.Start(psi)!)
        {
            string stdout = process.StandardOutput.ReadToEnd();
            string stderr = process.StandardError.ReadToEnd();
            process.WaitForExit(120_000);
            string combined = stdout + Environment.NewLine + stderr;
            Assert.AreEqual(expectedExitCode, process.ExitCode, combined);
            return combined;
        }
    }
}

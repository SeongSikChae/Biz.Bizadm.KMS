using Azure.Identity;
using Biz.Bizadm.KMS.Cipher;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Biz.Bizadm.KMSTest.Cipher
{
    [TestClass]
    [TestCategory("Manual")]
    [DoNotParallelize]
    [OSCondition(OperatingSystems.Windows)]
    public sealed class AzureKeyVaultKekCipherPerformanceTests
    {
        private const int PayloadSize = 32;

        public TestContext TestContext { get; set; } = null!;

        [TestMethod]
        [Timeout(300_000, CooperativeCancellation = true)]
        public async Task SequentialRoundtrip_LatencyIsBounded()
        {
            const int warmup = 3;
            const int operations = 30;
            byte[] plain = CreatePlain();
            long[] latenciesTicks = new long[operations];

            using AzureKeyVaultKekCipher cipher = await CreateCipherAsync(TestContext.CancellationToken);
            await RunRoundtripsAsync(cipher, plain, warmup, TestContext.CancellationToken);

            for (int i = 0; i < operations; i++)
            {
                long start = Stopwatch.GetTimestamp();
                byte[] encrypted = await cipher.EncryptAsync(plain, TestContext.CancellationToken);
                byte[] decrypted = await cipher.DecryptAsync(encrypted, TestContext.CancellationToken);
                latenciesTicks[i] = Stopwatch.GetTimestamp() - start;

                if (!plain.AsSpan().SequenceEqual(decrypted))
                    throw new AssertFailedException("복호화 결과가 원문과 일치하지 않습니다.");
            }

            Array.Sort(latenciesTicks);
            double p50 = ToMilliseconds(latenciesTicks[operations / 2]);
            double p95 = ToMilliseconds(latenciesTicks[(int)(operations * 0.95)]);
            double p99 = ToMilliseconds(latenciesTicks[(int)(operations * 0.99)]);
            double max = ToMilliseconds(latenciesTicks[^1]);
            double elapsedSec = latenciesTicks.Sum() / (double)Stopwatch.Frequency;
            double opsPerSecond = operations / elapsedSec;

            TestContext.WriteLine($"ops={operations}");
            TestContext.WriteLine($"p50={p50:F3}ms, p95={p95:F3}ms, p99={p99:F3}ms, max={max:F3}ms");
            TestContext.WriteLine($"throughput={opsPerSecond:N1} ops/s");

            Assert.IsLessThan(2_000, p50, $"p50 지연이 {p50:F3}ms 입니다.");
            Assert.IsLessThan(5_000, p95, $"p95 지연이 {p95:F3}ms 입니다.");
            Assert.IsLessThan(10_000, p99, $"p99 지연이 {p99:F3}ms 입니다.");
        }

        [TestMethod]
        [Timeout(300_000, CooperativeCancellation = true)]
        public async Task SequentialRoundtrip_Gen2GcLoadIsBounded()
        {
            const int warmup = 3;
            const int measured = 20;
            byte[] plain = CreatePlain();

            using AzureKeyVaultKekCipher cipher = await CreateCipherAsync(TestContext.CancellationToken);
            await RunRoundtripsAsync(cipher, plain, warmup, TestContext.CancellationToken);
            ForceFullGc();

            int gen0Before = GC.CollectionCount(0);
            int gen1Before = GC.CollectionCount(1);
            int gen2Before = GC.CollectionCount(2);
            long allocatedBefore = GC.GetAllocatedBytesForCurrentThread();

            await RunRoundtripsAsync(cipher, plain, measured, TestContext.CancellationToken);

            int gen0 = GC.CollectionCount(0) - gen0Before;
            int gen1 = GC.CollectionCount(1) - gen1Before;
            int gen2 = GC.CollectionCount(2) - gen2Before;
            long allocated = GC.GetAllocatedBytesForCurrentThread() - allocatedBefore;
            double bytesPerRoundtrip = allocated / (double)measured;

            TestContext.WriteLine($"Gen0={gen0}, Gen1={gen1}, Gen2={gen2}");
            TestContext.WriteLine($"allocated={allocated:N0}, bytes/roundtrip={bytesPerRoundtrip:N1}");

            Assert.IsLessThan(5, gen2, $"Gen2 GC가 {gen2}회 발생했습니다.");
            Assert.IsLessThan(512 * 1024, bytesPerRoundtrip, $"라운드트립당 할당량이 {bytesPerRoundtrip:N1} bytes 입니다.");
        }

        private static async Task<AzureKeyVaultKekCipher> CreateCipherAsync(CancellationToken cancellationToken)
        {
            using X509Store store = new(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

            X509Certificate2Collection certificates = store.Certificates.Find(
                X509FindType.FindByThumbprint,
                Environment.GetEnvironmentVariable("AZURE_KEY_VAULT_THUMBPRINT") ?? string.Empty,
                validOnly: false);

            using X509Certificate2 certificate = certificates.OfType<X509Certificate2>()
                .FirstOrDefault(x => x.HasPrivateKey)
                ?? throw new InvalidOperationException("개인 키가 포함된 인증서를 찾을 수 없습니다.");

            ClientCertificateCredential credential = new(
                Environment.GetEnvironmentVariable("AZURE_TENANTID"),
                Environment.GetEnvironmentVariable("AZURE_CLIENT_ID"),
                certificate);

            string keyName = $"TEST-KEY-PERF-{Guid.NewGuid():N}";
            return await AzureKeyVaultKekCipher.CreateAsync(
                new Uri(Environment.GetEnvironmentVariable("AZURE_KEY_VAULT_URL") ?? string.Empty),
                credential,
                keyName,
                cancellationToken: cancellationToken);
        }

        private static byte[] CreatePlain()
        {
            byte[] plain = new byte[PayloadSize];
            RandomNumberGenerator.Fill(plain);
            return plain;
        }

        private static async Task RunRoundtripsAsync(
            AzureKeyVaultKekCipher cipher,
            byte[] plain,
            int count,
            CancellationToken cancellationToken)
        {
            for (int i = 0; i < count; i++)
            {
                byte[] encrypted = await cipher.EncryptAsync(plain, cancellationToken);
                byte[] decrypted = await cipher.DecryptAsync(encrypted, cancellationToken);
                if (decrypted.Length != plain.Length)
                    throw new AssertFailedException("복호화 길이가 원문과 일치하지 않습니다.");
            }
        }

        private static void ForceFullGc()
        {
            GC.Collect(GC.MaxGeneration, GCCollectionMode.Forced, blocking: true, compacting: true);
            GC.WaitForPendingFinalizers();
            GC.Collect(GC.MaxGeneration, GCCollectionMode.Forced, blocking: true, compacting: true);
        }

        private static double ToMilliseconds(long ticks)
            => ticks * 1000.0 / Stopwatch.Frequency;
    }
}

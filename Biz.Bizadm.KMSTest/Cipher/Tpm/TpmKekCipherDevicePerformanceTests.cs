using Biz.Bizadm.KMS.Cipher.Tpm;
using System.Diagnostics;
using System.Security.Cryptography;
using Tpm2Lib;

namespace Biz.Bizadm.KMSTest.Cipher.Tpm
{
    public abstract class TpmKekCipherDevicePerformanceTests
    {
        protected const int PayloadSize = 32;
        // TSS.Net RSA Encrypt/Decrypt 마샬링 실측 ~376KiB/roundtrip
        protected const int MaxBytesPerRoundtrip = 512 * 1024;

        protected static readonly byte[] Password = "kms-tpm-perf-password"u8.ToArray();

        public TestContext TestContext { get; set; } = null!;

        protected abstract Tpm2Device CreateConnectedDevice();

        protected virtual int MemoryWarmup => 20;
        protected virtual int MemoryBatch => 100;
        protected virtual int GcWarmup => 20;
        protected virtual int GcMeasured => 200;
        protected virtual int LatencyWarmup => 10;
        protected virtual int LatencyOperations => 100;
        protected virtual double MaxP50Ms => 200;
        protected virtual double MaxP95Ms => 500;
        protected virtual double MaxP99Ms => 1000;

        [TestMethod]
        [Timeout(300_000, CooperativeCancellation = true)]
        public void SequentialRoundtrip_DoesNotLeakManagedMemory()
        {
            int warmup = MemoryWarmup;
            int batch = MemoryBatch;
            byte[] plain = CreatePlain();
            FileInfo kekFile = NewKekFile();

            try
            {
                using TpmKekCipher cipher = CreateCipher(kekFile);
                RunRoundtrips(cipher, plain, warmup);
                ForceFullGc();
                long baseline = GC.GetTotalMemory(true);

                RunRoundtrips(cipher, plain, batch);
                ForceFullGc();
                long afterFirst = GC.GetTotalMemory(true);

                RunRoundtrips(cipher, plain, batch);
                ForceFullGc();
                long afterSecond = GC.GetTotalMemory(true);

                long firstGrowth = Math.Max(0, afterFirst - baseline);
                long secondGrowth = Math.Max(0, afterSecond - afterFirst);

                TestContext.WriteLine($"baseline={baseline:N0}, afterFirst={afterFirst:N0}, afterSecond={afterSecond:N0}");
                TestContext.WriteLine($"firstGrowth={firstGrowth:N0}, secondGrowth={secondGrowth:N0}");

                Assert.IsLessThan(4 * 1024 * 1024, secondGrowth, $"두 번째 배치에서 관리 메모리가 {secondGrowth:N0} bytes 증가했습니다.");
                Assert.IsLessThan(16 * 1024 * 1024, afterSecond - baseline, $"전체 관리 메모리 증가량이 {(afterSecond - baseline):N0} bytes 입니다.");
            }
            finally
            {
                DeleteQuietly(kekFile);
            }
        }

        [TestMethod]
        [Timeout(300_000, CooperativeCancellation = true)]
        public void SequentialRoundtrip_Gen2GcLoadIsBounded()
        {
            int warmup = GcWarmup;
            int measured = GcMeasured;
            byte[] plain = CreatePlain();
            FileInfo kekFile = NewKekFile();

            try
            {
                using TpmKekCipher cipher = CreateCipher(kekFile);
                RunRoundtrips(cipher, plain, warmup);
                ForceFullGc();

                int gen0Before = GC.CollectionCount(0);
                int gen1Before = GC.CollectionCount(1);
                int gen2Before = GC.CollectionCount(2);
                long allocatedBefore = GC.GetAllocatedBytesForCurrentThread();

                RunRoundtrips(cipher, plain, measured);

                int gen0 = GC.CollectionCount(0) - gen0Before;
                int gen1 = GC.CollectionCount(1) - gen1Before;
                int gen2 = GC.CollectionCount(2) - gen2Before;
                long allocated = GC.GetAllocatedBytesForCurrentThread() - allocatedBefore;
                double bytesPerRoundtrip = allocated / (double)measured;

                TestContext.WriteLine($"Gen0={gen0}, Gen1={gen1}, Gen2={gen2}");
                TestContext.WriteLine($"allocated={allocated:N0}, bytes/roundtrip={bytesPerRoundtrip:N1}");

                Assert.IsLessThan(5, gen2, $"Gen2 GC가 {gen2}회 발생했습니다.");
                Assert.IsLessThan(MaxBytesPerRoundtrip, bytesPerRoundtrip, $"라운드트립당 할당량이 {bytesPerRoundtrip:N1} bytes 입니다.");
            }
            finally
            {
                DeleteQuietly(kekFile);
            }
        }

        [TestMethod]
        [Timeout(300_000, CooperativeCancellation = true)]
        public void SequentialRoundtrip_LatencyIsBounded()
        {
            int operations = LatencyOperations;
            byte[] plain = CreatePlain();
            long[] latenciesTicks = new long[operations];
            FileInfo kekFile = NewKekFile();

            try
            {
                using TpmKekCipher cipher = CreateCipher(kekFile);
                RunRoundtrips(cipher, plain, LatencyWarmup);

                for (int i = 0; i < operations; i++)
                {
                    long start = Stopwatch.GetTimestamp();
                    byte[] encrypted = cipher.Encrypt(plain);
                    byte[] decrypted = cipher.Decrypt(encrypted);
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

                Assert.IsLessThan(MaxP50Ms, p50, $"p50 지연이 {p50:F3}ms 입니다.");
                Assert.IsLessThan(MaxP95Ms, p95, $"p95 지연이 {p95:F3}ms 입니다.");
                Assert.IsLessThan(MaxP99Ms, p99, $"p99 지연이 {p99:F3}ms 입니다.");
            }
            finally
            {
                DeleteQuietly(kekFile);
            }
        }

        protected virtual TpmKekOptions Options => new();

        protected TpmKekCipher CreateCipher(FileInfo kekBlobFile)
            => TpmKekCipher.Create(
                CreateConnectedDevice(),
                new FixedPasswordCredentialProvider(Password),
                kekBlobFile,
                Options);

        protected static byte[] CreatePlain()
        {
            byte[] plain = new byte[PayloadSize];
            RandomNumberGenerator.Fill(plain);
            return plain;
        }

        protected static void RunRoundtrips(TpmKekCipher cipher, byte[] plain, int count)
        {
            for (int i = 0; i < count; i++)
            {
                byte[] encrypted = cipher.Encrypt(plain);
                byte[] decrypted = cipher.Decrypt(encrypted);
                if (decrypted.Length != plain.Length)
                    throw new AssertFailedException("복호화 길이가 원문과 일치하지 않습니다.");
            }
        }

        protected static FileInfo NewKekFile()
            => new(Path.Combine(Path.GetTempPath(), $"kms-tpm-kek-perf-{Guid.NewGuid():N}.blob"));

        protected static void DeleteQuietly(FileInfo file)
        {
            try
            {
                file.Refresh();
                if (file.Exists)
                    file.Delete();
            }
            catch (IOException)
            {
            }
        }

        protected static void ForceFullGc()
        {
            GC.Collect(GC.MaxGeneration, GCCollectionMode.Forced, blocking: true, compacting: true);
            GC.WaitForPendingFinalizers();
            GC.Collect(GC.MaxGeneration, GCCollectionMode.Forced, blocking: true, compacting: true);
        }

        protected static double ToMilliseconds(long ticks)
            => ticks * 1000.0 / Stopwatch.Frequency;
    }

    [TestClass]
    [TestCategory("Manual")]
    [DoNotParallelize]
    [OSCondition(OperatingSystems.Windows)]
    public sealed class TpmKekCipherAesTbsDevicePerformanceTests : TpmKekCipherDevicePerformanceTests
    {
        // 실물 TPM RSA-2048은 소프트웨어 TPM보다 한 자릿수 이상 느리다.
        protected override int MemoryWarmup => 5;
        protected override int MemoryBatch => 20;
        protected override int GcWarmup => 5;
        protected override int GcMeasured => 30;
        protected override int LatencyWarmup => 3;
        protected override int LatencyOperations => 20;
        protected override double MaxP50Ms => 2_000;
        protected override double MaxP95Ms => 4_000;
        protected override double MaxP99Ms => 8_000;

        protected override Tpm2Device CreateConnectedDevice()
        {
            TbsDevice device = new();
            device.Connect();
            return device;
        }
    }

    [TestClass]
    [TestCategory("Manual")]
    [DoNotParallelize]
    [OSCondition(OperatingSystems.Windows)]
    public sealed class TpmKekCipherRsaOaepTbsDevicePerformanceTests : TpmKekCipherDevicePerformanceTests
    {
        protected override TpmKekOptions Options => new() { WrapMode = TpmKekWrapMode.RsaOaep256 };

        protected override int MemoryWarmup => 5;
        protected override int MemoryBatch => 20;
        protected override int GcWarmup => 5;
        protected override int GcMeasured => 30;
        protected override int LatencyWarmup => 3;
        protected override int LatencyOperations => 20;
        protected override double MaxP50Ms => 2_000;
        protected override double MaxP95Ms => 4_000;
        protected override double MaxP99Ms => 8_000;

        protected override Tpm2Device CreateConnectedDevice()
        {
            TbsDevice device = new();
            device.Connect();
            return device;
        }
    }
}

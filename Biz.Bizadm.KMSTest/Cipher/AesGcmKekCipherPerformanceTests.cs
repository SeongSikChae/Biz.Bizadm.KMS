using Biz.Bizadm.KMS.Cipher;
using System.Diagnostics;
using System.Security.Cryptography;

namespace Biz.Bizadm.KMSTest.Cipher
{
    [TestClass]
    [DoNotParallelize]
    public sealed class AesGcmKekCipherPerformanceTests
    {
        private const int Iterations = 10_000;
        private const int PayloadSize = 32;

        private static readonly byte[] Password = "kms-perf-password"u8.ToArray();
        private static readonly byte[] Salt = [16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1];

        public TestContext TestContext { get; set; } = null!;

        private static AesGcmKekCipher CreateCipher()
            => new(Password, Salt, Iterations);

        private static byte[] CreatePlain()
        {
            byte[] plain = new byte[PayloadSize];
            RandomNumberGenerator.Fill(plain);
            return plain;
        }

        [TestMethod]
        [Timeout(60_000, CooperativeCancellation = true)]
        public void SequentialRoundtrip_DoesNotLeakManagedMemory()
        {
            const int warmup = 2_000;
            const int batch = 20_000;
            byte[] plain = CreatePlain();

            using AesGcmKekCipher cipher = CreateCipher();
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

            Assert.IsLessThan(2 * 1024 * 1024, secondGrowth, $"두 번째 배치에서 관리 메모리가 {secondGrowth:N0} bytes 증가했습니다.");
            Assert.IsLessThan(8 * 1024 * 1024, afterSecond - baseline, $"전체 관리 메모리 증가량이 {(afterSecond - baseline):N0} bytes 입니다.");
        }

        [TestMethod]
        [Timeout(60_000, CooperativeCancellation = true)]
        public void SequentialRoundtrip_Gen2GcLoadIsBounded()
        {
            const int warmup = 2_000;
            const int measured = 50_000;
            byte[] plain = CreatePlain();

            using AesGcmKekCipher cipher = CreateCipher();
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
            Assert.IsLessThan(1024, bytesPerRoundtrip, $"라운드트립당 할당량이 {bytesPerRoundtrip:N1} bytes 입니다.");
        }

        [TestMethod]
        [Timeout(90_000, CooperativeCancellation = true)]
        public void HighVolumeConcurrentRoundtrip_LatencyIsBounded()
        {
            const int operations = 40_000;
            int degree = Math.Max(4, Environment.ProcessorCount * 2);
            byte[] plain = CreatePlain();
            long[] latenciesTicks = new long[operations];

            using AesGcmKekCipher cipher = CreateCipher();
            RunRoundtrips(cipher, plain, 1_000);

            Parallel.For(0, operations, new ParallelOptions { MaxDegreeOfParallelism = degree }, i =>
            {
                long start = Stopwatch.GetTimestamp();
                byte[] encrypted = cipher.Encrypt(plain);
                byte[] decrypted = cipher.Decrypt(encrypted);
                latenciesTicks[i] = Stopwatch.GetTimestamp() - start;

                if (!plain.AsSpan().SequenceEqual(decrypted))
                    throw new AssertFailedException("복호화 결과가 원문과 일치하지 않습니다.");
            });

            Array.Sort(latenciesTicks);
            double p50 = ToMilliseconds(latenciesTicks[operations / 2]);
            double p95 = ToMilliseconds(latenciesTicks[(int)(operations * 0.95)]);
            double p99 = ToMilliseconds(latenciesTicks[(int)(operations * 0.99)]);
            double max = ToMilliseconds(latenciesTicks[^1]);
            double opsPerSecond = operations / (latenciesTicks.Sum() / (double)Stopwatch.Frequency / degree);

            TestContext.WriteLine($"ops={operations}, degree={degree}");
            TestContext.WriteLine($"p50={p50:F3}ms, p95={p95:F3}ms, p99={p99:F3}ms, max={max:F3}ms");
            TestContext.WriteLine($"approx throughput={opsPerSecond:N0} ops/s");

            Assert.IsLessThan(2.0, p50, $"p50 지연이 {p50:F3}ms 입니다.");
            Assert.IsLessThan(10.0, p95, $"p95 지연이 {p95:F3}ms 입니다.");
            Assert.IsLessThan(30.0, p99, $"p99 지연이 {p99:F3}ms 입니다.");
        }

        [TestMethod]
        [Timeout(90_000, CooperativeCancellation = true)]
        public void HighVolumeConcurrentRoundtrip_DoesNotLeakManagedMemory()
        {
            const int warmup = 4_000;
            const int batch = 30_000;
            int degree = Math.Max(4, Environment.ProcessorCount * 2);
            byte[] plain = CreatePlain();

            using AesGcmKekCipher cipher = CreateCipher();
            RunConcurrentRoundtrips(cipher, plain, warmup, degree);
            ForceFullGc();
            long baseline = GC.GetTotalMemory(true);

            RunConcurrentRoundtrips(cipher, plain, batch, degree);
            ForceFullGc();
            long afterFirst = GC.GetTotalMemory(true);

            RunConcurrentRoundtrips(cipher, plain, batch, degree);
            ForceFullGc();
            long afterSecond = GC.GetTotalMemory(true);

            long secondGrowth = Math.Max(0, afterSecond - afterFirst);

            TestContext.WriteLine($"baseline={baseline:N0}, afterFirst={afterFirst:N0}, afterSecond={afterSecond:N0}");
            TestContext.WriteLine($"secondGrowth={secondGrowth:N0}");

            Assert.IsLessThan(4 * 1024 * 1024, secondGrowth, $"대량 동시 요청 두 번째 배치에서 관리 메모리가 {secondGrowth:N0} bytes 증가했습니다.");
        }

        private static void RunRoundtrips(AesGcmKekCipher cipher, byte[] plain, int count)
        {
            for (int i = 0; i < count; i++)
            {
                byte[] encrypted = cipher.Encrypt(plain);
                byte[] decrypted = cipher.Decrypt(encrypted);
                if (decrypted.Length != plain.Length)
                    throw new AssertFailedException("복호화 길이가 원문과 일치하지 않습니다.");
            }
        }

        private static void RunConcurrentRoundtrips(AesGcmKekCipher cipher, byte[] plain, int count, int degree)
        {
            Parallel.For(0, count, new ParallelOptions { MaxDegreeOfParallelism = degree }, _ =>
            {
                byte[] encrypted = cipher.Encrypt(plain);
                cipher.Decrypt(encrypted);
            });
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

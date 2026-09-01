using Biz.Bizadm.KMS.Pkcs11.Cipher;
using System.Diagnostics;
using System.Security.Cryptography;

namespace Biz.Bizadm.KMSTest.Cipher.Pkcs11
{
    [TestClass]
    [TestCategory("Manual")]
    [DoNotParallelize]
    public sealed class Pkcs11KekCipherSoftHsmPerformanceTests
    {
        private const int PayloadSize = 32;

        public TestContext TestContext { get; set; } = null!;

        [TestMethod]
        [Timeout(300_000, CooperativeCancellation = true)]
        public void SequentialRoundtrip_LatencyIsBounded()
        {
            const int warmup = 3;
            const int operations = 30;
            byte[] plain = CreatePlain();
            long[] latenciesTicks = new long[operations];

            using Pkcs11LibraryContext context = SoftHsmPkcs11TestProfile.CreateContext();
            string keyLabel = SoftHsmPkcs11TestProfile.NewKeyLabel("kms-softhsm-perf");
            using Pkcs11KekCipher cipher = SoftHsmPkcs11TestProfile.CreateCipher(context, keyLabel);

            RunRoundtrips(cipher, plain, warmup);

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

            TestContext.WriteLine("profile=SoftHSM2-2.5.0 CKM_RSA_PKCS RSA-2048");
            TestContext.WriteLine($"ops={operations}");
            TestContext.WriteLine($"p50={p50:F3}ms, p95={p95:F3}ms, p99={p99:F3}ms, max={max:F3}ms");
            TestContext.WriteLine($"throughput={opsPerSecond:N1} ops/s");

            Assert.IsLessThan(5_000, p50, $"p50 지연이 {p50:F3}ms 입니다.");
            Assert.IsLessThan(15_000, p95, $"p95 지연이 {p95:F3}ms 입니다.");
            Assert.IsLessThan(30_000, p99, $"p99 지연이 {p99:F3}ms 입니다.");
        }

        private static void RunRoundtrips(Pkcs11KekCipher cipher, byte[] plain, int count)
        {
            for (int i = 0; i < count; i++)
            {
                byte[] encrypted = cipher.Encrypt(plain);
                byte[] decrypted = cipher.Decrypt(encrypted);
                if (!plain.AsSpan().SequenceEqual(decrypted))
                    throw new AssertFailedException("워밍업 라운드트립이 실패했습니다.");
            }
        }

        private static byte[] CreatePlain()
        {
            byte[] plain = new byte[PayloadSize];
            RandomNumberGenerator.Fill(plain);
            return plain;
        }

        private static double ToMilliseconds(long ticks)
            => ticks * 1000.0 / Stopwatch.Frequency;
    }
}

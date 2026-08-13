using System.Buffers.Binary;
using System.Net.Sockets;
using Tpm2Lib;

namespace Biz.Bizadm.KMS.Cipher.Tpm
{
    /// <summary>
    /// Rocky Linux swtpm TCP 프론트엔드용 디바이스.
    /// 명령 포트에는 raw TPM 프레임을 보내고, 제어 채널(port+1)은 swtpm control protocol을 사용한다.
    /// Microsoft <see cref="TcpTpmDevice"/>의 mssim handshake와는 호환되지 않는다.
    /// </summary>
    public sealed class SwtpmTpmDevice : Tpm2Device
    {
        private const int DefaultTimeoutMs = 15_000;
        private const int ControlTimeoutMs = 2_000;
        private const uint CmdSetLocality = 5;
        private const uint TpmRcSuccess = 0;
        private const uint TpmRcInitialize = 0x100;

        private static readonly byte[] StartupClear =
        [
            0x80, 0x01,
            0x00, 0x00, 0x00, 0x0C,
            0x00, 0x00, 0x01, 0x44,
            0x00, 0x00
        ];

        private readonly string host;
        private readonly int commandPort;
        private readonly int controlPort;
        private readonly int timeoutMs;
        private TcpClient? commandClient;
        private NetworkStream? commandStream;

        public SwtpmTpmDevice(string host, int commandPort, int timeoutMs = DefaultTimeoutMs)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(host);
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(commandPort);
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(timeoutMs);

            this.host = host;
            this.commandPort = commandPort;
            controlPort = commandPort + 1;
            this.timeoutMs = timeoutMs;
            NeedsHMAC = false;
        }

        public override void Connect()
        {
            // --flags not-need-init 이므로 CMD_INIT은 보내지 않는다.
            // startup-clear가 없으면 TPM2_Startup(SU_CLEAR)이 필요하다.
            EnsureCommandConnected();

            DispatchCommand(new CommandModifier(), StartupClear, out byte[] response);
            uint rc = ReadResponseCode(response);
            if (rc is not TpmRcSuccess and not TpmRcInitialize)
                throw new IOException($"swtpm TPM2_Startup failed with TPM_RC 0x{rc:X}.");
        }

        public override void Close()
        {
            CloseCommand();
        }

        public override void DispatchCommand(CommandModifier active, byte[] inBuf, out byte[] outBuf)
        {
            ArgumentNullException.ThrowIfNull(inBuf);

            if (active.ActiveLocality != 0)
                TryControlSetLocality(active.ActiveLocality);

            try
            {
                outBuf = SendCommand(inBuf);
            }
            catch (IOException)
            {
                CloseCommand();
                outBuf = SendCommand(inBuf);
            }
        }

        public override bool PlatformAvailable() => false;

        public override bool PowerCtlAvailable() => false;

        public override bool LocalityCtlAvailable() => true;

        public override bool NvCtlAvailable() => false;

        protected override void Dispose(bool disposing)
        {
            if (disposing)
                Close();

            base.Dispose(disposing);
        }

        private byte[] SendCommand(byte[] inBuf)
        {
            EnsureCommandConnected();
            commandStream!.Write(inBuf, 0, inBuf.Length);
            return ReadTpmResponse(commandStream);
        }

        private void EnsureCommandConnected()
        {
            if (commandStream is { CanWrite: true })
                return;

            CloseCommand();
            commandClient = ConnectTcp(commandPort, timeoutMs);
            commandStream = commandClient.GetStream();
        }

        private void CloseCommand()
        {
            commandStream?.Dispose();
            commandClient?.Dispose();
            commandStream = null;
            commandClient = null;
        }

        private void TryControlSetLocality(byte locality)
        {
            try
            {
                SendControl(CmdSetLocality, [locality]);
            }
            catch (IOException)
            {
            }
            catch (SocketException)
            {
            }
        }

        private void SendControl(uint command, byte[] payload)
        {
            byte[] request = new byte[4 + payload.Length];
            BinaryPrimitives.WriteUInt32BigEndian(request, command);
            payload.CopyTo(request, 4);

            using TcpClient client = ConnectTcp(controlPort, ControlTimeoutMs);
            using NetworkStream stream = client.GetStream();
            stream.Write(request, 0, request.Length);

            byte[] response = new byte[4];
            ReadExact(stream, response);
            uint rc = BinaryPrimitives.ReadUInt32BigEndian(response);
            if (rc != 0)
                throw new IOException($"swtpm control command {command} failed with {rc}.");
        }

        private TcpClient ConnectTcp(int port, int connectTimeoutMs)
        {
            TcpClient client = new()
            {
                NoDelay = true,
                ReceiveTimeout = connectTimeoutMs,
                SendTimeout = connectTimeoutMs
            };

            try
            {
                if (!client.ConnectAsync(host, port).Wait(connectTimeoutMs))
                    throw new IOException($"swtpm {host}:{port} 연결이 시간 초과되었습니다.");
            }
            catch
            {
                client.Dispose();
                throw;
            }

            return client;
        }

        private static byte[] ReadTpmResponse(NetworkStream stream)
        {
            byte[] header = new byte[10];
            ReadExact(stream, header);

            uint size = BinaryPrimitives.ReadUInt32BigEndian(header.AsSpan(2, 4));
            if (size < 10)
                throw new InvalidDataException($"Invalid TPM response size: {size}.");

            byte[] response = new byte[size];
            header.CopyTo(response, 0);
            if (size > 10)
                ReadExact(stream, response.AsSpan(10));

            return response;
        }

        private static void ReadExact(NetworkStream stream, Span<byte> buffer)
        {
            while (!buffer.IsEmpty)
            {
                int read = stream.Read(buffer);
                if (read == 0)
                    throw new IOException("swtpm 연결이 예기치 않게 종료되었습니다.");

                buffer = buffer[read..];
            }
        }

        private static uint ReadResponseCode(byte[] response)
        {
            if (response.Length < 10)
                throw new InvalidDataException("TPM response is too short.");

            return BinaryPrimitives.ReadUInt32BigEndian(response.AsSpan(6, 4));
        }
    }
}

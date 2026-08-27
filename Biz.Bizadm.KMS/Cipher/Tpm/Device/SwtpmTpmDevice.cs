using System.Buffers.Binary;
using System.Net.Sockets;
using Tpm2Lib;

namespace Biz.Bizadm.KMS.Cipher.Tpm.Device
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

        /// <summary>
        /// swtpm TCP 엔드포인트로 디바이스를 생성한다.
        /// </summary>
        /// <param name="host">swtpm 호스트.</param>
        /// <param name="commandPort">명령 포트. 제어 포트는 <c>commandPort + 1</c>.</param>
        /// <param name="timeoutMs">연결·송수신 타임아웃(밀리초).</param>
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

        /// <summary>
        /// 명령 포트를 연결하고 필요 시 <c>TPM2_Startup(SU_CLEAR)</c>를 수행한다.
        /// </summary>
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

        /// <summary>
        /// 명령 포트 연결을 닫는다.
        /// </summary>
        public override void Close()
        {
            CloseCommand();
        }

        /// <summary>
        /// TPM 명령을 전송하고 응답을 받는다.
        /// </summary>
        /// <param name="active">명령 수정자(로컬리티 등).</param>
        /// <param name="inBuf">요청 프레임.</param>
        /// <param name="outBuf">응답 프레임.</param>
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

        /// <summary>
        /// 플랫폼 제어 지원 여부. swtpm에서는 지원하지 않는다.
        /// </summary>
        public override bool PlatformAvailable() => false;

        /// <summary>
        /// 전원 제어 지원 여부. swtpm에서는 지원하지 않는다.
        /// </summary>
        public override bool PowerCtlAvailable() => false;

        /// <summary>
        /// 로컬리티 제어 지원 여부.
        /// </summary>
        public override bool LocalityCtlAvailable() => true;

        /// <summary>
        /// NV 제어 지원 여부. swtpm에서는 지원하지 않는다.
        /// </summary>
        public override bool NvCtlAvailable() => false;

        /// <summary>
        /// 관리·비관리 리소스를 해제한다.
        /// </summary>
        /// <param name="disposing"><see langword="true"/>이면 관리 리소스도 해제한다.</param>
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

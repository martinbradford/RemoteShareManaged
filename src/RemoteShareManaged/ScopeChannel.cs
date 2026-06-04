using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using RemoteShareManaged.Codec;
using RemoteShareManaged.Protocol;
using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace RemoteShareManaged
{
    /// <summary>
    /// Receives spectrum scope data from the SCU-LAN10 on port 50003.
    ///
    /// WIRE PROTOCOL (confirmed from Wireshark + FastDrawHelper facade analysis):
    ///
    ///   Each scope frame arrives as a single large UDP datagram, IP-fragmented
    ///   across 3 packets by the SCU:
    ///     Fragment 1: bytes    0-1479  (1480 bytes)
    ///     Fragment 2: bytes 1480-2959  (1480 bytes)
    ///     Fragment 3: bytes 2960-4109  (1150 bytes)
    ///   Windows reassembles these transparently before UdpClient.ReceiveAsync
    ///   returns, giving a single 4110-byte buffer.
    ///
    ///   UDP payload layout (4110 bytes total):
    ///     [0:2]   5A 5A  (ZZ magic)
    ///     [2]     0x0A   (type = scope data)
    ///     [3:6]   00 00 01
    ///     [6]     kl  (seq byte)
    ///     [7]     kh  (nonceB = -(seq*0x60)&0xff)
    ///     [8+]    FUN-encoded payload
    ///
    ///   FUN decoded payload:
    ///     fun[0:2]   = len (LE)      = 0x0006
    ///     fun[2:4]   = MID (LE)      = 0x0185
    ///     fun[4:6]   = data_len (LE) = 0x1000 = 4096
    ///     fun[6:10]  = SID
    ///     fun[10+]   = 4096 bytes of scope frame data
    ///                  (last 4 bytes may be absent — raw is 4110 bytes but
    ///                   full decode needs 4114; decode loop guards with bounds check)
    ///
    ///   SCOPE OPEN SEQUENCE (confirmed from Wireshark):
    ///     PC sends BuildSendAudioConnect(dev=3) — 18 bytes, same structure as
    ///     audio DevPortConnect but with dev=3. SCU responds with 0x0E MID=0x0184 ACK
    ///     then immediately starts streaming 0x0A scope frames.
    ///     There is NO SendScopeOpen (type 0x26) — unlike audio.
    ///
    ///   KEEPALIVE (confirmed from Wireshark):
    ///     SCU sends type 0x0E, MID 0x0187 to PC at ~1s intervals.
    ///     PC sends type 0x0E, MID 0x0107 to SCU at ~1s intervals.
    ///
    ///   SCOPE FRAME LAYOUT (4096 bytes, confirmed from binary analysis):
    ///     [0x0000-0x031F]  800 bytes   — SUB waterfall history
    ///     [0x0320-0x0427]  264 bytes   — SUB SPE (spectrum), 1 byte/bin
    ///     [0x0428-0x06A3]  636 bytes   — SUB metadata / gap
    ///     [0x06A4-0x06A5]  2 bytes     — Fixed boundary marker: 0x01 0x3D
    ///     [0x06A6-0x06C1]  28 bytes    — MAIN metadata gap
    ///     [0x06C2-0x07C9]  264 bytes   — MAIN SPE (spectrum), 1 byte/bin
    ///     [0x07CA-0x0B53]  906 bytes   — MAIN waterfall history
    ///     [0x0B54-0x0FFF]  1196 bytes  — Metadata (frequency axis, span config)
    ///
    ///   SPE data: 264 bytes per channel, 1 unsigned byte per frequency bin.
    ///   Bin 0 = lowest frequency, bin 263 = highest frequency.
    ///   Higher value = stronger signal.  Hz/bin = span_Hz / 264.
    ///   Cadence: ~40 ms (~25 frames/second).
    ///
    ///   SEQUENCE COUNTER: uses the session-shared counter (Func<byte> nextSeq)
    ///   exactly as AudioChannel does — the SCU rejects DevPortConnect if the
    ///   seq is out of sync with the established session.
    /// </summary>
    public sealed class ScopeChannel : IAsyncDisposable
    {
        // -----------------------------------------------------------------------
        // Frame layout constants (confirmed from binary analysis)
        // -----------------------------------------------------------------------

        public const int FrameSize = 4096;
        public const int SpeBins = 264;

        public const int SubWaterfallOffset = 0x0000;
        public const int SubWaterfallLength = 800;
        public const int SubSpeOffset = 0x0320;
        public const int SubSpeLength = SpeBins;

        public const int BoundaryOffset = 0x06A4;  // fixed bytes 0x01, 0x3D
        public const int MainSpeOffset = 0x06C2;
        public const int MainSpeLength = SpeBins;

        public const int MainWaterfallOffset = 0x07D2;
        public const int MainWaterfallLength = 898;
        public const int MetadataOffset = 0x0B54;

        // Frequency fields in metadata block (Big-Endian uint32, Hz)
        public const int MainFreqOffset = 0x0BFC;
        public const int SubFreqOffset = 0x0C12;

        // -----------------------------------------------------------------------
        // State
        // -----------------------------------------------------------------------

        private readonly ILogger<ScopeChannel> _log;
        private readonly string _addr;
        private readonly byte _helloAckNonce;
        private readonly Func<byte> _nextSeq;

        private UdpClient? _udp;
        private CancellationTokenSource _cts = new();
        private Task? _receiveTask;

        public bool IsRunning
        {
            get; private set;
        }

        // -----------------------------------------------------------------------
        // Public event
        // -----------------------------------------------------------------------

        /// <summary>
        /// Raised on each received scope frame (~25 Hz).
        /// Arrays inside ScopeFrame are freshly allocated — safe to retain.
        /// </summary>
        public event Action<ScopeFrame>? FrameReceived;

        // -----------------------------------------------------------------------
        // Construction — mirrors AudioChannel constructor pattern exactly
        // -----------------------------------------------------------------------

        /// <param name="addr">SCU-LAN10 IP address, e.g. "192.168.4.190"</param>
        /// <param name="helloAckNonce">The nonce byte from the HELLO-ACK packet</param>
        /// <param name="nextSeq">Session-shared sequence counter — same delegate used by AudioChannel</param>
        /// <param name="loggerFactory">Optional logger factory</param>
        public ScopeChannel(
            string addr,
            byte helloAckNonce,
            Func<byte> nextSeq,
            ILoggerFactory? loggerFactory = null)
        {
            _addr = addr;
            _helloAckNonce = helloAckNonce;
            _nextSeq = nextSeq;
            _log = (loggerFactory ?? NullLoggerFactory.Instance)
                                 .CreateLogger<ScopeChannel>();
        }

        // -----------------------------------------------------------------------
        // Lifecycle
        // -----------------------------------------------------------------------

        public async Task StartAsync(CancellationToken ct = default)
        {
            if (IsRunning)
                return;

            _cts = CancellationTokenSource.CreateLinkedTokenSource(ct);

            _udp = new UdpClient(0);  // bind to any local port

            // Disable ICMP port-unreachable socket poisoning (same as RemotePath)
            if (OperatingSystem.IsWindows())
                _udp.Client.IOControl(
                    unchecked((int)0x9800000C),
                    new byte[] { 0, 0, 0, 0 }, null);

            // Allow large reassembled datagrams (4110 bytes per scope frame)
            _udp.Client.ReceiveBufferSize = 65536;

            var localPort = ((IPEndPoint)_udp.Client.LocalEndPoint!).Port;
            _log.LogDebug("ScopeChannel bound to local port {Port}", localPort);

            await DoScopeOpenAsync(_cts.Token);

            IsRunning = true;
            _receiveTask = ReceiveLoopAsync(_cts.Token);

            _log.LogInformation("ScopeChannel started");
        }

        public async Task StopAsync()
        {
            if (!IsRunning)
                return;
            IsRunning = false;

            _cts.Cancel();
            _udp?.Close();

            if (_receiveTask is not null)
            {
                try
                {
                    await _receiveTask.WaitAsync(TimeSpan.FromSeconds(3));
                }
                catch { }
                _receiveTask = null;
            }

            _udp = null;
            _log.LogInformation("ScopeChannel stopped");
        }

        // -----------------------------------------------------------------------
        // Scope open sequence (confirmed from Wireshark)
        // -----------------------------------------------------------------------

        private async Task DoScopeOpenAsync(CancellationToken ct)
        {
            // Use BuildSendAudioConnect with dev=3 (scope device).
            // This produces an 18-byte packet identical in structure to the audio
            // DevPortConnect — confirmed from Yaesu Wireshark capture.
            // The SCU ACKs with 0x0E MID=0x0184 then begins streaming 0x0A frames.
            // Only one send is needed (Yaesu app sends one, not two).
            var connect = ZzFrameCodec.BuildSendAudioConnect(_nextSeq(), _helloAckNonce, dev: 3);
            _udp!.Client.SendTo(connect, RemoteEndPoint);

            // Wait for SCU to start streaming (~100ms observed in Wireshark)
            await Task.Delay(200, ct);
        }

        // -----------------------------------------------------------------------
        // Receive loop
        // -----------------------------------------------------------------------

        private async Task ReceiveLoopAsync(CancellationToken ct)
        {
            _log.LogDebug("ScopeChannel receive loop started");

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    var result = await _udp!.ReceiveAsync(ct);
                    ProcessPacket(result.Buffer);
                }
                catch (OperationCanceledException) { break; }
                catch (SocketException ex)
                {
                    _log.LogDebug("ScopeChannel socket exception {Code}: {Msg}",
                        ex.ErrorCode, ex.Message);
                    break;
                }
                catch (Exception ex)
                {
                    _log.LogWarning(ex, "ScopeChannel RX error — continuing");
                }
            }

            _log.LogDebug("ScopeChannel receive loop exited");
        }

        // -----------------------------------------------------------------------
        // Packet processing
        // -----------------------------------------------------------------------

        private void ProcessPacket(byte[] raw)
        {
            if (raw.Length < 8)
                return;
            if (raw[0] != 0x5A || raw[1] != 0x5A)
                return;

            byte type = raw[2];

            switch (type)
            {
                case 0x0A:
                    ProcessScopeFrame(raw);
                    break;

                case 0x0E:
                    // Keepalive from SCU — respond with MID 0x0107
                    // (confirmed from Yaesu Wireshark capture)
                    var response = ZzFrameCodec.BuildScopeKeepalive(_nextSeq(), _helloAckNonce);
                    try
                    {
                        _udp?.Client.SendTo(response, RemoteEndPoint);
                    }
                    catch { }
                    break;
            }
        }

        private void ProcessScopeFrame(byte[] raw)
        {
            // Need at least ZZ header (8 bytes) + FUN header (10 bytes)
            if (raw.Length < 18)
                return;

            byte kl = raw[6];
            byte kh = raw[7];

            // Decode FUN header fields directly
            // fun[i] = ((-i) & 0xff) ^ raw[8+i] ^ kl ^ kh
            int mid = (((-2) & 0xff) ^ raw[10] ^ kl ^ kh)
                    | ((((-3) & 0xff) ^ raw[11] ^ kl ^ kh) << 8);

            int dataLen = (((-4) & 0xff) ^ raw[12] ^ kl ^ kh)
                        | ((((-5) & 0xff) ^ raw[13] ^ kl ^ kh) << 8);

            if (mid != 0x0185)
            {
                _log.LogDebug("ScopeFrame: unexpected MID 0x{Mid:X4} — skipped", mid);
                return;
            }

            if (dataLen != FrameSize)
            {
                _log.LogDebug("ScopeFrame: unexpected dataLen {Len} — skipped", dataLen);
                return;
            }

            // Decode scope data payload.
            // Scope data = fun[10..4105] = raw[18..4113].
            // raw may be only 4110 bytes (last 4 bytes absent) — bounds-guarded below.
            var frameData = new byte[FrameSize];
            int available = Math.Min(FrameSize, raw.Length - 18);
            for (int i = 0; i < available; i++)
            {
                int j = 10 + i;  // position in FUN stream
                frameData[i] = (byte)(((-j) & 0xff) ^ raw[18 + i] ^ kl ^ kh);
            }
            // Bytes [available..FrameSize-1] remain 0 from array initialisation.

            // Validate boundary marker
            if (frameData[BoundaryOffset] != 0x01 ||
                frameData[BoundaryOffset + 1] != 0x3D)
            {
                _log.LogDebug("ScopeFrame: boundary marker mismatch — skipped");
                return;
            }

            // Extract SPE blocks
            var mainSpe = new byte[SpeBins];
            var subSpe = new byte[SpeBins];
            Array.Copy(frameData, MainSpeOffset, mainSpe, 0, SpeBins);
            Array.Copy(frameData, SubSpeOffset, subSpe, 0, SpeBins);

            // Extract VFO frequencies from metadata (Big-Endian uint32, Hz)
            uint mainFreqHz = ReadBEUInt32(frameData, MainFreqOffset);
            uint subFreqHz = ReadBEUInt32(frameData, SubFreqOffset);

            FrameReceived?.Invoke(new ScopeFrame(
                mainSpe, subSpe, frameData, mainFreqHz, subFreqHz));
        }

        // -----------------------------------------------------------------------
        // Helpers
        // -----------------------------------------------------------------------

        private IPEndPoint RemoteEndPoint =>
            new IPEndPoint(IPAddress.Parse(_addr), ScuPorts.Scope);

        private static uint ReadBEUInt32(byte[] data, int offset) =>
            ((uint)data[offset] << 24) |
            ((uint)data[offset + 1] << 16) |
            ((uint)data[offset + 2] << 8) |
             (uint)data[offset + 3];

        // -----------------------------------------------------------------------
        // IAsyncDisposable
        // -----------------------------------------------------------------------

        public async ValueTask DisposeAsync()
        {
            await StopAsync();
            _cts.Dispose();
        }
    }

    // -----------------------------------------------------------------------
    // ScopeFrame DTO
    // -----------------------------------------------------------------------

    /// <summary>One decoded scope frame from the SCU-LAN10.</summary>
    public sealed class ScopeFrame
    {
        /// <summary>
        /// MAIN receiver spectrum — 264 bytes, bin 0 = lowest frequency.
        /// Amplitude: higher byte value = stronger signal.
        /// Hz per bin = span_Hz / 264.
        /// </summary>
        public byte[] MainSpe
        {
            get;
        }

        /// <summary>SUB receiver spectrum — 264 bytes, same encoding as MainSpe.</summary>
        public byte[] SubSpe
        {
            get;
        }

        /// <summary>Full raw 4096-byte decoded frame (for waterfall / diagnostics).</summary>
        public byte[] RawFrame
        {
            get;
        }

        /// <summary>VFO A centre frequency in Hz (from frame metadata).</summary>
        public uint MainFrequencyHz
        {
            get;
        }

        /// <summary>VFO B centre frequency in Hz (from frame metadata).</summary>
        public uint SubFrequencyHz
        {
            get;
        }

        /// <summary>Convenience: MAIN centre frequency in MHz.</summary>
        public double MainFrequencyMHz => MainFrequencyHz / 1_000_000.0;

        /// <summary>Convenience: SUB centre frequency in MHz.</summary>
        public double SubFrequencyMHz => SubFrequencyHz / 1_000_000.0;

        public ScopeFrame(
            byte[] mainSpe, byte[] subSpe, byte[] rawFrame,
            uint mainFreqHz, uint subFreqHz)
        {
            MainSpe = mainSpe;
            SubSpe = subSpe;
            RawFrame = rawFrame;
            MainFrequencyHz = mainFreqHz;
            SubFrequencyHz = subFreqHz;
        }
    }
}
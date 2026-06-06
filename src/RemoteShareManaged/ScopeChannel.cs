using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using RemoteShareManaged.Codec;
using RemoteShareManaged.Protocol;
using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace RemoteShareManaged
{
    /// <summary>
    /// Receives spectrum scope data from the SCU-LAN10 on port 50003.
    ///
    /// WIRE PROTOCOL (confirmed from Wireshark + binary analysis):
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
    ///     [7]     kh  (nonceB = -(seq*0x60)&amp;0xff)
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
    ///   SCOPE OPEN SEQUENCE (confirmed from Wireshark 2026-06-05):
    ///     ORDERING IS CRITICAL. The scope DevPortConnect MUST be sent after the
    ///     audio DevPortConnect ACK but BEFORE SendAudioOpen. Once SendAudioOpen
    ///     is sent, the SCU enters streaming mode and ignores new DevPortConnect
    ///     requests on port 50003.
    ///
    ///     Confirmed sequence (from Yaesu reference capture):
    ///       1. Audio DevPortConnect (dev=2)   → wait for audio ACK
    ///       2. Scope DevPortConnect (dev=6)   ← BEFORE SendAudioOpen
    ///       3. Wait for scope ACK (type 0x0E, ~35ms) — timeout fallback 200ms
    ///       4. Wait additional 50ms settling time
    ///       5. SendAudioOpen ×2
    ///       6. Scope frames stream immediately
    ///
    ///     dev=6 (DinSpiIn) is confirmed correct. dev=3 produces a valid-looking
    ///     packet that the SCU silently ignores.
    ///
    ///     The ACK wait is critical: sending SendAudioOpen only 22ms after the
    ///     scope DevPortConnect (before the ACK arrives) causes the SCU to never
    ///     start the scope data stream.
    ///
    ///     This is implemented via ScopeChannel.SendDevPortConnectAsync(), called
    ///     from DoAudioChannelOpenAsync() at the correct point in the sequence.
    ///
    ///   KEEPALIVE (confirmed from Wireshark):
    ///     SCU sends type 0x0E, MID 0x0187 to PC at ~1s intervals.
    ///     PC sends type 0x0E, MID 0x0107 to SCU at ~1s intervals.
    ///
    ///   SCOPE FRAME LAYOUT (4096 bytes, confirmed from binary analysis):
    ///     The frame is a WATERFALL RING BUFFER. Each received frame adds one
    ///     new 132-byte SPE row into the ring. The write pointer advances ~86
    ///     bytes per frame, so the SPE does NOT live at a fixed offset.
    ///
    ///     Boundary marker 0x01 0x3D at offset 0x06A0 divides:
    ///       SUB ring:  0x0000 .. 0x069F  (132-byte rows, ~40 rows)
    ///       MAIN ring: 0x06A2 .. 0x0BFF  (132-byte rows, ~40 rows)
    ///       Metadata:  0x0B54 .. 0x0FFF  (frequency axis, span config)
    ///
    ///   SPE data: 66 bins per channel, 1 unsigned byte per bin.
    ///   Bin 0 = lowest frequency, bin 65 = highest frequency.
    ///   Higher value = stronger signal.  Hz/bin ≈ span_Hz / 66.
    ///   Cadence: ~40 ms (~25 frames/second).
    ///
    ///   SEQUENCE COUNTER: uses the session-shared counter (Func&lt;byte&gt; nextSeq)
    ///   exactly as AudioChannel does — the SCU rejects DevPortConnect if the
    ///   seq is out of sync with the established session.
    /// </summary>
    public sealed class ScopeChannel : IAsyncDisposable
    {
        // -----------------------------------------------------------------------
        // Frame layout constants (confirmed from binary analysis)
        // -----------------------------------------------------------------------

        public const int FrameSize = 4096;

        // ── MAIN spectrum — confirmed location (pcapng analysis 2026-06-06) ──────
        //
        // The MAIN spectrum lives at a FIXED offset, NOT in a ring buffer.
        // Confirmed by comparing antenna vs dummy-load captures: this is the only
        // 400-byte region whose variance is 8–10× higher with a live antenna than
        // with a dummy load. The entire region is homogeneous and updated every frame.
        //
        // Encoding: two bytes per bin (200 bins × 2 bytes = 400 bytes).
        //   even byte (frameData[offset + i*2    ]): rises with signal strength
        //   odd  byte (frameData[offset + i*2 + 1]): falls with signal strength
        //   noise floor: even ≈ 134, odd ≈ 122  → difference ≈ 12
        //   strong signal: even ≈ 200, odd ≈ 60  → difference ≈ 140
        //   display value = Max(0, even - odd)   → 0 at noise, up to ~255 at peak
        //
        // Bin 0 = lowest frequency, bin 199 = highest frequency.
        // Hz per bin = SpanHz / 200.
        public const int SpeBins       = 200;
        public const int MainSpeOffset = 0x0768;  // 0x0768..0x08F7 (400 bytes)

        // SUB spectrum offset: not yet confirmed. Pending a capture where both
        // VFOs are on dummy load (or a moving-carrier test on SUB VFO).
        // SubSpe is returned as a zero-filled placeholder until this is resolved.
        // public const int SubSpeOffset = ???;

        // Frequency and span fields in metadata block.
        // These are stable across frames — not inside any ring.
        public const int MetadataOffset = 0x0B54;

        // VFO frequencies — Big-Endian uint32, Hz. Confirmed from Wireshark.
        public const int MainFreqOffset = 0x0BFC;
        public const int SubFreqOffset  = 0x0C12;

        // Span index — lower nibble of byte at SpanIndexOffset = FD_index.
        // Upper nibble varies (0x80 in Yaesu-app pcapng, 0x40 in live testbed session).
        // Lower nibble is stable across both: 0x46 & 0x0F = 6 = FD006 = 100kHz. ✓
        //   frame[SpanIndexOffset] & 0x0F = FD_index
        //   FD_index → span Hz via SpanTableHz[]
        public const int SpanIndexOffset = 0x0BF2;

        // FTdx101D span lookup: index i → span in Hz (FD00i CAT command).
        // Confirmed: FD003=10k, FD005=50k, FD006=100k, FD007=200k,
        //            FD008=500k, FD009=1000k (from pcapng analysis 2026-06-06).
        //            FD000=1k, FD001=2k, FD002=5k, FD004=20k confirmed
        //            from radio menu (full span list: 1/2/5/10/20/50/100/200/500/1000 kHz).
        public static readonly uint[] SpanTableHz =
        {
              1_000,  // FD000
              2_000,  // FD001
              5_000,  // FD002
             10_000,  // FD003 confirmed
             20_000,  // FD004
             50_000,  // FD005 confirmed
            100_000,  // FD006 confirmed
            200_000,  // FD007 confirmed
            500_000,  // FD008 confirmed
          1_000_000,  // FD009 confirmed
        };

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
        private int _frameCount;
        private long _nextDiagTick;

        // Channel used to hand 0x0E ACK packets from the receive loop to
        // WaitForAckAsync() without blocking the receive loop.
        private readonly Channel<byte[]> _ackChannel =
            Channel.CreateBounded<byte[]>(new BoundedChannelOptions(8)
            {
                FullMode = BoundedChannelFullMode.DropOldest,
                SingleReader = true,
                SingleWriter = false,
            });

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
        // Construction
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

        /// <summary>
        /// Open the UDP socket and start the receive loop.
        /// Does NOT send the DevPortConnect — that is done at the right moment
        /// by SendDevPortConnectAsync(), called from DoAudioChannelOpenAsync()
        /// before SendAudioOpen is sent.
        /// </summary>
        public Task StartAsync(CancellationToken ct = default)
        {
            if (IsRunning)
                return Task.CompletedTask;

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

            IsRunning = true;
            _receiveTask = ReceiveLoopAsync(_cts.Token);

            _log.LogInformation("ScopeChannel socket open — waiting for DevPortConnect signal");
            return Task.CompletedTask;
        }

        /// <summary>
        /// Send the scope DevPortConnect packet and wait for the SCU's 0x0E ACK.
        ///
        /// MUST be called AFTER the audio DevPortConnect ACK and BEFORE SendAudioOpen.
        /// Called by DoAudioChannelOpenAsync() at the correct point in the sequence.
        ///
        /// dev=6 (DinSpiIn) confirmed correct from Wireshark byte-for-byte comparison
        /// with Yaesu reference capture. dev=3 is silently ignored by the SCU.
        ///
        /// Waits up to <paramref name="ackTimeout"/> for the SCU's 0x0E ACK, then
        /// waits an additional 50ms settling time before returning. The Yaesu reference
        /// capture shows ~35ms for the ACK and ~50ms total gap before SendAudioOpen.
        /// Sending SendAudioOpen too soon (e.g. 22ms, before the ACK) causes the SCU
        /// to never start the scope data stream.
        /// </summary>
        public async Task SendDevPortConnectAsync(
            TimeSpan ackTimeout, CancellationToken ct = default)
        {
            if (_udp is null)
            {
                _log.LogWarning("SendDevPortConnectAsync called but socket not open — call StartAsync first");
                return;
            }

            // dev=6 = DinSpiIn — confirmed from Yaesu reference capture 2026-06-05.
            // dev=3 produces a structurally valid packet that the SCU silently ignores.
            var connect = ZzFrameCodec.BuildSendAudioConnect(_nextSeq(), _helloAckNonce, dev: 6);
            _log.LogDebug("Scope DevPortConnect sent ({Len} bytes): {Hex}",
                connect.Length, Convert.ToHexString(connect));
            _udp.Client.SendTo(connect, RemoteEndPoint);

            // Wait for the SCU's 0x0E ACK on port 50003.
            // The receive loop feeds 0x0E packets into _ackChannel.
            // Confirmed from Wireshark: ACK arrives ~35ms after DevPortConnect.
            // Sending SendAudioOpen before this ACK (at ~22ms) silently breaks
            // the scope stream.
            //bool ackReceived = false;
            try
            {
                using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                timeoutCts.CancelAfter(ackTimeout);
                await _ackChannel.Reader.ReadAsync(timeoutCts.Token);
                _log.LogDebug("Scope DevPortConnect ACK received");
            }
            catch (OperationCanceledException)
            {
                if (ct.IsCancellationRequested)
                    throw;
                _log.LogWarning("Scope DevPortConnect ACK not received within {Ms}ms — continuing",
                    (int)ackTimeout.TotalMilliseconds);
            }

            // Additional settling delay before SendAudioOpen. The Yaesu reference
            // capture used ~50ms between scope DevPortConnect and SendAudioOpen even
            // when the ACK arrived quickly at ~35ms.
            await Task.Delay(50, ct);
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
                    // Could be either the DevPortConnect ACK or a steady-state keepalive.
                    // Feed into _ackChannel so SendDevPortConnectAsync can consume it.
                    // After the connect phase keepalives arrive at ~1s intervals, so the
                    // channel won't fill up in normal operation.
                    _ackChannel.Writer.TryWrite(raw);

                    // Respond with MID 0x0107 keepalive
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

            // ── MAIN SPE extraction (fixed offset, confirmed 2026-06-06) ─────────
            // The MAIN spectrum is at a fixed offset 0x0768..0x08F7 (400 bytes),
            // NOT in a ring buffer. Encoding: 2 bytes per bin — each pair encodes
            // signal level around a midpoint of ~128:
            //   noise floor: even≈134, odd≈122  (even above mid, odd below)
            //   with signal: even rises further, odd falls further
            //   e.g. S9+800: even≈175-220, odd≈47-085
            //   display value = Max(0, even - odd)
            //   → ~12 at noise (134-122), clamped to 0 after noise floor subtraction
            //   → ~100-160 at strong signal
            var mainSpe = new byte[SpeBins];
            for (int i = 0; i < SpeBins; i++)
            {
                int even = frameData[MainSpeOffset + i * 2];
                int odd  = frameData[MainSpeOffset + i * 2 + 1];
                mainSpe[i] = (byte)Math.Max(0, even - odd);
            }

            // SUB SPE: offset not yet confirmed — return zeros as placeholder.
            // TODO: locate SubSpeOffset from a capture with both VFOs on dummy load
            // or a moving-carrier test on the SUB VFO.
            var subSpe = new byte[SpeBins];

            // Frequency and span metadata are stable (not in the ring) — read directly
            uint mainFreqHz = ReadBEUInt32(frameData, MainFreqOffset);
            uint subFreqHz  = ReadBEUInt32(frameData, SubFreqOffset);

            // Span index: lower nibble of frame[SpanIndexOffset] = FD CAT command index.
            // Live session shows 0x46 (not 0x86) for FD006 (100kHz): upper nibble varies
            // between sessions (0x40 in live, 0x80 in pcapng). Lower nibble is stable.
            int spanIdx = frameData[SpanIndexOffset] & 0x0F;
            uint spanHz = (uint)spanIdx < (uint)SpanTableHz.Length
                ? SpanTableHz[spanIdx]
                : 0;

            // ── Diagnostic: log raw bytes at MainSpeOffset + SPE stats every 5s ─
            _frameCount++;
            long now = System.Diagnostics.Stopwatch.GetTimestamp();
            if (now >= _nextDiagTick)
            {
                _nextDiagTick = now + System.Diagnostics.Stopwatch.Frequency * 5;
                var sb = new System.Text.StringBuilder();
                sb.Append($"[SPE diag frame#{_frameCount}] raw[0x{MainSpeOffset:X4}..+11]: ");
                for (int i = 0; i < 12; i++)
                    sb.Append($"{frameData[MainSpeOffset + i]:D3} ");
                int speMin = mainSpe.Min();
                int speMax = mainSpe.Max();
                double speMean = mainSpe.Average(b => (double)b);
                sb.Append($"| spe min={speMin} max={speMax} mean={speMean:F1}");
                sb.Append($" | spanIdx={spanIdx} spanHz={spanHz} mainFreq={mainFreqHz}");
                _log.LogInformation("{Msg}", sb.ToString());
            }

            FrameReceived?.Invoke(new ScopeFrame(
                mainSpe, subSpe, frameData, mainFreqHz, subFreqHz, spanHz));
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
        /// MAIN receiver spectrum — 200 bytes, bin 0 = lowest frequency.
        /// Amplitude: higher byte value = stronger signal (0 = noise floor).
        /// Decoded from two-byte pairs at frame offset 0x0768: value = Max(0, odd - even).
        /// Hz per bin = span_Hz / 200.
        /// </summary>
        public byte[] MainSpe
        {
            get;
        }

        /// <summary>SUB receiver spectrum — 200 bytes, same encoding as MainSpe.
        /// Currently returns zeros (SUB frame offset not yet confirmed).</summary>
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

        /// <summary>
        /// Scope span in Hz (from frame metadata span index). Zero if unknown.
        /// Confirmed offsets: FD003=10k, FD005=50k … FD009=1000k.
        /// </summary>
        public uint SpanHz
        {
            get;
        }

        /// <summary>Convenience: MAIN centre frequency in MHz.</summary>
        public double MainFrequencyMHz => MainFrequencyHz / 1_000_000.0;

        /// <summary>Convenience: SUB centre frequency in MHz.</summary>
        public double SubFrequencyMHz => SubFrequencyHz / 1_000_000.0;

        /// <summary>
        /// Hz per spectrum bin (= SpanHz / 200). Zero if span unknown.
        /// Use for frequency-axis labelling: bin i covers
        ///   centre ± (i - SpeBins/2) × HzPerBin
        /// </summary>
        public double HzPerBin => SpanHz > 0 ? SpanHz / (double)ScopeChannel.SpeBins : 0;

        public ScopeFrame(
            byte[] mainSpe, byte[] subSpe, byte[] rawFrame,
            uint mainFreqHz, uint subFreqHz, uint spanHz)
        {
            MainSpe = mainSpe;
            SubSpe = subSpe;
            RawFrame = rawFrame;
            MainFrequencyHz = mainFreqHz;
            SubFrequencyHz = subFreqHz;
            SpanHz = spanHz;
        }
    }
}
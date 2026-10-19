using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using RemoteShareManaged.Codec;
using RemoteShareManaged.Protocol;
using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Channels;
using System.Collections.Generic;
using System.Linq;
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
    ///   SCOPE FRAME LAYOUT (4096 bytes, confirmed from heatmap receiver-disable tests 2026-06-09):
    ///
    ///     0x0000–0x034D  MAIN spectrum: 846 bytes, one byte per frequency bin.
    ///                    Encoding INVERTED: lower byte value = stronger signal.
    ///                    Bin 0 = VFO − span (lowest frequency).
    ///                    Bin 845 = VFO (highest frequency).
    ///                    Hz/bin ≈ span_Hz / 846.
    ///
    ///     0x034E–0x069B  SUB spectrum: 846 bytes, identical encoding.
    ///                    Bin 0 = SUB VFO − SUB span, bin 845 = SUB VFO.
    ///
    ///     0x069C–0x0737  Padding / unused (156 bytes, typically zero).
    ///
    ///     0x0738–0x0A4F  Oscilloscope / AF-FFT data.
    ///
    ///     0x0A50–0x0B53  Unknown.
    ///
    ///     0x0B54–0x0FFF  Metadata block:
    ///                    0x0BF2  span index byte   (& 0x0F → FD CAT index 0–9)
    ///                    0x0BFC  VFO A freq         BE uint32, Hz
    ///                    0x0C12  VFO B freq         BE uint32, Hz
    ///
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

        // ── Spectrum layout (confirmed 2026-06-09 via heatmap receiver-disable tests) ─
        //
        // The frame contains two flat linear spectrum arrays, back-to-back:
        //
        //   MAIN: bytes 0x0000–0x034D (846 bytes)
        //   SUB:  bytes 0x034E–0x069B (846 bytes)
        //   Pad:  bytes 0x069C–0x0737 (156 bytes, typically zero)
        //
        // Each byte = amplitude of one frequency bin.
        // Encoding is INVERTED: lower value = stronger signal.
        // Bin 0 = VFO − span (lowest frequency in frame).
        // Bin 845 = VFO (highest frequency = VFO itself).
        // Hz/bin ≈ SpanHz / 846.
        //
        // NOTE: there is NO ring buffer / row structure in the frame.
        //   Previous analysis claiming "7 rows × 264 bytes" was incorrect —
        //   confirmed wrong by heatmap VFO-sweep test 2026-06-09.
        public const int MainSpectrumStart = 0;
        public const int MainSpectrumBins  = 846;
        public const int SubSpectrumStart  = 846;
        public const int SubSpectrumBins   = 846;
        public const int SpeBins           = MainSpectrumBins;  // alias for callers

        // MAIN oscilloscope waveform buffer — offset-binary, 127 = zero crossing.
        // ~15 kHz sample rate. Confirmed 2026-06-09 by timebase-variation heatmap test.
        // Bytes 0x0738–0x0767 (48 bytes) are a preamble/header — byte 1895 is always
        // close to 255, byte 1896 is always close to 128 (zero). Audio starts at 0x0768.
        public const int OscPreambleStart = 0x0738;  // 1848 — preamble, not audio
        public const int OscStart         = 0x0768;  // 1896 — first real audio sample
        public const int OscSamples       = 400;     // 400 samples = ~26.7 ms at 15 kHz

        // MAIN AF-FFT magnitude buffer — INVERTED encoding: lower byte = stronger signal
        // (same convention as RF spectrum). 0xFF = no signal, 0x00 = maximum.
        // Preceded by boundary marker: byte 0x06A0=0x01, byte 0x06A1=config (e.g. 0x3D).
        // Confirmed 2026-06-10 by filter-width and IF-shift heatmap experiments.
        public const int    AfFftMarkerOffset = 0x06A0;  // 1696 — marker byte, always 0x01
        public const int    AfFftStart        = 0x06A2;  // 1698 — first magnitude bin
        public const int    AfFftBins         = 198;     // bytes 1698–1895
        public const double AfFftHzPerBin     = 22.0;    // confirmed 2026-06-10 via RTTY tone calibration
        // Total span: 198 × 22 = 4356 Hz ≈ 4.4 kHz (matches Yaesu's 4.0k axis)

        // SUB AF-FFT magnitude buffer — same encoding as MAIN (inverted).
        // Header: byte 0x08F8 = marker (0x01), byte 0x08F9 = config.
        // Data: 0x08FA–0x09BF (198 bytes). No 4-byte padding before header
        // (unlike MAIN which has 4 padding bytes at 0x069C–0x069F).
        // Confirmed 2026-06-10 by offset-slider sweep: 0x08FA is the clean start.
        public const int SubAfFftMarkerOffset = 0x08F8;  // 2296 — marker byte, expect 0x01
        public const int SubAfFftStart        = 0x08FA;  // 2298 — first SUB magnitude bin
        public const int SubAfFftBins         = 198;     // bytes 2298–2495
        // Hz/bin and span are the same as MAIN (22 Hz/bin, ~4.4 kHz)

        // VFO frequencies — Big-Endian uint32, Hz.
        // SUB metadata block is at MAIN metadata block + 0x16 (22 bytes).
        // Confirmed 2026-06-07 by MetaScan byte dump with MAIN=14.074 SUB=7.074 span=50kHz:
        //   0x0BFC = 14074000 (MAIN ✓), 0x0C12 = 7074000 (SUB ✓).
        //   Old SubFreqOffset 0x0C16 was unreliable: correct when MAIN≠SUB band,
        //   but reads MAIN−span when both VFOs on same band.
        public const int MainFreqOffset = 0x0BFC;
        public const int SubFreqOffset  = 0x0C12;  // confirmed 2026-06-07 (+0x16 from MainFreqOffset)

        // Span index — lower nibble of byte at SpanIndexOffset = FD_index.
        // Upper nibble varies (0x80 in Yaesu-app pcapng, 0x45 in live testbed).
        // Lower nibble is stable: & 0x0F = FD_index → SpanTableHz[].
        // SUB span is +0x16 bytes from MAIN span (same 22-byte offset pattern).
        // Confirmed 2026-06-07: 0x0BF2=0x45 (MAIN, &0F=5=50kHz ✓), 0x0C08=0x45 (SUB, &0F=5=50kHz ✓).
        //   Old SubSpanIndexOffset 0x0C0C had value 0xF6 → &0F=6=100kHz (wrong).
        public const int SpanIndexOffset    = 0x0BF2;  // MAIN span index
        public const int SubSpanIndexOffset = 0x0C08;  // SUB  span index (confirmed 2026-06-07)

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
        private Task? _keepaliveTask;
        private int  _frameCount;
        private int  _decimationCounter;

        /// <summary>
        /// Render every Nth scope frame; the rest are decoded but not raised.
        /// 1 = every frame (~25 fps), 2 = every other frame (~12 fps),
        /// 3 = every third frame (~8 fps), etc.
        /// Reduces UI render load and Dispatcher queue pressure on slow links
        /// without changing the wire bandwidth (the SCU always sends ~25 fps).
        /// Safe to change at any time — takes effect on the next received frame.
        /// </summary>
        public int FrameDecimation { get; set; } = 1;


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

            // Large receive buffer reduces fragment drop probability on slow/jittery links.
            // Each scope frame is 4110 bytes (3 IP fragments); losing any one kills the frame.
            // 256 KB holds ~62 frames worth of raw UDP data.
            _udp.Client.ReceiveBufferSize = 256 * 1024;

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

            // Connected — start the 1 s keepalive (the Yaesu app's first one follows
            // the connect by ~0.8 s).
            _keepaliveTask ??= KeepaliveLoopAsync(_cts.Token);
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

            if (_keepaliveTask is not null)
            {
                try
                {
                    await _keepaliveTask.WaitAsync(TimeSpan.FromSeconds(3));
                }
                catch { }
                _keepaliveTask = null;
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
                    // Either the DevPortConnect ACK or the SCU's ACK (MID 0x0187) to one of
                    // our periodic keepalives. Feed into _ackChannel so
                    // SendDevPortConnectAsync can consume it (DropOldest — harmless if unread).
                    _ackChannel.Writer.TryWrite(raw);

                    // Do NOT answer ACKs. Replying to every 0x0187 with a 0x0107 made the
                    // SCU ACK the reply, and so on — a ~667 packet/s ping-pong on 50003
                    // that loaded the SCU and caused periodic dropouts in TX audio. The
                    // Yaesu app only sends a keepalive every ~1 s (KeepaliveLoopAsync).
                    // Only answer a genuine keepalive request from the SCU, should one come.
                    if (raw.Length >= 12 && DecodeMid(raw) == 0x0107)
                    {
                        try
                        {
                            _udp?.Client?.SendTo(
                                ZzFrameCodec.BuildScopeKeepalive(_nextSeq(), _helloAckNonce),
                                RemoteEndPoint);
                        }
                        catch { }
                    }
                    break;
            }
        }

        private static int DecodeMid(byte[] raw)
        {
            byte kl = raw[6], kh = raw[7];
            return (((-2) & 0xff) ^ raw[10] ^ kl ^ kh)
                 | ((((-3) & 0xff) ^ raw[11] ^ kl ^ kh) << 8);
        }

        // Scope-port keepalive (MID 0x0107), one per second — matches the Yaesu
        // reference capture (~1.01 s cadence, each answered by a single 0x0187 ACK).
        private async Task KeepaliveLoopAsync(CancellationToken ct)
        {
            try
            {
                using var timer = new PeriodicTimer(TimeSpan.FromSeconds(1));
                while (await timer.WaitForNextTickAsync(ct))
                {
                    try
                    {
                        _udp?.Client?.SendTo(
                            ZzFrameCodec.BuildScopeKeepalive(_nextSeq(), _helloAckNonce),
                            RemoteEndPoint);
                    }
                    catch (Exception ex) when (ex is not OperationCanceledException)
                    {
                        _log.LogDebug("Scope keepalive send failed: {Msg}", ex.Message);
                    }
                }
            }
            catch (OperationCanceledException) { }
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

            _frameCount++;
            ExtractAndRaise(frameData);
        }

        // -----------------------------------------------------------------------
        // SPE extraction
        // -----------------------------------------------------------------------

        // Flat linear read — no ring buffer, no row structure.
        // MAIN = bytes 0x0000–0x034D (846 bytes).
        // SUB  = bytes 0x034E–0x069B (846 bytes).
        // Encoding: lower byte = stronger signal (inverted).
        // Confirmed 2026-06-09 by VFO-sweep heatmap test: single continuous array,
        // signal peak moves smoothly as VFO changes — no 264-byte repetition.
        private static (byte[] mainSpe, byte[] subSpe) ExtractSpectra(byte[] frameData)
        {
            var mainSpe = new byte[MainSpectrumBins];
            var subSpe  = new byte[SubSpectrumBins];
            Array.Copy(frameData, MainSpectrumStart, mainSpe, 0, MainSpectrumBins);
            Array.Copy(frameData, SubSpectrumStart,  subSpe,  0, SubSpectrumBins);
            return (mainSpe, subSpe);
        }

        // -----------------------------------------------------------------------
        // Static-frame replay (for display testing without live radio)
        // -----------------------------------------------------------------------

        /// <summary>
        /// Load a saved 4096-byte frame file (e.g. from FastDrawFrames\frame_NNNNNN_avg0.bin)
        /// and fire FrameReceived once as if it arrived from the network.
        ///
        /// Use this to:
        ///   - Verify that our RawFrame matches the Yaesu app's ScopeRead buffer exactly
        ///   - Experiment with zeroing frame regions to map display semantics
        ///   - Compare our rendering against the Yaesu app rendering of identical data
        ///
        /// Does NOT require a live session — call any time after construction.
        /// </summary>
        public void FireReplayFrame(string binFilePath)
        {
            var frameData = File.ReadAllBytes(binFilePath);
            if (frameData.Length < FrameSize)
                throw new InvalidDataException(
                    $"Replay file is {frameData.Length} bytes — expected {FrameSize}");

            // Trim to exactly FrameSize if file is larger
            if (frameData.Length > FrameSize)
                Array.Resize(ref frameData, FrameSize);

            ExtractAndRaise(frameData);
        }

        /// <summary>
        /// Common extraction logic shared by ProcessScopeFrame (live) and
        /// FireReplayFrame (static). Fires FrameReceived with the extracted data.
        /// </summary>
        private void ExtractAndRaise(byte[] frameData)
        {
            // Decimation: raise FrameReceived only on every Nth frame.
            // Counter increments on every call so the skip is evenly distributed.
            int n = FrameDecimation;
            if (n > 1)
            {
                _decimationCounter = (_decimationCounter + 1) % n;
                if (_decimationCounter != 0)
                    return;
            }

            var (mainSpe, subSpe) = ExtractSpectra(frameData);

            uint mainFreqHz = ReadBEUInt32(frameData, MainFreqOffset);
            uint subFreqHz  = ReadBEUInt32(frameData, SubFreqOffset);

            int  mainSpanIdx = frameData[SpanIndexOffset]    & 0x0F;
            int  subSpanIdx  = frameData[SubSpanIndexOffset] & 0x0F;
            uint mainSpanHz  = (uint)mainSpanIdx < (uint)SpanTableHz.Length ? SpanTableHz[mainSpanIdx] : 0;
            uint subSpanHz   = (uint)subSpanIdx  < (uint)SpanTableHz.Length ? SpanTableHz[subSpanIdx]  : 0;

            FrameReceived?.Invoke(new ScopeFrame(
                mainSpe, subSpe, frameData, mainFreqHz, subFreqHz, mainSpanHz, subSpanHz));
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
        /// MAIN receiver spectrum — 132 bytes, bin 0 = lowest frequency.
        /// Each byte is a single-byte amplitude: 0 = no signal, 255 = max.
        /// Derived from the newest ring row (bytes 132–263 of each row = MAIN).
        /// Typical noise floor: ~60–80 (quiet band), ~170–210 (busy FT8 band).
        /// Hz per bin ≈ SpanHz / 132.
        /// </summary>
        public byte[] MainSpe
        {
            get;
        }

        /// <summary>
        /// SUB receiver spectrum — 132 bytes, same encoding as MainSpe.
        /// Derived from the newest ring row (bytes 0–131 of each row = SUB).
        /// </summary>
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
        /// MAIN scope span in Hz (from frame metadata at SpanIndexOffset). Zero if unknown.
        /// </summary>
        public uint SpanHz
        {
            get;
        }

        /// <summary>
        /// SUB scope span in Hz (from frame metadata at SubSpanIndexOffset). Zero if unknown.
        /// </summary>
        public uint SubSpanHz
        {
            get;
        }

        /// <summary>Convenience: MAIN centre frequency in MHz.</summary>
        public double MainFrequencyMHz => MainFrequencyHz / 1_000_000.0;

        /// <summary>Convenience: SUB centre frequency in MHz.</summary>
        public double SubFrequencyMHz => SubFrequencyHz / 1_000_000.0;

        /// <summary>Hz per MAIN spectrum bin. Zero if span unknown.</summary>
        public double HzPerBin => SpanHz > 0 ? SpanHz / (double)ScopeChannel.SpeBins : 0;

        /// <summary>Hz per SUB spectrum bin. Zero if span unknown.</summary>
        public double SubHzPerBin => SubSpanHz > 0 ? SubSpanHz / (double)ScopeChannel.SpeBins : 0;

        public ScopeFrame(
            byte[] mainSpe, byte[] subSpe, byte[] rawFrame,
            uint mainFreqHz, uint subFreqHz, uint spanHz, uint subSpanHz)
        {
            MainSpe = mainSpe;
            SubSpe = subSpe;
            RawFrame = rawFrame;
            MainFrequencyHz = mainFreqHz;
            SubFrequencyHz = subFreqHz;
            SpanHz = spanHz;
            SubSpanHz = subSpanHz;
        }
    }
}
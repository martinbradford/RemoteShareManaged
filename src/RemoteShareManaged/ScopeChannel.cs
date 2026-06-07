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
    ///   SCOPE FRAME LAYOUT (4096 bytes, confirmed from binary analysis 2026-06-07):
    ///
    ///     0x0000–0x0737  Spectrum ring buffer: 7 rows × 264 bytes = 1848 bytes.
    ///                    Each row layout: [MAIN: 132 bytes][SUB: 132 bytes].
    ///                    Single-byte amplitude per bin: higher = stronger signal.
    ///                    Bin 0 = lowest frequency, bin 131 = highest.
    ///                    The SCU writes one new row per frame, advancing a circular
    ///                    write pointer through rows 0–6. The newest row contains the
    ///                    current instantaneous spectrum; older rows retain recent history.
    ///                    FastDrawHelper.dll applies max-hold across all 7 rows to render
    ///                    the SPE display — we do the same.
    ///                    SpeBins = 132 per channel. Hz/bin ≈ span_Hz / 132.
    ///
    ///     0x0738–0x083F  Oscilloscope data (264 bytes per channel).
    ///                    Blanked by zeroing this region in experiments.
    ///
    ///     0x0840–0x0A4F  AF-FFT and additional oscilloscope data.
    ///
    ///     0x0B00–0x0FFF  Metadata block:
    ///                    0x0BF2  span index byte   (& 0x0F → FD CAT index 0–9)
    ///                    0x0BFC  VFO A freq         BE uint32, Hz
    ///                    0x0C16  VFO B freq         BE uint32, Hz
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

        // ── Spectrum ring buffer layout (confirmed 2026-06-07) ──────────────────
        //
        // Ring: 7 rows × 264 bytes = 0x0000–0x0737.
        // Each row: bytes   0–131 = MAIN SPE (132 bins, single-byte amplitude)
        //           bytes 132–263 = SUB  SPE (132 bins, single-byte amplitude)
        //
        // Single-byte amplitude encoding:
        //   0   = no signal (or uninitialised)
        //   ~60 = quiet band noise floor (confirmed: SUB on 40m with no signals)
        //   ~170-220 = busy FT8 band bins
        //   255 = maximum signal
        //
        // FastDrawHelper.dll applies MAX-HOLD across all 7 rows for the SPE
        // display (wf_len=264, 2 px/bin × 132 bins). We do the same.
        //
        // SpeBins = 132 per channel. Hz/bin ≈ SpanHz / 132.
        // Bin 0 = lowest frequency, bin 131 = highest.
        public const int RingRows     = 7;
        public const int RingRowBytes = 264;   // 132 MAIN + 132 SUB
        public const int SpeBins      = 132;   // bins per channel

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
        private int _frameCount;
        private long _nextDiagTick;
        private long _nextSubDiagTick;    // 1-second SUB correlation diagnostic
        private bool _metaScanDone;       // one-shot metadata scanner
        private byte[]? _prevFrameData;   // previous frame for delta-based newest-row detection
        private long[]? _lastRowDeltas;   // per-row deltas from most recent ExtractNewestRow call


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
            _metaScanDone = false;   // re-run scan on every new connection

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

            _frameCount++;
            ExtractAndRaise(frameData);
        }

        // -----------------------------------------------------------------------
        // SPE extraction
        // -----------------------------------------------------------------------

        // Row 6 (the last ring row) is always the freshest instantaneous FFT snapshot.
        // Rows 0–5 are older max-hold accumulations. Confirmed empirically (2026-06-07):
        //   row 6 MAIN mean ≈ 158–161  (rows 0–5: 178–188 — saturated max-hold)
        //   row 6 SUB  mean ≈  54–61  (rows 0–5: 174–187 — old max-hold from prior freq)
        // The SUB channel being on 8 MHz (quiet noise floor) is only reflected in row 6;
        // rows 0–5 still carry max-hold residue from earlier SUB frequencies.
        private const int NewestRingRow = RingRows - 1;   // = 6

        /// <summary>
        /// Extract MAIN and SUB SPE from the newest ring row (row 6 — always freshest).
        /// Also fills <paramref name="rowDeltasOut"/> with per-row MAIN-channel deltas
        /// for diagnostic use (does not affect row selection).
        /// </summary>
        private static (int bestRow, byte[] mainSpe, byte[] subSpe) ExtractNewestRow(
            byte[] frameData, byte[]? prevFrameData, long[]? rowDeltasOut = null)
        {
            // Capture per-row deltas for diagnostics only.
            if (rowDeltasOut != null && prevFrameData != null &&
                prevFrameData.Length >= RingRows * RingRowBytes)
            {
                for (int row = 0; row < RingRows; row++)
                {
                    int rb = row * RingRowBytes;
                    long delta = 0;
                    for (int b = 0; b < SpeBins; b++)
                        delta += Math.Abs(frameData[rb + b] - prevFrameData[rb + b]);
                    if (row < rowDeltasOut.Length) rowDeltasOut[row] = delta;
                }
            }

            int best = NewestRingRow * RingRowBytes;
            var mainSpe = new byte[SpeBins];
            var subSpe  = new byte[SpeBins];
            Array.Copy(frameData, best,           mainSpe, 0, SpeBins);
            Array.Copy(frameData, best + SpeBins, subSpe,  0, SpeBins);
            return (NewestRingRow, mainSpe, subSpe);
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
            // Find the newest ring row via frame delta (primary) or variance (fallback).
            if (_lastRowDeltas == null) _lastRowDeltas = new long[RingRows];
            var (selectedRow, mainSpe, subSpe) = ExtractNewestRow(frameData, _prevFrameData, _lastRowDeltas);
            // Save a copy AFTER extraction (so _lastRowDeltas captured real deltas above).
            if (_prevFrameData == null || _prevFrameData.Length != frameData.Length)
                _prevFrameData = new byte[frameData.Length];
            Array.Copy(frameData, _prevFrameData, RingRows * RingRowBytes);

            uint mainFreqHz = ReadBEUInt32(frameData, MainFreqOffset);
            uint subFreqHz  = ReadBEUInt32(frameData, SubFreqOffset);

            int  mainSpanIdx = frameData[SpanIndexOffset]    & 0x0F;
            int  subSpanIdx  = frameData[SubSpanIndexOffset] & 0x0F;
            uint mainSpanHz  = (uint)mainSpanIdx < (uint)SpanTableHz.Length ? SpanTableHz[mainSpanIdx] : 0;
            uint subSpanHz   = (uint)subSpanIdx  < (uint)SpanTableHz.Length ? SpanTableHz[subSpanIdx]  : 0;

            // ── One-shot metadata scanner ────────────────────────────────────────
            // Scans the entire metadata region (0x0B54-0x0FFF) on the first frame
            // and logs every BE uint32 value that looks like an HF frequency
            // (1 MHz – 30 MHz range).  Use this to find the true SubFreqOffset
            // when the compile-time constant gives the wrong value.
            if (!_metaScanDone)
            {
                _metaScanDone = true;

                // 1. HF frequency scan (1–30 MHz as BE uint32)
                var hits = new System.Text.StringBuilder();
                for (int off = 0x0B54; off <= 0x0FFC; off++)
                {
                    if (off + 3 >= frameData.Length) break;
                    uint v = ReadBEUInt32(frameData, off);
                    if (v >= 1_000_000 && v <= 30_000_000)
                        hits.Append($"  0x{off:X4}={v}");
                }
                _log.LogInformation("[MetaScan] HF-range BE-uint32 hits in 0x0B54-0x0FFF:{H}", hits);

                // 2. Span-index byte dump around MAIN span (0x0BF2) and SUB span candidate (0x0C0C).
                // Looking for bytes whose lower nibble = valid span index (0–9).
                // MAIN span confirmed at 0x0BF2.  The correct SUB span offset should have
                // lower nibble matching the SUB scope span set on the radio.
                // Dump raw hex for 0x0BE0–0x0C20 so we can compare by eye.
                var spanDump = new System.Text.StringBuilder();
                for (int off = 0x0BE0; off <= 0x0C20 && off < frameData.Length; off++)
                    spanDump.Append($"  {off:X4}:{frameData[off]:X2}");
                _log.LogInformation("[MetaScan] Byte dump 0x0BE0-0x0C20 (MAIN span@0x0BF2, SUB span?): {D}", spanDump);
                _log.LogInformation("[MetaScan] MAIN span idx={MI} ({MH}Hz)  SUB span idx={SI} ({SH}Hz) [current offsets]",
                    mainSpanIdx, mainSpanHz, subSpanIdx, subSpanHz);
            }

            // ── Diagnostic every 5s ──────────────────────────────────────────────
            long now = System.Diagnostics.Stopwatch.GetTimestamp();
            if (now >= _nextDiagTick)
            {
                _nextDiagTick = now + System.Diagnostics.Stopwatch.Frequency * 5;
                byte speMin = mainSpe[0], speMax = mainSpe[0];
                double speSum = 0;
                for (int i = 0; i < SpeBins; i++)
                {
                    if (mainSpe[i] < speMin) speMin = mainSpe[i];
                    if (mainSpe[i] > speMax) speMax = mainSpe[i];
                    speSum += mainSpe[i];
                }
                double subSum = 0;
                byte subMin = subSpe[0], subMax = subSpe[0];
                for (int i = 0; i < SpeBins; i++)
                {
                    subSum += subSpe[i];
                    if (subSpe[i] < subMin) subMin = subSpe[i];
                    if (subSpe[i] > subMax) subMax = subSpe[i];
                }
                // Per-row deltas — captured during ExtractNewestRow (BEFORE prevFrame update,
                // so these are genuine frame-to-frame differences, not self-comparison).
                // One row should dominate if the ring is a live cycling buffer.
                var deltaStr = _lastRowDeltas == null ? "n/a"
                    : string.Join(" ", _lastRowDeltas.Select((d, i) => $"r{i}:{d}"));
                _log.LogInformation(
                    "[Scope diag #{F}] selectedRow={R} MAIN mean={Mean:F0} min={Min} max={Max} | rowDeltas: {D}",
                    _frameCount, selectedRow, speSum / SpeBins, speMin, speMax, deltaStr);

                // Per-row means — if one row has a very different mean, it's the fresh instantaneous row.
                var rowMeans = string.Join(" ", Enumerable.Range(0, RingRows)
                    .Select(row => { double s = 0; int rb = row * RingRowBytes;
                        for (int b = 0; b < SpeBins; b++) s += frameData[rb + b];
                        return $"r{row}:{s/SpeBins:F0}"; }));
                _log.LogInformation("[Scope diag #{F}] rowMeans: {RM}", _frameCount, rowMeans);

                // SUB row means — if MAIN/SUB are separate, one row might show low SUB mean.
                var subRowMeans = string.Join(" ", Enumerable.Range(0, RingRows)
                    .Select(row => { double s = 0; int rb = row * RingRowBytes + SpeBins;
                        for (int b = 0; b < SpeBins; b++) s += frameData[rb + b];
                        return $"r{row}:{s/SpeBins:F0}"; }));
                _log.LogInformation("[Scope diag #{F}] subRowMeans(last132): {SR} SUB freq={SF}",
                    _frameCount, subRowMeans, subFreqHz);
            }

            // ── 1-second SUB correlation diagnostic ─────────────────────────────
            // Logs SUB mean+max every second so fluctuations can be correlated
            // against the 15s FT8 TX/RX cycle.  If subMax rises during FT8 TX
            // periods the data has real RF content; if it tracks MAIN audio it
            // suggests the bytes we are reading are not the SUB RF spectrum.
            if (now >= _nextSubDiagTick)
            {
                _nextSubDiagTick = now + System.Diagnostics.Stopwatch.Frequency;
                double subSum2 = 0; byte subMax2 = 0;
                for (int i = 0; i < SpeBins; i++)
                {
                    subSum2 += subSpe[i];
                    if (subSpe[i] > subMax2) subMax2 = subSpe[i];
                }
                double mainSum2 = 0; byte mainMax2 = 0;
                for (int i = 0; i < SpeBins; i++)
                {
                    mainSum2 += mainSpe[i];
                    if (mainSpe[i] > mainMax2) mainMax2 = mainSpe[i];
                }
                _log.LogInformation(
                    "[Scope 1s #{F}] MAIN mean={MM:F0} max={MX}  SUB mean={SM:F0} max={SX}  subFreq={SF}",
                    _frameCount,
                    mainSum2 / SpeBins, mainMax2,
                    subSum2  / SpeBins, subMax2, subFreqHz);
            }

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
        /// Derived by max-hold across all 7 ring rows (bytes 0–131 of each row).
        /// Typical noise floor: ~60–80 (quiet band), ~170–210 (busy FT8 band).
        /// Hz per bin ≈ SpanHz / 132.
        /// </summary>
        public byte[] MainSpe
        {
            get;
        }

        /// <summary>
        /// SUB receiver spectrum — 132 bytes, same encoding as MainSpe.
        /// Derived by max-hold across all 7 ring rows (bytes 132–263 of each row).
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
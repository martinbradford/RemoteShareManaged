using System.Buffers;
using System.Threading.Channels;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using NAudio.Wave;
using RemoteShareManaged.Codec;
using RemoteShareManaged.Protocol;
using RemoteShareManaged.Transport;

namespace RemoteShareManaged;

/// <summary>
/// Full-duplex audio channel over SCU-LAN10 port 50002.
///
/// Wire format (confirmed from Wireshark captures):
///   RX  SCU→PC  ZZ type 0xa2, FUN header 24 bytes + 640 bytes audio payload
///   TX  PC→SCU  ZZ type 0xa6, FUN header 32 bytes + 642 bytes audio payload
///
///   Audio quality is selected via <see cref="AudioQuality"/>:
///     PCM 16 kHz  — 16-bit stereo PCM,  best quality,  ~160 kbps
///     u-Law 16 kHz — µ-law companded,   natural HF rolloff,  ~80 kbps
///     PCM 8 kHz   — 16-bit stereo PCM,  half bandwidth
///     u-Law 8 kHz  — µ-law 8 kHz,       lowest bandwidth, best for slow WAN
///
///   For u-Law modes the RX pump applies NAudio MuLawDecoder before playback.
///   For 8 kHz modes WireFormat is adjusted to 8000 Hz accordingly.
///
///   The SCU sends 4 interleaved copies of each ~10 ms audio frame for WAN loss
///   resilience. All copies are fed to the playback buffer — no deduplication needed.
///
///   Stereo layout: main RX on L (after L↔R swap), sub-RX on R.
///   PTT is handled externally via ScuSession.SendCatAsync("TX;") / "RX;".
///
/// Usage:
///   var audio = new AudioChannel(addr, nonce, () => nextSeq(), channelOpen,
///                                quality: AudioQuality.Pcm16k, loggerFactory);
///   await audio.StartAsync();
///   // ...
///   await audio.StopAsync();
/// </summary>
public sealed class AudioChannel : IAsyncDisposable
{
    // ── Wire format constants (confirmed from captures) ───────────────────────

    /// <summary>NAudio WaveFormat for the current audio quality setting.</summary>
    public WaveFormat WireFormat => _quality switch
    {
        AudioQuality.Pcm8k  or AudioQuality.ULaw8k  => new WaveFormat(8_000,  16, 2),
        _                                             => new WaveFormat(16_000, 16, 2),
    };

    /// <summary>True when the current quality uses µ-law encoding.</summary>
    private bool IsULaw => _quality is AudioQuality.ULaw16k or AudioQuality.ULaw8k;

    private const int RxPcmBytes  = 640;   // audio payload per RX packet
    private const int TxPcmBytes  = 642;   // TX payload — needs separate verification

    // RX FUN header size before audio payload.
    // Confirmed from Wireshark for both PCM and u-Law modes:
    //   fun[28:30] = 0x0280 (640) — audio payload length field
    //   8 + 30 + 640 = 678 = raw packet length exactly
    // Both PCM and u-Law modes use the same 30-byte header.
    private const int FunHdrBytes = 30;

    // ── State ─────────────────────────────────────────────────────────────────

    private readonly ILogger<AudioChannel> _log;
    private readonly ILoggerFactory _loggerFactory;
    private readonly string _addr;
    private readonly byte _helloAckNonce;
    private readonly Func<byte> _nextSeq;
    private readonly Func<RemotePath, CancellationToken, Task> _channelOpen;
    private readonly AudioQuality _quality;
    private readonly int _waveOutDevice;

    private RemotePath? _path;
    private WaveOutEvent? _waveOut;
    private BufferedWaveProvider? _rxBuffer;
    private WaveInEvent? _waveIn;

    private CancellationTokenSource _cts = new();
    private Task? _rxPumpTask;
    private Task? _txPumpTask;

    // TX: fun[10] frame counter — same value in both packets of a pair,
    // then incremented. Wraps naturally through 0xff.
    private byte _txFrameSeq;

    public bool IsRunning
    {
        get; private set;
    }

    // ── Constructor ───────────────────────────────────────────────────────────

    /// <param name="addr">SCU-LAN10 IP address.</param>
    /// <param name="helloAckNonce">Session nonce (dec[5] from HELLO-ACK).</param>
    /// <param name="nextSeq">Returns the next ZZ sequence byte, shared with
    ///   ScuSession so all ports use one monotonic counter.</param>
    /// <param name="loggerFactory">Optional logger factory.</param>
    public AudioChannel(
        string addr,
        byte helloAckNonce,
        Func<byte> nextSeq,
        Func<RemotePath, CancellationToken, Task> channelOpen,
        AudioQuality quality = AudioQuality.Pcm16k,
        int waveOutDevice = 0,
        ILoggerFactory? loggerFactory = null)
    {
        _addr = addr;
        _helloAckNonce = helloAckNonce;
        _nextSeq = nextSeq;
        _channelOpen = channelOpen;
        _quality = quality;
        _waveOutDevice = waveOutDevice;
        _loggerFactory = loggerFactory ?? NullLoggerFactory.Instance;
        _log = _loggerFactory.CreateLogger<AudioChannel>();
    }

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    public async Task StartAsync(CancellationToken ct = default)
    {
        if (IsRunning)
            return;

        _cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        _path = new RemotePath(_addr, ScuPorts.Audio,
                    _loggerFactory.CreateLogger<RemotePath>());
        _path.Open();

        // Give the receive loop a moment to start and drain any ICMP errors
        // that the SCU may have sent at the end of the previous session.
        // Without this, WSAECONNRESET from a stale ICMP can poison early sends
        // even with SIO_UDP_CONNRESET disabled on some Windows configurations.
        await Task.Delay(100, ct);

        // RX playback.
        //
        // Declare the buffer at wire rate (16 kHz stereo 16-bit) — identical to
        // what the Yaesu DLL does.  WaveOutEvent passes this format to Windows MME
        // which routes it through the kernel-mode resampler (DME / WASAPI shared
        // mode) to the device's native rate.  This gives significantly higher
        // quality than any application-level upsampling, and eliminates the
        // fill/drain rate mismatch that caused underruns with the 48 kHz buffer.
        //
        // Buffer sized at 1000 ms + DesiredLatency 500 ms to absorb WAN jitter
        // (over-the-internet sessions can see occasional 50–100 ms packet gaps).
        _rxBuffer = new BufferedWaveProvider(WireFormat)
        {
            BufferDuration = TimeSpan.FromMilliseconds(1000),
            DiscardOnBufferOverflow = true,
        };
        _waveOut = new WaveOutEvent { DesiredLatency = 500, DeviceNumber = _waveOutDevice };
        _waveOut.Init(_rxBuffer);
        _waveOut.Play();

        // TX capture — 10 ms buffer matches our send cadence.
        _waveIn = new WaveInEvent
        {
            WaveFormat = WireFormat,
            BufferMilliseconds = 10,
        };

        IsRunning = true;

        // Run the port 50002 handshake (SendDevPortConnect + SendDevPortOpen)
        // before starting the pumps so the SCU is ready to send RX audio.
        await _channelOpen(_path, _cts.Token);

        _rxPumpTask = Task.Run(RxPumpAsync, _cts.Token);
        _txPumpTask = Task.Run(TxPumpAsync, _cts.Token);

        _log.LogInformation("AudioChannel started — {Quality} ({Rate} Hz stereo 16-bit)",
            _quality, WireFormat.SampleRate);
        await Task.CompletedTask;
    }

    public async Task StopAsync()
    {
        if (!IsRunning)
            return;
        IsRunning = false;
        _cts.Cancel();

        // Clear the playback buffer first so WaveOut stops immediately rather
        // than continuing to play whatever PCM was already queued in it.
        _rxBuffer?.ClearBuffer();
        _waveIn?.StopRecording();
        _waveOut?.Stop();

        // Close the RemotePath BEFORE waiting for the pump tasks.
        // RxPumpAsync blocks on _path.Frames.ReadAllAsync(_cts.Token) — cancelling
        // _cts only unblocks it when the channel reader is waiting. Completing the
        // channel writer (via CloseAsync) guarantees ReadAllAsync exits immediately.
        if (_path is not null)
        {
            await _path.CloseAsync();
            _path = null;
        }

        var tasks = new[] { _rxPumpTask, _txPumpTask }
            .Where(t => t is not null).Select(t => t!);
        try
        {
            await Task.WhenAll(tasks).WaitAsync(TimeSpan.FromSeconds(3));
        }
        catch { /* timeout fine */ }

        _waveOut?.Dispose();
        _waveOut = null;
        _waveIn?.Dispose();
        _waveIn = null;
        _rxBuffer = null;
        _log.LogInformation("AudioChannel stopped");
    }

    // ── RX pump — SCU→PC audio (type 0xa2) ───────────────────────────────────

    private async Task RxPumpAsync()
    {
        _log.LogDebug("RX audio pump started");

        // For u-Law modes: each wire byte is one µ-law sample which expands to
        // a 16-bit PCM sample, so the output buffer is 2× the input size.
        const int PcmUsable = (RxPcmBytes / 4) * 4;  // 640 — frame-aligned
        int pcmBufSize = IsULaw ? PcmUsable * 2 : PcmUsable;
        byte[] pcm = ArrayPool<byte>.Shared.Rent(pcmBufSize);

        try
        {
            await foreach (var frame in _path!.Frames.ReadAllAsync(_cts.Token))
            {
                if (frame.ZzType != 0xa2)
                    continue;

                var raw = frame.Raw;
                if (raw.Length < 8 + FunHdrBytes + 4)
                    continue;

                byte kl = raw[6], kh = raw[7];

                int limit = Math.Min(raw.Length - (8 + FunHdrBytes), PcmUsable);
                limit = (limit / 4) * 4;
                if (limit < 4)
                    continue;

                // FUN-decode audio payload into pcm[]
                for (int i = 0; i < limit; i++)
                {
                    int fi = FunHdrBytes + i;
                    pcm[i] = (byte)(((~fi + 1) & 0xff) ^ raw[8 + fi] ^ kl ^ kh);
                }

                if (IsULaw)
                {
                    // µ-law: each decoded byte is one sample — expand to 16-bit PCM.
                    // Decode backwards so we can expand in-place without a second buffer.
                    // Wire stereo: [L_ulaw, R_ulaw, ...] → [L_lo, L_hi, R_lo, R_hi, ...]
                    int outLen = limit * 2;
                    for (int i = limit - 1; i >= 0; i--)
                    {
                        short s = NAudio.Codecs.MuLawDecoder.MuLawToLinearSample(pcm[i]);
                        pcm[i * 2]     = (byte)(s & 0xFF);
                        pcm[i * 2 + 1] = (byte)(s >> 8);
                    }
                    SwapAndAdd(pcm, outLen);
                }
                else
                {
                    SwapAndAdd(pcm, limit);
                }
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) { _log.LogError(ex, "RX audio pump error"); }
        finally { ArrayPool<byte>.Shared.Return(pcm); }

        _log.LogDebug("RX audio pump stopped");
    }

    /// <summary>
    /// Swap L↔R channel pairs in-place then add to <see cref="_rxBuffer"/>.
    /// Avoids allocating a separate byte[] on every packet.
    /// </summary>
    private void SwapAndAdd(byte[] pcm, int len)
    {
        // Each stereo frame is 4 bytes: [L_lo, L_hi, R_lo, R_hi]
        // Swap to [R_lo, R_hi, L_lo, L_hi]
        for (int i = 0; i < len; i += 4)
        {
            (pcm[i], pcm[i + 2]) = (pcm[i + 2], pcm[i]);
            (pcm[i + 1], pcm[i + 3]) = (pcm[i + 3], pcm[i + 1]);
        }
        _rxBuffer!.AddSamples(pcm, 0, len);
    }

    // ── TX pump — PC→SCU audio (type 0xa6) ───────────────────────────────────

    private async Task TxPumpAsync()
    {
        _log.LogDebug("TX audio pump started");

        // Bounded channel: WaveIn DataAvailable → TX timer loop.
        // DropOldest keeps the stream live if the timer lags briefly.
        var micCh = Channel.CreateBounded<byte[]>(
            new BoundedChannelOptions(20) { FullMode = BoundedChannelFullMode.DropOldest });

        _waveIn!.DataAvailable += (_, e) =>
        {
            if (e.BytesRecorded <= 0)
                return;
            var buf = new byte[e.BytesRecorded];
            Buffer.BlockCopy(e.Buffer, 0, buf, 0, e.BytesRecorded);
            micCh.Writer.TryWrite(buf);
        };
        _waveIn.StartRecording();

        // Accumulator: collect mic chunks until we have a full TX frame.
        byte[] acc = new byte[TxPcmBytes];
        int fill = 0;

        try
        {
            using var timer = new PeriodicTimer(TimeSpan.FromMilliseconds(10));
            while (await timer.WaitForNextTickAsync(_cts.Token))
            {
                // Drain available mic data.
                while (fill < TxPcmBytes && micCh.Reader.TryRead(out var chunk))
                {
                    int copy = Math.Min(chunk.Length, TxPcmBytes - fill);
                    Buffer.BlockCopy(chunk, 0, acc, fill, copy);
                    fill += copy;
                }

                // Use accumulated data, or silence if not enough arrived.
                byte[] pcm;
                if (fill >= TxPcmBytes)
                {
                    pcm = acc;
                    acc = new byte[TxPcmBytes];
                    fill = 0;
                }
                else
                {
                    pcm = new byte[TxPcmBytes];  // silence (all zeros)
                }

                // Build FUN payload once; both packets in the pair are identical.
                byte[] funPayload = BuildTxFunPayload(pcm);
                _path!.Send(ZzFrameCodec.BuildFunFrame(0xa6, _nextSeq(), funPayload));
                _path!.Send(ZzFrameCodec.BuildFunFrame(0xa6, _nextSeq(), funPayload));

                // Advance frame counter after the pair.
                _txFrameSeq++;
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) { _log.LogError(ex, "TX audio pump error"); }

        _waveIn?.StopRecording();
        _log.LogDebug("TX audio pump stopped");
    }

    // ── TX FUN payload builder ────────────────────────────────────────────────

    /// <summary>
    /// Build the 32-byte FUN header + PCM payload passed to BuildFunFrame.
    ///
    /// Header confirmed byte-by-byte from Wireshark captures.
    /// All bytes are fixed except fun[10] (_txFrameSeq — same across both
    /// packets of a pair, incremented after the pair is sent).
    ///
    ///   [0:2]   0x02 0x00  FUN len field
    ///   [2:4]   0x05 0x01  MID 0x0105 LE (UsbAudio_Write)
    ///   [4:6]   0x9c 0x02  payload size 668 LE
    ///   [6]     0x14       sub-type / device id
    ///   [7]     0x00
    ///   [8:10]  0x00 0x00
    ///   [10]    frameSeq   per-pair frame counter (low byte)
    ///   [11]    0x65       frame counter high byte (fixed in all captures)
    ///   [12]    0x01       PCM format
    ///   [13]    0x02       channel count (2 = stereo)
    ///   [14:16] 0x80 0x3e  0x3e80 = 16000 audio bandwidth Hz
    ///   [16:18] 0x00 0x00
    ///   [18]    0x01
    ///   [19:26] 0x00 * 7
    ///   [26:28] 0xd0 0x07  2000 LE (send buffer, ms)
    ///   [28:30] 0xd0 0x07  2000 LE (recv buffer, ms)
    ///   [30]    0x64       volume 100
    ///   [31]    0x64       volume 100
    ///   [32:]   PCM (TxPcmBytes bytes, 32 kHz stereo 16-bit LE)
    /// </summary>
    private byte[] BuildTxFunPayload(byte[] pcm)
    {
        var fun = new byte[FunHdrBytes + TxPcmBytes];

        fun[0] = 0x02;
        fun[1] = 0x00;
        fun[2] = 0x05;
        fun[3] = 0x01;
        fun[4] = 0x9c;
        fun[5] = 0x02;
        fun[6] = 0x14;
        fun[7] = 0x00;
        fun[8] = 0x00;
        fun[9] = 0x00;
        fun[10] = _txFrameSeq;
        fun[11] = 0x65;
        fun[12] = 0x01;
        fun[13] = 0x02;
        fun[14] = 0x80;
        fun[15] = 0x3e;
        fun[16] = 0x00;
        fun[17] = 0x00;
        fun[18] = 0x01;
        // fun[19..25] = 0x00 by default
        fun[26] = 0xd0;
        fun[27] = 0x07;
        fun[28] = 0xd0;
        fun[29] = 0x07;
        fun[30] = 0x64;
        fun[31] = 0x64;

        Buffer.BlockCopy(pcm, 0, fun, FunHdrBytes, TxPcmBytes);
        return fun;
    }

    // ── IAsyncDisposable ──────────────────────────────────────────────────────

    public async ValueTask DisposeAsync()
    {
        await StopAsync();
        _cts.Dispose();
    }
}
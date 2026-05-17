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
/// Wire format (confirmed from Wireshark captures, stereo 32 kHz 16-bit LE):
///   RX  SCU→PC  ZZ type 0xa2, FUN MID 0x0185, 32-byte FUN header + 638 bytes PCM
///   TX  PC→SCU  ZZ type 0xa6, FUN MID 0x0105, 32-byte FUN header + 642 bytes PCM
///
///   Each 10 ms frame is sent as an exact duplicate pair (WAN loss resilience).
///   The SCU deduplicates on fun[6] (the FUN-level frame sequence byte).
///   RX pairs are similarly deduplicated before feeding the audio buffer.
///
///   Stereo layout: L = main receiver / main TX, R = sub-receiver (silent if off).
///
///   PTT is handled externally via ScuSession.SendCatAsync("TX;") / "RX;".
///   TX audio (silence when not transmitting) streams continuously — the SCU
///   requires an uninterrupted flow in both directions.
///
/// Usage:
///   var audio = new AudioChannel(addr, helloAckNonce, () => nextSeq(), loggerFactory);
///   await audio.StartAsync();
///   // ...
///   await audio.StopAsync();
/// </summary>
public sealed class AudioChannel : IAsyncDisposable
{
    // ── Wire format constants (confirmed from captures) ───────────────────────

    /// <summary>NAudio WaveFormat matching the SCU-LAN10 audio stream.</summary>
    /// Stereo 16 kHz 16-bit signed LE (Yaesu "PCM 16kHz" setting).
    /// Packets arrive as identical duplicate pairs; only one of each pair
    /// is fed to the audio buffer (deduplication on fun[6]).
    /// 100 unique packets/sec × 638 bytes = 63,800 bytes/sec ≈ 16,000 × 4.
    public static readonly WaveFormat WireFormat =
        new WaveFormat(rate: 16_000, bits: 16, channels: 2);

    private const int RxPcmBytes = 638;  // PCM payload per RX packet (fun[32:])
    private const int TxPcmBytes = 642;  // PCM payload per TX packet (fun[32:])
    private const int FunHdrBytes = 32;   // FUN header size before PCM

    // ── State ─────────────────────────────────────────────────────────────────

    private readonly ILogger<AudioChannel> _log;
    private readonly string _addr;
    private readonly byte _helloAckNonce;
    private readonly Func<byte> _nextSeq;
    private readonly Func<RemotePath, CancellationToken, Task> _channelOpen;

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

    // RX: last fun[6] seen — for duplicate suppression.
    private byte _lastRxSeq = 0xff;

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
        ILoggerFactory? loggerFactory = null)
    {
        _addr = addr;
        _helloAckNonce = helloAckNonce;
        _nextSeq = nextSeq;
        _channelOpen = channelOpen;
        _log = (loggerFactory ?? NullLoggerFactory.Instance).CreateLogger<AudioChannel>();
    }

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    public async Task StartAsync(CancellationToken ct = default)
    {
        if (IsRunning)
            return;

        _cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        _path = new RemotePath(_addr, ScuPorts.Audio,
                    NullLoggerFactory.Instance.CreateLogger<RemotePath>());
        _path.Open();

        // RX playback.
        // Declare the buffer at 48 kHz (device native rate) so WaveOutEvent
        // drains at exactly the rate we fill. We upsample 16→48 kHz manually
        // in RxPumpAsync by repeating each frame 3× before adding to the buffer.
        // Buffer duration kept short (200ms) to avoid overflow-discard ticks.
        _rxBuffer = new BufferedWaveProvider(new WaveFormat(48000, 16, 2))
        {
            BufferDuration = TimeSpan.FromMilliseconds(200),
            DiscardOnBufferOverflow = true,
        };
        _waveOut = new WaveOutEvent { DesiredLatency = 150 };
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

        _log.LogInformation("AudioChannel started — 32 kHz stereo 16-bit");
        await Task.CompletedTask;
    }

    public async Task StopAsync()
    {
        if (!IsRunning)
            return;
        IsRunning = false;
        _cts.Cancel();

        _waveIn?.StopRecording();
        _waveOut?.Stop();

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

        if (_path is not null)
        {
            await _path.CloseAsync();
            _path = null;
        }
        _log.LogInformation("AudioChannel stopped");
    }

    // ── RX pump — SCU→PC audio (type 0xa2) ───────────────────────────────────

    private async Task RxPumpAsync()
    {
        _log.LogDebug("RX audio pump started");
        try
        {
            await foreach (var frame in _path!.Frames.ReadAllAsync(_cts.Token))
            {
                if (frame.ZzType != 0xa2)
                    continue;

                var raw = frame.Raw;
                if (raw.Length < 8 + FunHdrBytes + 2)
                    continue;

                byte kl = raw[6], kh = raw[7];

                // Deduplicate on fun[6].
                // FUN decode formula: fun[i] = (~i+1 & 0xff) ^ raw[8+i] ^ kl ^ kh
                // For i=6: (~7 & 0xff) = 0xf9
                byte rxSeq = (byte)(0xf9 ^ raw[14] ^ kl ^ kh);
                if (rxSeq == _lastRxSeq)
                    continue;
                _lastRxSeq = rxSeq;

                // FUN-decode the PCM region: fun[32..32+RxPcmBytes]
                int pcmLen = Math.Min(raw.Length - (8 + FunHdrBytes), RxPcmBytes);
                if (pcmLen < 2)
                    continue;

                byte[] pcm = new byte[pcmLen];
                for (int i = 0; i < pcmLen; i++)
                {
                    int fi = FunHdrBytes + i;  // index within fun[]
                    pcm[i] = (byte)(((~fi + 1) & 0xff) ^ raw[8 + fi] ^ kl ^ kh);
                }

                var upsampled = Upsample16To48(pcm, pcmLen);
                _rxBuffer!.AddSamples(upsampled, 0, upsampled.Length);
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) { _log.LogError(ex, "RX audio pump error"); }
        _log.LogDebug("RX audio pump stopped");
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

    // ── Resampling ────────────────────────────────────────────────────────────

    /// <summary>
    /// Upsample stereo 16 kHz 16-bit PCM to stereo 48 kHz by nearest-neighbour
    /// (repeat each input frame 3 times). Alias products land at 16/32 kHz,
    /// well above the HF audio passband, and are filtered by WSJT-X and other
    /// decoders internally. Signal energy at all in-band frequencies is preserved
    /// perfectly — unlike linear interpolation which acts as a low-pass filter.
    /// </summary>
    private static byte[] Upsample16To48(byte[] src, int srcLen)
    {
        srcLen = (srcLen / 4) * 4;  // clamp to whole stereo frames
        int frames = srcLen / 4;
        byte[] dst = new byte[frames * 4 * 3];
        int di = 0;
        for (int f = 0; f < frames; f++)
        {
            byte b0 = src[f * 4], b1 = src[f * 4 + 1], b2 = src[f * 4 + 2], b3 = src[f * 4 + 3];
            // Swap L↔R to match Yaesu channel assignment (main RX on L, sub RX on R)
            dst[di++] = b2;
            dst[di++] = b3;
            dst[di++] = b0;
            dst[di++] = b1;
            dst[di++] = b2;
            dst[di++] = b3;
            dst[di++] = b0;
            dst[di++] = b1;
            dst[di++] = b2;
            dst[di++] = b3;
            dst[di++] = b0;
            dst[di++] = b1;
        }
        return dst;
    }

    // ── IAsyncDisposable ──────────────────────────────────────────────────────

    public async ValueTask DisposeAsync()
    {
        await StopAsync();
        _cts.Dispose();
    }
}
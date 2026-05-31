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
/// Wire format — confirmed from Wireshark captures across all four quality modes:
///
///   16 kHz modes (PCM 16k, µ-Law 16k):
///     RX  SCU→PC  ZZ type 0xa2, 30-byte FUN header + 640 bytes 16-bit stereo PCM
///     TX  PC→SCU  ZZ type 0xa6, 30-byte FUN header + 642 bytes PCM
///     Packet size: 678 bytes RX / 682 bytes TX,  ~200 pkts/sec
///
///   8 kHz modes (PCM 8k, µ-Law 8k):
///     RX  SCU→PC  ZZ type 0xc2, 30-byte FUN header + 160 bytes 16-bit stereo PCM
///     TX  PC→SCU  ZZ type 0xc6, 32-byte FUN header + 160 bytes audio
///     Packet size: 198 bytes RX / 202 bytes TX,  ~200 pkts/sec
///
///   IMPORTANT: the SCU always sends 16-bit stereo PCM in the RX audio payload
///   regardless of whether µ-Law was requested. The codec byte in SendAudioOpen
///   is honoured only in the TX header format field — it does not affect RX.
///
///   MODE SWITCHING: Simply sending SendAudioOpen with 8k parameters is not
///   sufficient. The SCU switches to 0xc2 mode only after receiving the first
///   0xc6 TX audio packet. Therefore AudioChannel sends a silent 0xc6 frame
///   immediately after SendAudioOpen for 8k modes to trigger the switch.
///
///   Audio payload length is read from fun[28:30] in each RX packet dynamically.
///
///   The SCU sends 2 duplicate copies of each ~10 ms audio frame for WAN loss
///   resilience. All copies are fed to the playback buffer — no deduplication
///   needed.
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
    // ── Wire format constants ─────────────────────────────────────────────────

    // FUN header size before audio payload — confirmed 30 bytes for all modes.
    // Exception: 0xc6 TX uses 32-byte header (audio starts at fun[32]).
    private const int FunHdrBytesRx = 30;
    private const int FunHdrBytesTx16k = 30;
    private const int FunHdrBytesTx8k = 32;

    // ZZ type bytes
    private const byte RxType16k = 0xa2;
    private const byte TxType16k = 0xa6;
    private const byte RxType8k = 0xc2;
    private const byte TxType8k = 0xc6;

    // TX audio payload sizes (confirmed from Wireshark)
    private const int TxPcmBytes16k = 642;
    private const int TxPcmBytes8k = 160;

    // Max RX audio payload (640 bytes for 16k)
    private const int MaxRxPcmBytes = 640;

    private bool Is8k => _quality is AudioQuality.Pcm8k or AudioQuality.ULaw8k;

    /// <summary>
    /// NAudio WaveFormat for RX audio playback.
    /// The SCU always sends 16-bit stereo PCM. Sample rate is 16000 or 8000 Hz
    /// depending on AudioQuality.
    /// </summary>
    public WaveFormat WireFormat => Is8k
        ? new WaveFormat(8_000, 16, 2)
        : new WaveFormat(16_000, 16, 2);

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

    private byte _txFrameSeq;

    public bool IsRunning
    {
        get; private set;
    }

    // ── Constructor ───────────────────────────────────────────────────────────

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

        // Give the receive loop a moment to start and drain any stale ICMP errors.
        await Task.Delay(100, ct);

        var wireFormat = WireFormat;
        _rxBuffer = new BufferedWaveProvider(wireFormat)
        {
            BufferDuration = TimeSpan.FromMilliseconds(1000),
            DiscardOnBufferOverflow = true,
        };
        _waveOut = new WaveOutEvent { DesiredLatency = 500, DeviceNumber = _waveOutDevice };
        _waveOut.Init(_rxBuffer);
        _waveOut.Play();

        _waveIn = new WaveInEvent
        {
            WaveFormat = wireFormat,
            BufferMilliseconds = 10,
        };

        IsRunning = true;

        // Run the port 50002 handshake (SendAudioConnect + SendAudioOpen).
        await _channelOpen(_path, _cts.Token);

        // For 8k modes the SCU only switches from 0xa2→0xc2 RX after receiving
        // the first 0xc6 TX packet. Send a silent trigger frame now.
        if (Is8k)
        {
            byte[] silence = new byte[TxPcmBytes8k];  // all zeros = silence
            byte[] trigger = BuildTxFunPayload(silence);
            _path.Send(ZzFrameCodec.BuildFunFrame(TxType8k, _nextSeq(), trigger));
            _path.Send(ZzFrameCodec.BuildFunFrame(TxType8k, _nextSeq(), trigger));
            _txFrameSeq++;
            // Brief pause to allow SCU to process the trigger before RX pump starts
            await Task.Delay(60, ct);
        }

        _rxPumpTask = Task.Run(RxPumpAsync, _cts.Token);
        _txPumpTask = Task.Run(TxPumpAsync, _cts.Token);

        _log.LogInformation("AudioChannel started — {Quality} ({Rate} Hz stereo 16-bit)",
            _quality, wireFormat.SampleRate);
    }

    public async Task StopAsync()
    {
        if (!IsRunning)
            return;
        IsRunning = false;
        _cts.Cancel();

        _rxBuffer?.ClearBuffer();
        _waveIn?.StopRecording();
        _waveOut?.Stop();

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

    // ── RX pump ───────────────────────────────────────────────────────────────

    private async Task RxPumpAsync()
    {
        _log.LogDebug("RX audio pump started");

        byte expectedRxType = Is8k ? RxType8k : RxType16k;
        byte[] pcm = ArrayPool<byte>.Shared.Rent(MaxRxPcmBytes);

        try
        {
            await foreach (var frame in _path!.Frames.ReadAllAsync(_cts.Token))
            {
                if (frame.ZzType != expectedRxType)
                    continue;

                var raw = frame.Raw;
                if (raw.Length < 8 + FunHdrBytesRx + 4)
                    continue;

                byte kl = raw[6], kh = raw[7];

                // Read audio payload length from fun[28:30] dynamically.
                int hdr28 = ((~28 + 1) & 0xff) ^ raw[8 + 28] ^ kl ^ kh;
                int hdr29 = ((~29 + 1) & 0xff) ^ raw[8 + 29] ^ kl ^ kh;
                int audioLen = hdr28 | (hdr29 << 8);

                int available = raw.Length - (8 + FunHdrBytesRx);
                int limit = Math.Min(audioLen, Math.Min(available, MaxRxPcmBytes));
                limit = (limit / 4) * 4;
                if (limit < 4)
                    continue;

                // FUN-decode audio payload. fi is the full FUN payload index
                // (header + audio), used as the XOR position key.
                for (int i = 0; i < limit; i++)
                {
                    int fi = FunHdrBytesRx + i;
                    pcm[i] = (byte)(((~fi + 1) & 0xff) ^ raw[8 + fi] ^ kl ^ kh);
                }

                // SCU always sends 16-bit stereo PCM — swap L↔R and play.
                SwapAndAdd(pcm, limit);
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) { _log.LogError(ex, "RX audio pump error"); }
        finally { ArrayPool<byte>.Shared.Return(pcm); }

        _log.LogDebug("RX audio pump stopped");
    }

    /// <summary>Swap L↔R stereo pairs in-place then add to playback buffer.</summary>
    private void SwapAndAdd(byte[] pcm, int len)
    {
        for (int i = 0; i < len; i += 4)
        {
            (pcm[i], pcm[i + 2]) = (pcm[i + 2], pcm[i]);
            (pcm[i + 1], pcm[i + 3]) = (pcm[i + 3], pcm[i + 1]);
        }
        _rxBuffer!.AddSamples(pcm, 0, len);
    }

    // ── TX pump ───────────────────────────────────────────────────────────────

    private async Task TxPumpAsync()
    {
        _log.LogDebug("TX audio pump started");

        byte txType = Is8k ? TxType8k : TxType16k;
        int txPcmBytes = Is8k ? TxPcmBytes8k : TxPcmBytes16k;

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

        byte[] acc = new byte[txPcmBytes];
        int fill = 0;

        try
        {
            using var timer = new PeriodicTimer(TimeSpan.FromMilliseconds(10));
            while (await timer.WaitForNextTickAsync(_cts.Token))
            {
                while (fill < txPcmBytes && micCh.Reader.TryRead(out var chunk))
                {
                    int copy = Math.Min(chunk.Length, txPcmBytes - fill);
                    Buffer.BlockCopy(chunk, 0, acc, fill, copy);
                    fill += copy;
                }

                byte[] pcm;
                if (fill >= txPcmBytes)
                {
                    pcm = acc;
                    acc = new byte[txPcmBytes];
                    fill = 0;
                }
                else
                {
                    pcm = new byte[txPcmBytes];  // silence
                }

                byte[] funPayload = BuildTxFunPayload(pcm);
                _path!.Send(ZzFrameCodec.BuildFunFrame(txType, _nextSeq(), funPayload));
                _path!.Send(ZzFrameCodec.BuildFunFrame(txType, _nextSeq(), funPayload));
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
    /// Build the FUN header + PCM payload for a TX audio packet.
    ///
    /// 16 kHz (0xa6): 30-byte header, format=0x01 PCM, rate=16000, 642 bytes audio
    /// 8 kHz  (0xc6): 32-byte header, format=0x03 µ-Law header field, rate=8000,
    ///                160 bytes audio. Note: SCU sends PCM back regardless.
    ///
    /// Header confirmed byte-by-byte from Wireshark captures.
    /// </summary>
    private byte[] BuildTxFunPayload(byte[] pcm)
    {
        bool is8k = Is8k;
        int hdrBytes = is8k ? FunHdrBytesTx8k : FunHdrBytesTx16k;
        int txPcmBytes = pcm.Length;
        int sampleRate = is8k ? 8_000 : 16_000;
        byte format = is8k ? (byte)0x03 : (byte)0x01;

        var fun = new byte[hdrBytes + txPcmBytes];

        fun[0] = 0x02;
        fun[1] = 0x00;
        fun[2] = 0x05;
        fun[3] = 0x01;
        int dataLen = hdrBytes + txPcmBytes - 6;
        fun[4] = (byte)(dataLen & 0xff);
        fun[5] = (byte)(dataLen >> 8);
        // fun[6..9] = SID/device bytes — mirror what we set in SendAudioOpen
        // fun[6:10] in the Yaesu 8k capture = 52 00 00 00 (SID LE)
        // For simplicity keep as 0x00 — SCU appears to accept this
        fun[10] = _txFrameSeq;
        fun[11] = is8k ? (byte)0x77 : (byte)0x65;  // fixed high byte from captures
        fun[12] = format;
        fun[13] = 0x02;   // stereo
        fun[14] = (byte)(sampleRate & 0xff);
        fun[15] = (byte)(sampleRate >> 8);
        fun[16] = 0x00;
        fun[17] = 0x00;
        fun[18] = 0x01;
        // fun[19..25] = 0x00
        fun[26] = 0xd0;
        fun[27] = 0x07;   // 2000 ms send buffer
        fun[28] = is8k ? (byte)0xd0 : (byte)0xd0;
        fun[29] = 0x07;   // 2000 ms recv buffer
        fun[30] = 0x64;   // volume 100
        fun[31] = 0x64;   // volume 100
        // 8k has 2 extra header bytes (fun[32..33]) before audio — already zero

        Buffer.BlockCopy(pcm, 0, fun, hdrBytes, txPcmBytes);
        return fun;
    }

    // ── IAsyncDisposable ──────────────────────────────────────────────────────

    public async ValueTask DisposeAsync()
    {
        await StopAsync();
        _cts.Dispose();
    }
}
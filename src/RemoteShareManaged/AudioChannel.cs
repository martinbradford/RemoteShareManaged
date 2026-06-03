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
/// Wire format confirmed from Wireshark and RemoteShare.dll decompilation:
///
///   16 kHz modes (PCM 16k, µ-Law 16k):
///     RX  SCU→PC  ZZ type 0xa2, 30-byte FUN header + 640 bytes raw 16-bit stereo PCM
///     TX  PC→SCU  ZZ type 0xa6, 34-byte FUN header + 640 bytes audio
///     Packet size: 678 bytes RX / 682 bytes TX
///
///   8 kHz modes (PCM 8k, µ-Law 8k):
///     RX  SCU→PC  ZZ type 0xc2, 30-byte FUN header + 160 bytes audio
///     TX  PC→SCU  ZZ type 0xc6, 34-byte FUN header + 160 bytes audio
///     Packet size: 198 bytes RX / 202 bytes TX
///
/// RX encoding by mode (confirmed from Wireshark byte-level analysis):
///
///   16k PCM:   640 bytes raw 16-bit stereo PCM
///   16k µ-Law: 640 bytes raw 16-bit stereo PCM (SCU ignores µ-Law at 16k)
///   8k PCM:    160 bytes raw 16-bit stereo PCM (assumed; treated same as 16k)
///   8k µ-Law:  160 bytes Yaesu µ-Law stereo pairs [L_ulaw, R_ulaw] × 80 frames
///              L=main RX audio, R=0xff (µ-Law silence). Decode via YaesuMuLaw.
///
/// TX encoding (from RemoteShare.dll FUN_10003eb0):
///   PCM modes:   raw 16-bit stereo PCM
///   µ-Law modes: Yaesu-custom µ-Law (NOT G.711) — 320 bytes PCM → 160 wire bytes
///
/// 8k DEDUPLICATION:
///   SCU sends 2 copies per frame ~1ms apart. At 8kHz that 1ms gap ≈ 8 samples,
///   producing a comb filter with nulls at ~1000 Hz — fatal for FT8 decoding.
///   8k RX pump deduplicates using fun[6:8] as frame ID.
///   16k modes feed both copies (confirmed working, comb not audible at 16kHz).
///
/// TX header (34 bytes, both 0xa6 and 0xc6 — confirmed from Wireshark):
///   fun[10]    = txFrameSeq low byte  (increments each unique frame)
///   fun[11]    = txFrameSeq high byte (increments every 256 frames ~2.56s)
///   fun[30:32] = volume bytes (0x64, 0x64)
///   fun[32:34] = audio_len LE
///   fun[34+]   = audio data
///   0xc6 additionally: fun[6:10] = SID (helloAckNonce^0x08) in ALL frames
///
/// Stereo layout: main RX on L wire, sub-RX on R wire. No swap needed for 16k paths.
/// PTT: ScuSession.SendCatAsync("TX;") / "RX;".
/// </summary>
public sealed class AudioChannel : IAsyncDisposable
{
    // ── Wire format constants ─────────────────────────────────────────────────

    private const int FunHdrBytesRx = 30;
    // Both 0xa6 (16k) and 0xc6 (8k) TX headers are 34 bytes — confirmed from
    // Wireshark: fun[30:32]=volume, fun[32:34]=audio_len, audio starts at fun[34].
    private const int FunHdrBytesTx16k = 34;
    private const int FunHdrBytesTx8k  = 34;

    private const byte RxType16k = 0xa2;
    private const byte TxType16k = 0xa6;
    private const byte RxType8k = 0xc2;
    private const byte TxType8k = 0xc6;

    private const int TxWireBytes16k = 640;
    private const int TxWireBytes8k = 160;

    private const int MaxRxWireBytes = 640;
    private const int MaxRxPcmBytes = 640;

    // SCU has no PCM 8k mode — Wireshark confirms Yaesu app uses 0xa6/0xa2 (16k packets)
    // for PCM 8k. Only ULaw8k genuinely uses the 0xc6/0xc2 8k path.
    private bool Is8k => _quality == AudioQuality.ULaw8k;
    private bool IsULaw => _quality is AudioQuality.ULaw16k or AudioQuality.ULaw8k;

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
    private readonly int _waveInDevice;

    private RemotePath? _path;
    private WaveOutEvent? _waveOut;
    private BufferedWaveProvider? _rxBuffer;
    private WaveInEvent? _waveIn;

    private CancellationTokenSource _cts = new();
    private Task? _rxPumpTask;
    private Task? _txPumpTask;

    private ushort _txFrameSeq;  // 16-bit: fun[10]=low byte, fun[11]=high byte

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
        int waveInDevice = 0,
        ILoggerFactory? loggerFactory = null)
    {
        _addr = addr;
        _helloAckNonce = helloAckNonce;
        _nextSeq = nextSeq;
        _channelOpen = channelOpen;
        _quality = quality;
        _waveOutDevice = waveOutDevice;
        _waveInDevice = waveInDevice;
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
            DeviceNumber = _waveInDevice,
        };

        IsRunning = true;
        await _channelOpen(_path, _cts.Token);

        if (Is8k)
        {
            byte[] silence = new byte[TxWireBytes8k];
            byte[] trigger = BuildTxFunPayload(silence);
            _path.Send(ZzFrameCodec.BuildFunFrame(TxType8k, _nextSeq(), trigger));
            _path.Send(ZzFrameCodec.BuildFunFrame(TxType8k, _nextSeq(), trigger));
            _txFrameSeq++;
            await Task.Delay(80, ct);
        }

        _rxPumpTask = Task.Run(RxPumpAsync, _cts.Token);
        _txPumpTask = Task.Run(TxPumpAsync, _cts.Token);

        _log.LogInformation("AudioChannel started — {Quality} ({Rate} Hz stereo)",
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
        catch { }

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
        _log.LogDebug("RX audio pump started ({Mode})", _quality);

        bool decode8kULaw = _quality == AudioQuality.ULaw8k;
        bool is8k = Is8k;
        byte expectedType = is8k ? RxType8k : RxType16k;

        byte[] wire = ArrayPool<byte>.Shared.Rent(MaxRxWireBytes);
        byte[] pcm = ArrayPool<byte>.Shared.Rent(MaxRxPcmBytes);

        // 8k deduplication: SCU sends 2 copies ~1ms apart. At 8kHz this creates
        // a comb filter with nulls at ~1000 Hz — fatal for FT8. Track the frame
        // ID from fun[6:8] and skip any packet with the same ID as the last one.
        // 16k modes intentionally skip deduplication (confirmed working as-is).
        int lastFrameId = -1;

        try
        {
            await foreach (var frame in _path!.Frames.ReadAllAsync(_cts.Token))
            {
                if (frame.ZzType != expectedType)
                    continue;

                var raw = frame.Raw;
                if (raw.Length < 8 + FunHdrBytesRx + 4)
                    continue;

                byte kl = raw[6], kh = raw[7];

                // 8k deduplication: use fun[6:8] as the frame counter.
                // fun[6] increments every unique frame; duplicate pairs share
                // the same value. fun[0:2] is always 0x0002 (len) — do NOT use.
                if (is8k)
                {
                    int id0 = ((~6 + 1) & 0xff) ^ raw[8 + 6] ^ kl ^ kh;
                    int id1 = ((~7 + 1) & 0xff) ^ raw[8 + 7] ^ kl ^ kh;
                    int frameId = id0 | (id1 << 8);
                    if (frameId == lastFrameId)
                        continue;
                    lastFrameId = frameId;
                }

                // Audio payload length from fun[28:30].
                int hdr28 = ((~28 + 1) & 0xff) ^ raw[8 + 28] ^ kl ^ kh;
                int hdr29 = ((~29 + 1) & 0xff) ^ raw[8 + 29] ^ kl ^ kh;
                int wireLen = hdr28 | (hdr29 << 8);

                int available = raw.Length - (8 + FunHdrBytesRx);
                int limit = Math.Min(wireLen, Math.Min(available, MaxRxWireBytes));

                if (decode8kULaw)
                {
                    // 8k µ-Law: wire = [L_ulaw, R_ulaw] × 80 stereo pairs.
                    // L=main RX audio, R=0xff (µ-Law silence).
                    limit = (limit / 2) * 2;
                    if (limit < 2)
                        continue;

                    // FUN-decode wire bytes.
                    for (int i = 0; i < limit; i++)
                    {
                        int fi = FunHdrBytesRx + i;
                        wire[i] = (byte)(((~fi + 1) & 0xff) ^ raw[8 + fi] ^ kl ^ kh);
                    }

                    // Decode µ-Law pairs → stereo PCM.
                    // Wire: even=L(audio), odd=R(silence).
                    // Write audio into R position and silence into L position so
                    // that SwapAndAdd moves audio to L — matching 16k PCM convention
                    // and ensuring WSJT-X receives audio on the left channel.
                    int pcmLen = 0;
                    for (int i = 0; i < limit; i += 2)
                    {
                        short lSample = YaesuMuLaw.DecodeSample(wire[i]);      // audio
                        short rSample = YaesuMuLaw.DecodeSample(wire[i + 1]);  // silence→0
                        // Place audio in R, silence in L (SwapAndAdd will flip them).
                        pcm[pcmLen++] = (byte)rSample;
                        pcm[pcmLen++] = (byte)((ushort)rSample >> 8);
                        pcm[pcmLen++] = (byte)lSample;
                        pcm[pcmLen++] = (byte)((ushort)lSample >> 8);
                    }

                    SwapAndAdd(pcm, pcmLen);
                }
                else
                {
                    // 16k (all modes) and 8k PCM: raw 16-bit stereo PCM.
                    limit = (limit / 4) * 4;
                    if (limit < 4)
                        continue;

                    for (int i = 0; i < limit; i++)
                    {
                        int fi = FunHdrBytesRx + i;
                        pcm[i] = (byte)(((~fi + 1) & 0xff) ^ raw[8 + fi] ^ kl ^ kh);
                    }

                    // Wire is already Main=L, Sub=R — no swap needed.
                    _rxBuffer!.AddSamples(pcm, 0, limit);
                }
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) { _log.LogError(ex, "RX audio pump error"); }
        finally
        {
            ArrayPool<byte>.Shared.Return(wire);
            ArrayPool<byte>.Shared.Return(pcm);
        }

        _log.LogDebug("RX audio pump stopped");
    }

    /// <summary>Swap L↔R stereo pairs in-place then feed to playback buffer.</summary>
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
        _log.LogDebug("TX audio pump started ({Mode})", _quality);

        bool isULaw = IsULaw;
        bool is8k = Is8k;
        byte txType = is8k ? TxType8k : TxType16k;
        int txWireBytes = is8k ? TxWireBytes8k : TxWireBytes16k;
        int txPcmAccum = isULaw ? txWireBytes * 2 : txWireBytes;

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

        byte[] acc = new byte[txPcmAccum];
        byte[] wireBuf = new byte[txWireBytes];
        int fill = 0;

        try
        {
            using var timer = new PeriodicTimer(TimeSpan.FromMilliseconds(10));
            while (await timer.WaitForNextTickAsync(_cts.Token))
            {
                while (fill < txPcmAccum && micCh.Reader.TryRead(out var chunk))
                {
                    int copy = Math.Min(chunk.Length, txPcmAccum - fill);
                    Buffer.BlockCopy(chunk, 0, acc, fill, copy);
                    fill += copy;
                }

                if (fill >= txPcmAccum)
                {
                    if (isULaw)
                        YaesuMuLaw.Encode(acc, txPcmAccum, wireBuf);
                    else
                        Buffer.BlockCopy(acc, 0, wireBuf, 0, txWireBytes);
                    acc = new byte[txPcmAccum];
                    fill = 0;
                }
                else
                {
                    Array.Clear(wireBuf, 0, txWireBytes);
                }

                byte[] funPayload = BuildTxFunPayload(wireBuf);
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

    private byte[] BuildTxFunPayload(byte[] wireAudio)
    {
        bool is8k = Is8k;
        bool isULaw = IsULaw;
        int hdrBytes = is8k ? FunHdrBytesTx8k : FunHdrBytesTx16k;
        int audioLen = wireAudio.Length;
        int sampleRate = is8k ? 8_000 : 16_000;
        byte format = isULaw ? (byte)0x03 : (byte)0x01;

        var fun = new byte[hdrBytes + audioLen];

        fun[0] = 0x02;
        fun[1] = 0x00;
        fun[2] = 0x05;   // MID = 0x0105 (confirmed from Yaesu reference capture)
        fun[3] = 0x01;
        int dataLen = hdrBytes + audioLen - 6;
        fun[4] = (byte)(dataLen & 0xff);
        fun[5] = (byte)(dataLen >> 8);

        // SID present in ALL TX frames (0xa6 and 0xc6) - confirmed from Yaesu reference capture
        uint sid = (uint)(_helloAckNonce ^ 0x08);
        fun[6] = (byte)sid;
        fun[7] = (byte)(sid >> 8);
        fun[8] = (byte)(sid >> 16);
        fun[9] = (byte)(sid >> 24);

        fun[10] = (byte)(_txFrameSeq & 0xff);
        fun[11] = is8k ? (byte)0x43 : (byte)0x71;  // fixed constant (confirmed from Yaesu reference capture)
        fun[12] = format;
        fun[13] = 0x02;
        fun[14] = (byte)(sampleRate & 0xff);
        fun[15] = (byte)(sampleRate >> 8);
        fun[18] = 0x01;
        fun[26] = 0xd0;
        fun[27] = 0x07;
        fun[28] = 0xd0;
        fun[29] = 0x07;
        fun[30] = 0x64;
        fun[31] = 0x64;
        // audio_len field present in both 0xa6 and 0xc6 (confirmed from Wireshark)
        fun[32] = (byte)(audioLen & 0xff);
        fun[33] = (byte)(audioLen >> 8);

        Buffer.BlockCopy(wireAudio, 0, fun, hdrBytes, audioLen);
        return fun;
    }

    // ── IAsyncDisposable ──────────────────────────────────────────────────────

    public async ValueTask DisposeAsync()
    {
        await StopAsync();
        _cts.Dispose();
    }
}
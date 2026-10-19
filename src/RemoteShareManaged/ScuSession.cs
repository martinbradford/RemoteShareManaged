using System.Reactive.Linq;
using System.Reactive.Subjects;
using System.Threading.Channels;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using RemoteShareManaged.Codec;
using RemoteShareManaged.Protocol;
using RemoteShareManaged.Transport;

namespace RemoteShareManaged;

/// <summary>
/// Manages the full SCU-LAN10 connection lifecycle.
///
/// Connection sequence (authoritative — from frmTopMain.doLogin):
///   1.  Open four UDP paths (ports 50000–50003)
///   2.  5× SendHchk (sid=0, dev=LoginSession)
///   3.  SendLogin → wait MID_LoginAns → extract sid + MAC
///   4.  catcmd_table upload ("putfile catcmd_table" + page data)
///   5.  SendCatOpen (port 50001, baud 38400, dev UsbCat=1) × 2
///   6.  SendDevPortOpen audio (port 50002, dev UsbAudio=2) × 2
///   7.  SendDevPortOpen scope (port 50003, dev DinSpiIn=6) × 2
///   8.  SendDevPortConnect CAT (on cat path)
///   9.  CAT baud negotiation (PS1 + AI commands)
///   10. SendDevPortConnect audio
///   11. SendDevPortConnect scope
///
/// Portability: pure .NET — no P/Invoke, no Windows APIs.
/// Works on Windows, Linux, and Android.
/// </summary>
public sealed class ScuSession : IAsyncDisposable
{
    // ── State ─────────────────────────────────────────────────────────────────

    private readonly ILogger<ScuSession> _log;
    private readonly ILoggerFactory _loggerFactory;
    private ScuSessionTiming _t = ScuSessionTiming.Default;  // set in ConnectAsync

    private RemotePath? _control;
    private RemotePath? _cat;
    private RemotePath? _audio;
    private RemotePath? _scope;

    private string _addr = string.Empty;  // stored for AudioChannel factory
    private AudioQuality _audioQuality = AudioQuality.Pcm16k;  // stored for AudioChannel factory

    private uint _seq;          // outgoing ZZ-frame sequence counter, starts at 1
    private byte _catCmdCounter; // dec[9] in type 0x19 CAT send packets (legacy ZZ path)
    private ushort _catPktId;      // FUN SendCatWrite packet ID, increments per write

    private byte NextSeq() => (byte)(++_seq);

    private CancellationTokenSource _cts = new();
    private Task? _catPumpTask;
    private Task? _keepaliveTask;

    // ── Reactive / channel output ─────────────────────────────────────────────

    private readonly Subject<CatMessage> _catSubject = new();
    private readonly Channel<CatMessage> _catChannel =
        Channel.CreateUnbounded<CatMessage>(
            new UnboundedChannelOptions { SingleWriter = true });

    /// <summary>
    /// Observable stream of incoming CAT messages.
    /// Subscribe in your ReactiveUI ViewModel:
    ///   session.CatMessages.ObserveOn(RxApp.MainThreadScheduler).Subscribe(...)
    /// </summary>
    public IObservable<CatMessage> CatMessages => _catSubject.AsObservable();

    private readonly Subject<byte[]> _binaryMeterSubject = new();

    /// <summary>
    /// Observable stream of raw binary meter responses (e.g. SPM 15-byte packets).
    /// Fires when the radio responds to a binary poll command such as the SPM meter request.
    /// </summary>
    public IObservable<byte[]> BinaryMeterMessages => _binaryMeterSubject.AsObservable();

    /// <summary>
    /// Async enumerable of incoming CAT messages.
    /// Alternative consumption style for non-reactive consumers.
    /// </summary>
    public IAsyncEnumerable<CatMessage> CatMessagesAsync
        => _catChannel.Reader.ReadAllAsync();

    // ── Connection state ──────────────────────────────────────────────────────

    public bool IsConnected
    {
        get; private set;
    }

    // ── Constructor ───────────────────────────────────────────────────────────

    public ScuSession(ILoggerFactory? loggerFactory = null)
    {
        _loggerFactory = loggerFactory ?? NullLoggerFactory.Instance;
        _log = _loggerFactory.CreateLogger<ScuSession>();
    }

    // ── Connect ───────────────────────────────────────────────────────────────

    /// <summary>
    /// Run the full doLogin sequence.
    /// Safe to call from any thread. Returns true on success.
    /// </summary>
    public async Task<bool> ConnectAsync(
        string addr,
        string username,
        string password,
        bool isFt710 = false,
        AudioQuality audioQuality = AudioQuality.Pcm16k,
        ScuSessionTiming? timing = null,
        CancellationToken ct = default)
    {
        _t = timing ?? ScuSessionTiming.Default;

        if (IsConnected)
            await DisconnectAsync();

        _log.LogInformation("Connecting to {Addr}", addr);
        _addr = addr;
        _audioQuality = audioQuality;
        _cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        _seq = 0;  // reset sequence counter — first packet will be seq=1

        try
        {
            // Step 1 — open ONLY the control path before handshake.
            // The SCU probes ports 50001-50003 during the KEY EXCHANGE phase;
            // opening them early causes ICMP Port Unreachable responses that
            // abort the SCU's state machine. Open them after handshake completes.
            _control = OpenPath(addr, ScuPorts.Control);

            // Step 2 — 5× pre-login health check (type 0x0e, sequential counter)
            for (int i = 0; i < 5; i++)
                _control.Send(ZzFrameCodec.BuildKeepalive(
                    authenticated: false, NextSeq()));

            // Step 3 — Login (HELLO → HELLO-ACK)
            if (!await DoLoginAsync(username, password, ct))
                return false;

            // Steps 3b-3f — KEY EXCHANGE → AUTH BLOB → CONFIG → INIT
            // This is the full port 50000 handshake that must complete
            // before the DLL-level commands (SendLogin etc.) are sent
            if (!await DoHandshakeAsync(ct))
                return false;

            // Now safe to open the data paths.
            // NOTE: Do NOT open _audio here — AudioChannel.StartAsync() opens its own
            // RemotePath for port 50002. Opening a second socket here causes the SCU to
            // receive SendAudioConnect from a different local port than the one it should
            // reply to, and the SCU's ACK goes to the wrong socket. The _audio field is
            // left null; CleanupPathsAsync handles null entries safely.
            // NOTE: Do NOT open port 50003 (scope) — the SCU sends ICMP Port Unreachable
            // back to our keepalives on that port, which corrupts its session state.
            _cat = OpenPath(addr, ScuPorts.Cat);
            _log.LogDebug("Data paths opened (cat)");

            // Keepalive can start now (uses port 50000 only during handshake)
            _keepaliveTask = Task.Run(KeepaliveAsync, _cts.Token);

            // Step 4 — Port 50001 mini-handshake + catcmd_table upload
            // CatPump must NOT start until after channel open, because it
            // consumes frames from the same channel and would steal the 0x0e ACK.
            if (!await DoCatChannelOpenAsync(ct))
                return false;

            // Now start CatPump — channel is open and all handshake frames consumed
            IsConnected = true;
            _catPumpTask = Task.Run(CatPumpAsync, _cts.Token);

            // Give CatPump a moment to start, then query initial frequency
            await Task.Delay(_t.PostConnectDelayMs, ct);
            SendPollCmd(PollCmd1);
            SendPollCmd(PollCmd2);
            SendCatQuery(FreqQueryCmd);

            _log.LogInformation("Connected");
            return true;
        }
        catch (OperationCanceledException)
        {
            _log.LogWarning("Connect cancelled");
            await CleanupPathsAsync();
            return false;
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Connect failed");
            await CleanupPathsAsync();
            return false;
        }
    }

    // ── Disconnect ────────────────────────────────────────────────────────────

    public async Task DisconnectAsync()
    {
        if (!IsConnected)
            return;
        _log.LogInformation("Disconnecting...");

        // Send proper logout to SCU BEFORE closing sockets so it can close the
        // session cleanly. Without this, the SCU keeps sending 0x18 data for
        // minutes and may block the next connection attempt.
        if (_control is not null && _helloAckNonce != 0)
        {
            _control.Send(ZzFrameCodec.BuildLogout(NextSeq(), _helloAckNonce));
            await Task.Delay(_t.DisconnectDelayMs);  // give SCU time to process before we close
        }

        IsConnected = false;
        _cts.Cancel();

        // Send a simple keepalive-style disconnect notification (best-effort)
        if (_control is not null)
        {
            try
            {
                _control.Send(ZzFrameCodec.BuildKeepalive(false, NextSeq()));
            }
            catch { }
        }

        // Give tasks a moment to stop cleanly
        var tasks = new[] { _catPumpTask, _keepaliveTask }
            .Where(t => t is not null)
            .Select(t => t!);
        try
        {
            await Task.WhenAll(tasks).WaitAsync(TimeSpan.FromMilliseconds(_t.StepTimeoutMs));
        }
        catch { /* timeout fine */ }

        await CleanupPathsAsync();
        _log.LogInformation("Disconnected");
    }

    // ── Login steps ───────────────────────────────────────────────────────────

    private byte _helloAckNonce; // dec[5] from HELLO-ACK — used to build KEY EXCHANGE and AUTH BLOB
    public uint Sid => _helloAckNonce ^ 0x08u;

    private async Task<bool> DoLoginAsync(string user, string pass, CancellationToken ct)
    {
        _log.LogDebug("Sending Login (HELLO)...");

        for (int attempt = 0; attempt < 2; attempt++)
        {
            if (attempt > 0)
                _log.LogDebug("Login timeout — retrying");

            byte[] hello = ZzFrameCodec.BuildHello(user, pass, NextSeq());
            _control!.Send(hello);

            var received = await _control.WaitForZzTypeAsync(0x18, TimeSpan.FromMilliseconds(_t.StepTimeoutMs), ct);
            if (received is null)
                continue;

            _helloAckNonce = received.Value.Payload.Length > 5
                ? received.Value.Payload[5]
                : (byte)0;

            _log.LogInformation("HELLO-ACK received — nonce=0x{Nonce:x2}", _helloAckNonce);
            return true;
        }

        _log.LogError("Login timed out — no HELLO-ACK");
        return false;
    }

    /// <summary>
    /// The full port 50000 handshake sequence after HELLO-ACK:
    ///   KEY EXCHANGE → KEY-ACK (~5s)
    ///   AUTH BLOB    → AUTH-ACK pair (~14s)
    ///   CONFIG A + B → CONFIG-ACK
    ///   INIT A/B/C/D → FINAL-ACK
    ///
    /// All packets use EncodeWithSeq with the sequential counter.
    /// The SCU echoes back the nonce values from each PC packet in its ACKs.
    /// </summary>
    private async Task<bool> DoHandshakeAsync(CancellationToken ct)
    {
        _log.LogDebug("Starting port 50000 handshake (KEY EXCHANGE → INIT)...");

        // KEY EXCHANGE — only dec[5] is nonce-dependent: nonce ^ 0x06
        _control!.Send(ZzFrameCodec.BuildKeyExchange(NextSeq(), _helloAckNonce));
        _log.LogDebug("KEY EXCHANGE sent (nonce=0x{N:x2}) — waiting for KEY-ACK...", _helloAckNonce);
        var keyAck = await _control.WaitForZzTypeAsync(0x18, TimeSpan.FromMilliseconds(_t.StepTimeoutMs), ct);
        if (keyAck is null)
        {
            _log.LogError("KEY-ACK not received");
            return false;
        }
        _log.LogDebug("KEY-ACK received");

        // AUTH BLOB — dec[5] = nonce ^ 0x79
        _control.Send(ZzFrameCodec.BuildAuthBlob(NextSeq(), _helloAckNonce));
        _log.LogDebug("AUTH BLOB sent — waiting for AUTH-ACK...");
        var authAck1 = await _control.WaitForZzTypeAsync(0x1a, TimeSpan.FromMilliseconds(_t.AuthTimeoutMs), ct);
        if (authAck1 is null)
        {
            _log.LogError("AUTH-ACK not received");
            return false;
        }
        var authAck2 = await _control.WaitForZzTypeAsync(0x1a, TimeSpan.FromMilliseconds(_t.StepTimeoutMs), ct);
        _log.LogDebug("AUTH-ACK received ({N} of 2)", authAck2.HasValue ? 2 : 1);

        // CONFIG A + B = SendCatOpen ×2 (confirmed from decompiled RemoteShare.dll).
        // Uses FUN_10003c30 encoding with SID = helloAckNonce ^ 0x08.
        // Registers this client (SID + recvPort=50001) with the SCU so it will
        // respond to RR1$ with directed 0x10 packets (not just the 0x18 broadcast).
        _control.Send(ZzFrameCodec.BuildSendCatOpen(NextSeq(), _helloAckNonce));
        _control.Send(ZzFrameCodec.BuildSendCatOpen(NextSeq(), _helloAckNonce));

        var cfgAck = await _control.WaitForZzTypeAsync(0x0e, TimeSpan.FromMilliseconds(_t.ConfigAckTimeoutMs), ct);
        if (cfgAck is null)
            _log.LogWarning("CONFIG ACK not received — continuing");

        // INIT packets — required for a cold SCU to reach the state where port 50001
        // RR1$/CH0$/DO< gets the 0x10/0x12 ACK response. The DLL can skip these
        // because it always runs after a full Yaesu app session that already sent INIT.
        // Without INIT on a cold SCU, RR1$ only gets the 0x18 broadcast, not the
        // 0x10 directed response needed to open the CAT channel.
        _control.Send(ZzFrameCodec.BuildInit(ZzFrameCodec.InitATemplate, NextSeq(), _helloAckNonce, 0x02));
        var initAck = await _control.WaitForZzTypeAsync(0x0e, TimeSpan.FromMilliseconds(_t.ConfigAckTimeoutMs), ct);
        if (initAck is null)
            _log.LogWarning("INIT ACK not received — continuing");

        _control.Send(ZzFrameCodec.BuildInit(ZzFrameCodec.InitBTemplate, NextSeq(), _helloAckNonce, 0x02));
        _control.Send(ZzFrameCodec.BuildInit(ZzFrameCodec.InitCTemplate, NextSeq(), _helloAckNonce, 0x06));
        _control.Send(ZzFrameCodec.BuildInit(ZzFrameCodec.InitDTemplate, NextSeq(), _helloAckNonce, 0x06));

        var finalAck = await _control.WaitForZzTypeAsync(0x0e, TimeSpan.FromMilliseconds(_t.ConfigAckTimeoutMs), ct);
        if (finalAck is null)
            _log.LogWarning("FINAL-ACK not received — continuing");
        else
            _log.LogInformation("Handshake complete — FINAL-ACK received");

        return true;
    }

    // ── Port 50001 channel open (post-handshake) ──────────────────────────────

    /// <summary>
    /// After the port 50000 handshake, activate the CAT channel on port 50001
    /// using the same FUN_10003c30 protocol as the Yaesu app.
    ///
    /// Confirmed from cold-start Yaesu trace:
    ///   1. SendDevPortConnect (FUN 0x0e, MID=0x0104) — activates channel
    ///   2. SCU responds with 0x0e ACK
    ///   3. SendCatWrite ×3 (PS1; AI0; AI;) at +30ms, repeated on 30ms timer
    ///   4. SCU responds with 0x10×2 + 0x12×2 (UsbCat data frames)
    ///   5. Send AI1; + confirm 0x12
    ///   6. Connected — CatPump starts
    /// </summary>
    private async Task<bool> DoCatChannelOpenAsync(CancellationToken ct)
    {
        _log.LogDebug("Opening CAT channel (port 50001)...");

        // Step 1: SendDevPortConnect — activates the CAT channel
        _cat!.Send(ZzFrameCodec.BuildSendDevPortConnect(NextSeq(), _helloAckNonce));

        var connAck = await _cat.WaitForZzTypeAsync(0x0e, TimeSpan.FromMilliseconds(_t.StepTimeoutMs), ct);
        if (connAck is null)
            _log.LogWarning("SendDevPortConnect ACK not received — continuing");

        // Step 2: SendCatWrite × 3 (PS1; AI0; AI;) in two rounds, 30ms apart.
        // Wait 30ms before the FIRST round too — Yaesu waits 30ms after DPC ACK.
        // The SCU needs to process SendDevPortConnect before accepting CatWrites.
        byte[] ps1 = System.Text.Encoding.ASCII.GetBytes("PS1;");
        byte[] ai0 = System.Text.Encoding.ASCII.GetBytes("AI0;");
        byte[] ai = System.Text.Encoding.ASCII.GetBytes("AI;");
        ushort pktId = _catPktId;

        for (int round = 0; round < 2; round++)
        {
            await Task.Delay(_t.CatRoundDelayMs, ct);  // before each round (including first)
            _cat.Send(ZzFrameCodec.BuildSendCatWrite(NextSeq(), _helloAckNonce, ++pktId, ps1));
            _cat.Send(ZzFrameCodec.BuildSendCatWrite(NextSeq(), _helloAckNonce, ++pktId, ai0));
            _cat.Send(ZzFrameCodec.BuildSendCatWrite(NextSeq(), _helloAckNonce, ++pktId, ai));
        }

        // Step 3: Wait for 0x10 (UsbCat_ConnectAns) from SCU
        var catAck = await _cat.WaitForZzTypeAsync(0x10, TimeSpan.FromMilliseconds(_t.StepTimeoutMs), ct);
        if (catAck is null)
            _log.LogWarning("CAT channel 0x10 not received — continuing");
        else
            _log.LogDebug("CAT channel 0x10 received");

        // Step 4: Send AI1; + session confirm (0x12)
        byte[] ai1 = System.Text.Encoding.ASCII.GetBytes("AI1;");
        _cat.Send(ZzFrameCodec.BuildSendCatWrite(NextSeq(), _helloAckNonce, ++pktId, ai1));
        _cat.Send(ZzFrameCodec.BuildSendCatWrite(NextSeq(), _helloAckNonce, ++pktId, ai1));
        _cat.Send(ZzFrameCodec.BuildSendCatConfirm(NextSeq(), _helloAckNonce, 2));
        _cat.Send(ZzFrameCodec.BuildSendCatConfirm(NextSeq(), _helloAckNonce, 2));

        // Drain remaining handshake frames
        await DrainAny(TimeSpan.FromMilliseconds(_t.CatDrainMs), ct);
        _catPktId = pktId;  // save for steady-state SendCatWrite calls

        _log.LogInformation("CAT channel open");

        // ── Audio routing initialisation ──────────────────────────────────────
        // The Yaesu app sends these undocumented commands immediately after the
        // CAT channel opens. They configure the SCU's audio output routing to
        // the post-DSP (filtered) path. Without them the SCU delivers unfiltered
        // audio, so the radio's WIDTH/SHIFT/DSP filter settings have no effect.
        //
        // From Yaesu app log at 12:14:32.809–12:14:32.885 (confirmed):
        //   AI1;JP0101;JP0010;JP0710;ID;   — JP selects filtered audio path
        //   SPr<0xFF><0xFF><0x13>;ST;TS;VS;FR;  — SP has binary args (undocumented)
        //   RI0;SS05;SS06;FD000;FD001;     — FD = spectrum display config
        //   FD002;FD003;IF;MD0;AN0;        — IF/MD/AN = standard CAT queries
        //
        // JP and SP are not in the published CAT manual. JP0101/0010/0710 are sent
        // verbatim; the radio responds JP0101005AFFA52506220808 confirming success.
        // SP has three non-printable bytes and must be sent as a raw byte array.

        await Task.Delay(_t.RoutingStepDelayMs, ct);  // brief gap as observed in Yaesu capture

        // Packet 3: AI1 + JP audio routing commands
        SendCatWriteRaw(ref pktId,
            System.Text.Encoding.ASCII.GetBytes("AI1;JP0101;JP0010;JP0710;ID;"));

        await Task.Delay(_t.RoutingStepDelayMs, ct);

        // Packet 4: SP (binary args) + standard state queries
        // SP raw bytes from log: 53 50 72 FF FF 00 (= "SPr" + 0xFF 0xFF 0x13) + ";ST;TS;VS;FR;"
        // The 0x13 in the log is a control character observed in the raw packet.
        SendCatWriteRaw(ref pktId, [
            0x53, 0x50, 0x72, 0xFF, 0xFF, 0x13, 0x3B,  // SPr<0xFF><0xFF><0x13>;
            .. System.Text.Encoding.ASCII.GetBytes("ST;TS;VS;FR;")
        ]);

        await Task.Delay(_t.RoutingStepDelayMs, ct);

        // Packet 7: spectrum display config + more state
        SendCatWriteRaw(ref pktId,
            System.Text.Encoding.ASCII.GetBytes("RI0;SS05;SS06;FD000;FD001;"));

        await Task.Delay(_t.RoutingStepDelayMs, ct);

        // Packet 8: remaining spectrum config + standard startup queries
        SendCatWriteRaw(ref pktId,
            System.Text.Encoding.ASCII.GetBytes("FD002;FD003;IF;MD0;AN0;"));

        await DrainAny(TimeSpan.FromMilliseconds(_t.RoutingDrainMs), ct);
        _catPktId = pktId;

        _log.LogInformation("Audio routing initialised (JP commands sent)");
        return true;
    }

    /// <summary>
    /// Send a raw byte payload as a SendCatWrite FUN packet.
    /// Used for commands with non-printable bytes (e.g. SP command).
    /// </summary>
    private void SendCatWriteRaw(ref ushort pktId, byte[] payload)
    {
        if (_cat is null)
            return;
        _cat.Send(ZzFrameCodec.BuildSendCatWrite(NextSeq(), _helloAckNonce, ++pktId, payload));
        _cat.Send(ZzFrameCodec.BuildSendCatWrite(NextSeq(), _helloAckNonce, ++pktId, payload));
    }

    /// <summary>Wait for up to <count> packets of <type>, with per-packet timeout.</summary>
    private async Task DrainType(byte type, int count, int timeoutMs, CancellationToken ct)
    {
        for (int i = 0; i < count; i++)
        {
            var f = await _cat!.WaitForZzTypeAsync(type, TimeSpan.FromMilliseconds(timeoutMs), ct);
            if (f is null)
                break;
        }
    }

    /// <summary>Drain all pending frames with a short timeout until none arrive.</summary>
    private async Task DrainAny(TimeSpan timeout, CancellationToken ct)
    {
        while (true)
        {
            var f = await _cat!.WaitForAnyFrameAsync(timeout, ct);
            if (f is null)
                break;
        }
    }

    // ── Port 50002 audio channel open ─────────────────────────────────────────

    /// <summary>
    /// Activate the RX audio stream on port 50002.
    /// Mirrors DoCatChannelOpenAsync but for audio (dev=2, UsbAudio).
    ///
    /// Confirmed sequence from Yaesu RX-only Wireshark capture:
    ///   1. PC→SCU:50002  SendAudioConnect (0x0e, MID=0x0104)
    ///   2. SCU→PC:50002  0x0e ACK (MID=0x0184)
    ///   3. PC→SCU:50002  SendAudioOpen ×2 (0x26, MID=0x0105) — audio config
    ///   4. SCU begins sending 0xa2 RX audio ~40ms later
    /// </summary>
    /// <summary>
    /// Open the audio channel on port 50002.
    /// <para>
    /// ORDERING: scope.SendDevPortConnect() is called after the audio ACK but
    /// before SendAudioOpen. This is the only window in which the SCU accepts a
    /// scope DevPortConnect — confirmed from Wireshark analysis 2026-06-05.
    /// Once SendAudioOpen is sent the SCU enters streaming mode and ignores
    /// further DevPortConnect requests on port 50003.
    /// </para>
    /// </summary>
    internal async Task DoAudioChannelOpenAsync(
        RemotePath audioPath, CancellationToken ct, ScopeChannel? scope = null)
    {
        _log.LogDebug("Opening audio channel (port 50002)...");

        // Send SendAudioConnect twice. On Windows, the very first Send() on a newly
        // opened UdpClient socket is sometimes silently dropped by the kernel before
        // the socket is fully registered. Sending twice (with a short gap) ensures
        // the SCU receives at least one copy. The SCU ignores duplicates harmlessly.
        var connectFrame1 = ZzFrameCodec.BuildSendAudioConnect(NextSeq(), _helloAckNonce);
        _log.LogDebug("AudioConnect frame 1 ({Len} bytes): {Hex}",
                      connectFrame1.Length, Convert.ToHexString(connectFrame1));
        audioPath.Send(connectFrame1);
        _log.LogDebug("AudioConnect frame 1 sent");

        await Task.Delay(5, ct);

        var connectFrame2 = ZzFrameCodec.BuildSendAudioConnect(NextSeq(), _helloAckNonce);
        _log.LogDebug("AudioConnect frame 2 ({Len} bytes): {Hex}",
                      connectFrame2.Length, Convert.ToHexString(connectFrame2));
        audioPath.Send(connectFrame2);
        _log.LogDebug("AudioConnect frame 2 sent");

        var connAck = await audioPath.WaitForZzTypeAsync(0x0e, TimeSpan.FromMilliseconds(_t.StepTimeoutMs), ct);
        if (connAck is null)
            _log.LogWarning("Audio SendDevPortConnect ACK not received — continuing");
        else
            _log.LogDebug("Audio SendDevPortConnect ACK received");

        // ── Scope DevPortConnect (MUST come before SendAudioOpen) ─────────────
        // Confirmed from Wireshark: the SCU only accepts the scope DevPortConnect
        // in the window between the audio ACK and SendAudioOpen. Once SendAudioOpen
        // is sent, the SCU ignores port 50003 DevPortConnect requests entirely.
        //if (scope is not null)
        //{
        //    scope.SendDevPortConnect();
        //    _log.LogDebug("Scope DevPortConnect sent — waiting 20ms before SendAudioOpen");
        //    await Task.Delay(20, ct);   // ← add this
        //}

        if (scope is not null)
        {
            await scope.SendDevPortConnectAsync(TimeSpan.FromMilliseconds(_t.ScopeAckTimeoutMs), ct);
        }

        // Duplicate pair — same content sent twice
        audioPath.Send(ZzFrameCodec.BuildSendAudioOpen(NextSeq(), _helloAckNonce, _audioQuality,
            playbackLatencyMs: _t.AudioPlaybackLatencyMs, recordLatencyMs: _t.AudioRecordLatencyMs));
        audioPath.Send(ZzFrameCodec.BuildSendAudioOpen(NextSeq(), _helloAckNonce, _audioQuality,
            playbackLatencyMs: _t.AudioPlaybackLatencyMs, recordLatencyMs: _t.AudioRecordLatencyMs));

        // Give the SCU time to start the RX stream (~40ms observed in capture)
        await Task.Delay(_t.AudioSettleMs, ct);
        _log.LogInformation("Audio channel open");
    }

    /// <summary>
    /// Create an AudioChannel wired into this session's address, nonce and
    /// sequence counter. Call StartAsync() on the returned instance to open
    /// the audio channel and begin audio flow.
    /// </summary>
    /// <param name="scope">
    /// Optional ScopeChannel. When supplied, its DevPortConnect is sent at the
    /// correct point inside DoAudioChannelOpenAsync (after audio ACK, before
    /// SendAudioOpen) so that scope data starts flowing automatically.
    /// The ScopeChannel must have been created via CreateScopeChannel() and
    /// StartAsync() must have been called on it first to open its socket.
    /// </param>
    public AudioChannel CreateAudioChannel(
        int waveOutDevice = 0,
        ILoggerFactory? loggerFactory = null,
        int waveInDevice = 0,
        ScopeChannel? scope = null)
    {
        // Capture scope in the closure so the channel-open delegate can pass it
        // through to DoAudioChannelOpenAsync without changing the AudioChannel API.
        return new AudioChannel(
            _addr, _helloAckNonce, NextSeq,
            (path, ct) => DoAudioChannelOpenAsync(path, ct, scope),
            _audioQuality, waveOutDevice, waveInDevice, loggerFactory ?? _loggerFactory, _t);
    }

    /// <summary>
    /// Create a ScopeChannel. Call StartAsync() on it to open the socket, then
    /// pass it to CreateAudioChannel(scope: ...) so the session wires up the
    /// DevPortConnect at the correct moment during audio channel open.
    /// </summary>
    public ScopeChannel CreateScopeChannel(ILoggerFactory? loggerFactory = null)
    {
        var ch = new ScopeChannel(_addr, _helloAckNonce, NextSeq, loggerFactory ?? _loggerFactory);
        ch.FrameDecimation = _t.ScopeFrameDecimation;
        return ch;
    }

    // ── Steady-state tasks ────────────────────────────────────────────────────

    /// <summary>
    /// Fixed binary poll commands (PC→SCU, type 0x19, K=0x01).
    /// Extracted from Yaesu Wireshark capture. Not ASCII CAT.
    /// </summary>
    private static readonly byte[] PollCmd1 = [0x40, 0x51, 0x31, 0x27, 0x49, 0x46, 0x24];
    private static readonly byte[] PollCmd2 = [0x52, 0x52, 0x4e, 0x48, 0x2f, 0x68, 0x24];

    /// <summary>
    /// 0x15 'CG&lt;' query command (dec[13:] = 43 47 3c) — triggers SCU to
    /// respond with a 0x1a packet containing the current VFO-A frequency.
    /// Confirmed from DLL Wireshark capture at 21.879123 MHz.
    /// </summary>
    private static readonly byte[] FreqQueryCmd = [0x43, 0x47, 0x3c];

    /// <summary>
    /// Decode frequency from 0x1a SCU→PC response (dec[13:], 8 bytes).
    /// Encoding keys confirmed from one capture (21.879123 MHz):
    ///   1d, 14, 13, 0d, 0a, 02, 01, 0f
    /// Each byte: freq_ascii[i] = payload[i] ^ key[i], then freq_ascii - 0x30 = digit.
    /// Last key 0x0f is the terminator key (matches CAT SET ';' key).
    /// </summary>
    private static readonly byte[] FreqResponseKeys =
        [0x1d, 0x14, 0x13, 0x0d, 0x0a, 0x02, 0x01, 0x0f];

    private static long? DecodeFrequency1a(byte[] payload)
    {
        if (payload.Length < 8)
            return null;
        var sb = new System.Text.StringBuilder();
        for (int i = 0; i < 8; i++)
        {
            int digit = (payload[i] ^ FreqResponseKeys[i]) - 0x30;
            if (digit < 0 || digit > 9)
                return null;
            sb.Append(digit);
        }
        // 8 digits = last 8 of the 9-digit FA0XXXXXXXXX; format
        // Prepend leading zero for frequencies < 100 MHz
        if (!long.TryParse(sb.ToString(), out long freq8))
            return null;
        // The 9-digit freq has a leading zero: 0XXXXXXXX
        // but FA021879123 → digits 2,1,8,7,9,1,2,3 → 21879123 → 21.879123 MHz
        return freq8;  // in Hz (e.g. 21879123 = 21.879123 MHz)
    }

    private async Task CatPumpAsync()
    {
        _log.LogDebug("CAT pump started");
        try
        {
            await foreach (var frame in _cat!.Frames.ReadAllAsync(_cts.Token))
            {
                // All SCU→PC responses on port 50001 use FUN_10003c30 encoding.
                // MID = 0x0185 (UsbCat_WriteAns).
                // The full CAT response string = ASCII bytes at fun[10..] up to ';'.
                // fun[10:14] holds the first 4 chars (stored as LE uint32 ASCII).
                // fun[14:] holds the remaining chars including the terminating ';'.
                //
                // Packet types seen: 0x1a (FA freq), 0x2a (IF full state),
                //                    0x1d (FD band/filter), and others.
                // 0x18 is the continuous broadcast — skip it.
                if (frame.ZzType == 0x18)
                    continue;

                // Binary meter responses (e.g. SPM) must be checked first: they end with ';'
                // so DecodeFunCatResponse would "succeed" and return binary garbage.
                var binary = DecodeFunBinaryPayload(frame.Raw);
                if (binary is not null)
                {
                    _binaryMeterSubject.OnNext(binary);
                }
                else
                {
                    var cat = DecodeFunCatResponse(frame.Raw);
                    if (cat is not null)
                    {
                        _log.LogDebug("CAT RX: '{Cat}'", cat);
                        EmitCat(cat);
                    }
                }
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) { _log.LogError(ex, "CAT pump error"); }
        _log.LogDebug("CAT pump stopped");
    }

    /// <summary>
    /// Decode a FUN_10003c30-encoded SCU→PC response on port 50001.
    /// Returns the full ASCII CAT string (e.g. "FA028500000;" "IF001028500000+000000200000;")
    /// or null if the packet doesn't contain a valid CAT response.
    /// </summary>
    private static string? DecodeFunCatResponse(byte[] raw)
    {
        if (raw.Length < 18)
            return null;  // too short for any valid response
        // FUN decode
        byte kl = raw[6], kh = raw[7];
        var fun = new byte[raw.Length - 8];
        for (int i = 0; i < fun.Length; i++)
            fun[i] = (byte)(((~i + 1) & 0xff) ^ raw[8 + i] ^ kl ^ kh);

        // Sanity check: mid should be 0x0185 (UsbCat_WriteAns)
        if (fun.Length < 14)
            return null;
        ushort mid = (ushort)(fun[2] | (fun[3] << 8));
        if (mid != 0x0185)
            return null;

        // CAT string starts at fun[10] (first 4 bytes are ASCII chars of prefix)
        // and runs to the first ';'
        int end = Array.IndexOf(fun, (byte)';', 10);
        if (end < 0)
            return null;
        return System.Text.Encoding.ASCII.GetString(fun, 10, end - 10 + 1);
    }

    private void EmitCat(string cat)
    {
        var msg = new CatMessage(cat);
        _catSubject.OnNext(msg);
        _catChannel.Writer.TryWrite(msg);
    }

    /// <summary>
    /// Decode the FUN-encoded payload from a port 50001 packet and return the
    /// 15-byte binary meter data if the packet is an SPM response.
    ///
    /// SPM serial format: fun[10..24] = "SPM" + 12 meter bytes + BCC, fun[25] = ';'
    /// (CatFormat.AddData strips the trailing ';' before calling TryParse, so the
    /// 15-byte payload is fun[10..24] with BCC at fun[24].)
    ///
    /// Detection: "SPM" ASCII prefix (0x53 0x50 0x4D) at fun[10..12] plus BCC check.
    /// Must be called BEFORE DecodeFunCatResponse because the trailing ';' at fun[25]
    /// would otherwise cause DecodeFunCatResponse to return binary garbage.
    /// </summary>
    private static byte[]? DecodeFunBinaryPayload(byte[] raw)
    {
        // Need: 8 ZZ header + 10 FUN header + 15 payload + 1 ';' = 34 bytes minimum
        if (raw.Length < 34)
            return null;

        byte kl = raw[6], kh = raw[7];

        // Decode only as many bytes as we need (FUN header + 16 bytes of payload+';')
        const int needed = 26;  // fun[0..25]: 10-byte header + 15-byte payload + ';'
        var fun = new byte[Math.Min(needed, raw.Length - 8)];
        for (int i = 0; i < fun.Length; i++)
            fun[i] = (byte)(((~i + 1) & 0xff) ^ raw[8 + i] ^ kl ^ kh);

        if (fun.Length < needed)
            return null;

        ushort mid = (ushort)(fun[2] | (fun[3] << 8));
        if (mid != 0x0185)
            return null;

        // Must start with "SPM" (0x53 0x50 0x4D) — the binary response command identifier
        if (fun[10] != 0x53 || fun[11] != 0x50 || fun[12] != 0x4D)
            return null;

        // Extract 15-byte payload (fun[10..24]) and validate BCC: sum(bytes[0..13]) == bytes[14]
        var payload = new byte[15];
        Array.Copy(fun, 10, payload, 0, 15);
        byte bcc = 0;
        for (int i = 0; i < 14; i++)
            bcc += payload[i];
        if (bcc != payload[14])
            return null;

        return payload;
    }

    private static string? DecodeCatString(byte[] payload)
    {
        // Payload ends with 0x24 '$' — strip it and return the ASCII content
        int end = Array.IndexOf(payload, (byte)0x24);
        if (end < 0)
            end = payload.Length;
        if (end == 0)
            return null;
        return System.Text.Encoding.ASCII.GetString(payload, 0, end);
    }

    private void SendPollCmd(byte[] cmdData)
    {
        if (_cat is null)
            return;
        _cat.Send(ZzFrameCodec.BuildCatSend(NextSeq(), _helloAckNonce,
                                             (byte)++_catCmdCounter, cmdData));
    }

    /// <summary>
    /// Send a 0x15 query command to the SCU (triggers a 0x1a response with state data).
    /// 'CG&lt;' queries VFO-A frequency. Confirmed from DLL Wireshark trace.
    /// </summary>
    private void SendCatQuery(byte[] queryData)
    {
        if (_cat is null)
            return;
        _cat.Send(ZzFrameCodec.BuildCatCmd(ZzFrameCodec.Port50001Type15Template,
                                            NextSeq(), _helloAckNonce, 0x05,
                                            queryData));
    }

    private sealed record RadioState(long? FreqHz, string? Mode);

    /// <summary>
    /// Decode the binary state response from the SCU (dec[13:] of type 0x1e or 0x19).
    ///
    /// Observed 0x1e response dec[13:] (12 bytes):
    ///   1a 19 18 07 06 c2 01 3d 0f 0c XX 34
    ///   where XX = mode byte (varies with radio mode)
    ///
    /// Spontaneous 0x19 dec[13:] (7 bytes):
    ///   31 30 33 2f 2c 2f 24  = '103/,/$' etc (may encode frequency)
    ///
    /// Full decoding not yet confirmed — returns null if format unrecognised.
    /// </summary>
    private static RadioState? DecodeRadioState(byte[] data)
    {
        if (data.Length == 12 && data[0] == 0x1a && data[1] == 0x19)
        {
            // 0x1e response: mode at byte 10
            byte modeByte = data[10];
            string? mode = modeByte switch
            {
                0x57 => "1",  // LSB
                0x5a => "2",  // USB
                0x5f => "3",  // CW-L or similar
                0x5c => "5",  // AM
                0x55 => "6",  // FM
                0x64 => "7",  // DATA-L
                0x66 => "8",  // DATA-U
                0x6b => "9",  // DATA-FM
                _ => null
            };
            return new RadioState(null, mode);
        }

        // Spontaneous 0x19 — format TBD, return null for now
        return null;
    }

    private async Task KeepaliveAsync()
    {
        _log.LogDebug("Keepalive task started");
        int failures = 0;

        try
        {
            while (!_cts.Token.IsCancellationRequested)
            {
                await Task.Delay(_t.KeepaliveIntervalMs, _cts.Token);

                // Send keepalives to all open ports
                // NOTE: do NOT send to port 50003 (scope) — the SCU sends ICMP
                // Port Unreachable back to us, which corrupts the session state.
                // Scope is not yet supported.
                byte seq50000 = NextSeq();
                byte seq50001 = NextSeq();

                _control!.Send(ZzFrameCodec.BuildKeepalive(false, seq50000));
                _cat!.Send(ZzFrameCodec.BuildKeepalive(authenticated: true, seq50001, _helloAckNonce));

                // Port 50000 responds with type 0x0b
                var ack = await _control.WaitForZzTypeAsync(0x0b, TimeSpan.FromMilliseconds(_t.KeepaliveTimeoutMs), _cts.Token);

                if (ack is null)
                {
                    failures++;
                    _log.LogWarning("Keepalive timeout #{Failures}", failures);
                    if (failures >= 10)
                    {
                        _log.LogError("10 keepalive failures — connection lost");
                        IsConnected = false;
                        _catSubject.OnError(new IOException("SCU connection lost"));
                        break;
                    }
                }
                else
                {
                    failures = 0;
                }
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) { _log.LogError(ex, "Keepalive error"); }

        _log.LogDebug("Keepalive task stopped");
    }

    // ── Public CAT API ────────────────────────────────────────────────────────

    // NOTE: The SCU-LAN10 does NOT use Yaesu ASCII CAT over port 50001.
    // It uses a proprietary binary polling protocol (see CatPumpAsync).
    // The public API below emits synthetic CAT-style strings decoded from
    // the binary state responses so callers can use familiar CAT notation.
    // Direct ASCII CAT command sending is not supported in this protocol.

    /// <summary>
    /// Request a frequency readback. Sends the confirmed 0x15 'CG&lt;' query
    /// which triggers a 0x1a response containing the current VFO-A frequency.
    /// The result arrives asynchronously via CatMessages as "FA0XXXXXXXX;".
    /// </summary>
    public ValueTask RequestFrequencyAsync(bool vfoB = false,
                                            CancellationToken ct = default)
    {
        if (!IsConnected || _cat is null)
            return ValueTask.CompletedTask;
        SendCatQuery(FreqQueryCmd);
        return ValueTask.CompletedTask;
    }

    /// <summary>
    /// Send a raw binary payload to the radio via the SCU-LAN10 CAT channel.
    /// Used for binary poll commands such as the SPM meter request.
    /// </summary>
    public ValueTask SendCatBytesAsync(byte[] data, CancellationToken ct = default)
    {
        if (!IsConnected || _cat is null)
            return ValueTask.CompletedTask;
        _cat.Send(ZzFrameCodec.BuildSendCatWrite(NextSeq(), _helloAckNonce, ++_catPktId, data));
        return ValueTask.CompletedTask;
    }

    /// <summary>
    /// Send a Yaesu ASCII CAT command to the radio via the SCU-LAN10.
    /// The command is wrapped in a FUN_10003c30-encoded SendCatWrite packet
    /// (same encoding used by SetFrequencyAsync and the Yaesu app itself).
    /// Examples: "FA;" "MD;" "MD0;" "PC;" "SM0;" "TX;" "RX;"
    /// </summary>
    public ValueTask SendCatAsync(string command, CancellationToken ct = default)
    {
        if (!IsConnected || _cat is null)
            return ValueTask.CompletedTask;

        _log.LogDebug("SendCat: '{Cmd}'", command);
        _cat.Send(ZzFrameCodec.BuildSendCatWrite(NextSeq(), _helloAckNonce,
                                                  ++_catPktId,
                                                  System.Text.Encoding.ASCII.GetBytes(command)));
        return ValueTask.CompletedTask;
    }

    /// <summary>Set VFO-A (or B) frequency in Hz. e.g. 14_200_000 for 14.200 MHz.</summary>
    public ValueTask SetFrequencyAsync(long freqHz, bool vfoB = false,
                                        CancellationToken ct = default)
    {
        if (!IsConnected || _cat is null)
            return ValueTask.CompletedTask;

        // Format: FA0<8 digits>; (12 chars total), e.g. 14350125 Hz → "FA014350125;"
        string prefix = vfoB ? "FB0" : "FA0";
        string cmd = prefix + (freqHz % 100_000_000).ToString("D8") + ";";
        _log.LogDebug("SetFrequency: {Cmd}", cmd);
        // Use SendCatWrite (FUN format) — same encoding used by Yaesu app
        _cat.Send(ZzFrameCodec.BuildSendCatWrite(NextSeq(), _helloAckNonce,
                                                  ++_catPktId,
                                                  System.Text.Encoding.ASCII.GetBytes(cmd)));
        return ValueTask.CompletedTask;
    }

    private RemotePath OpenPath(string addr, int port)
    {
        var path = new RemotePath(addr, port,
            _loggerFactory.CreateLogger<RemotePath>());
        path.Open();
        return path;
    }

    // ── Cleanup ───────────────────────────────────────────────────────────────

    private async Task CleanupPathsAsync()
    {
        var paths = new[] { _control, _cat, _audio, _scope };
        _control = _cat = _audio = _scope = null;
        foreach (var p in paths)
            if (p is not null)
                await p.CloseAsync();
    }

    public async ValueTask DisposeAsync()
    {
        await DisconnectAsync();
        _catSubject.OnCompleted();
        _binaryMeterSubject.OnCompleted();
        _catChannel.Writer.TryComplete();
        _cts.Dispose();
    }
}
using System.Reactive.Linq;
using System.Reactive.Subjects;
using System.Text;
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
    // ── Configuration ─────────────────────────────────────────────────────────

    private static readonly TimeSpan StepTimeout = TimeSpan.FromSeconds(3);
    private static readonly TimeSpan KeepaliveInterval = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan KeepaliveTimeout = TimeSpan.FromSeconds(2);

    // ── State ─────────────────────────────────────────────────────────────────

    private readonly ILogger<ScuSession> _log;
    private readonly ILoggerFactory _loggerFactory;

    private RemotePath? _control;
    private RemotePath? _cat;
    private RemotePath? _audio;
    private RemotePath? _scope;

    private uint _seq;          // outgoing ZZ-frame sequence counter, starts at 1
    private byte _catCmdCounter; // dec[9] in type 0x19 CAT send packets

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
        CancellationToken ct = default)
    {
        if (IsConnected)
            await DisconnectAsync();

        _log.LogInformation("Connecting to {Addr}", addr);
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

            // Now safe to open the data paths
            _cat = OpenPath(addr, ScuPorts.Cat);
            _audio = OpenPath(addr, ScuPorts.Audio);
            _scope = OpenPath(addr, ScuPorts.Scope);
            _log.LogDebug("Data paths opened (cat/audio/scope)");

            // Step 4 — Port 50001 mini-handshake + catcmd_table upload
            if (!await DoCatChannelOpenAsync(ct))
                return false;

            // Start steady-state tasks
            IsConnected = true;
            _catPumpTask = Task.Run(CatPumpAsync, _cts.Token);
            _keepaliveTask = Task.Run(KeepaliveAsync, _cts.Token);

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
            await Task.WhenAll(tasks).WaitAsync(TimeSpan.FromSeconds(3));
        }
        catch { /* timeout fine */ }

        await CleanupPathsAsync();
        _log.LogInformation("Disconnected");
    }

    // ── Login steps ───────────────────────────────────────────────────────────

    private byte _helloAckNonce; // dec[5] from HELLO-ACK — used to build KEY EXCHANGE and AUTH BLOB

    private async Task<bool> DoLoginAsync(string user, string pass, CancellationToken ct)
    {
        _log.LogDebug("Sending Login (HELLO)...");

        for (int attempt = 0; attempt < 2; attempt++)
        {
            if (attempt > 0)
                _log.LogDebug("Login timeout — retrying");

            byte[] hello = ZzFrameCodec.BuildHello(user, pass, NextSeq());
            _control!.Send(hello);

            var received = await _control.WaitForZzTypeAsync(0x18, StepTimeout, ct);
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
        var keyAck = await _control.WaitForZzTypeAsync(0x18, TimeSpan.FromSeconds(10), ct);
        if (keyAck is null)
        {
            _log.LogError("KEY-ACK not received");
            return false;
        }
        _log.LogDebug("KEY-ACK received");

        // AUTH BLOB — dec[5] = nonce ^ 0x79
        _control.Send(ZzFrameCodec.BuildAuthBlob(NextSeq(), _helloAckNonce));
        _log.LogDebug("AUTH BLOB sent — waiting for AUTH-ACK...");
        var authAck1 = await _control.WaitForZzTypeAsync(0x1a, TimeSpan.FromSeconds(20), ct);
        if (authAck1 is null)
        {
            _log.LogError("AUTH-ACK not received");
            return false;
        }
        var authAck2 = await _control.WaitForZzTypeAsync(0x1a, TimeSpan.FromSeconds(5), ct);
        _log.LogDebug("AUTH-ACK received ({N} of 2)", authAck2.HasValue ? 2 : 1);

        // CONFIG A — send alone, wait for ACK, then send CONFIG B
        _control.Send(ZzFrameCodec.BuildConfig(ZzFrameCodec.ConfigATemplate, NextSeq(), _helloAckNonce));
        var cfgAckA = await _control.WaitForZzTypeAsync(0x0e, TimeSpan.FromMilliseconds(500), ct);
        if (cfgAckA is null)
            _log.LogWarning("CONFIG A ACK not received — continuing");

        _control.Send(ZzFrameCodec.BuildConfig(ZzFrameCodec.ConfigBTemplate, NextSeq(), _helloAckNonce));

        // INIT packets — send one at a time, wait for ACK between each
        // Yaesu sends: INIT A → wait ACK → INIT B, C, D in quick succession → FINAL-ACK
        _control.Send(ZzFrameCodec.BuildInit(ZzFrameCodec.InitATemplate, NextSeq(), _helloAckNonce, 0x02));
        var initAckA = await _control.WaitForZzTypeAsync(0x0e, TimeSpan.FromMilliseconds(500), ct);
        if (initAckA is null)
            _log.LogWarning("INIT A ACK not received — continuing");

        _control.Send(ZzFrameCodec.BuildInit(ZzFrameCodec.InitBTemplate, NextSeq(), _helloAckNonce, 0x02));
        _control.Send(ZzFrameCodec.BuildInit(ZzFrameCodec.InitCTemplate, NextSeq(), _helloAckNonce, 0x06));
        _control.Send(ZzFrameCodec.BuildInit(ZzFrameCodec.InitDTemplate, NextSeq(), _helloAckNonce, 0x06));

        var finalAck = await _control.WaitForZzTypeAsync(0x0e, TimeSpan.FromMilliseconds(500), ct);
        if (finalAck is null)
            _log.LogWarning("FINAL-ACK not received — continuing");
        else
            _log.LogInformation("Handshake complete — FINAL-ACK received");

        return true;
    }

    // ── Port 50001 channel open (post-handshake) ──────────────────────────────

    /// <summary>
    /// After the port 50000 handshake completes, port 50001 needs its own
    /// mini-handshake before CAT commands can flow:
    ///   1. PC → keepalive 0x0e (dec[1]=0x02, dec[5]=nonce^0x0a)
    ///   2. SCU → keepalive 0x0e + flood of 0x18 packets
    ///   3. PC → two 0x16 packets + one 0x15 packet (catcmd_table)
    ///   4. SCU → flood of 0x18 responses
    ///   5. PC → 0x12 packet (session confirm)
    ///   6. Steady state: PC → 0x19 (CAT), SCU → 0x19 (response)
    /// </summary>
    private async Task<bool> DoCatChannelOpenAsync(CancellationToken ct)
    {
        _log.LogDebug("Opening CAT channel (port 50001)...");

        // Authenticated keepalive: dec[1]=0x02, dec[5]=nonce^0x0a
        _cat!.Send(ZzFrameCodec.BuildKeepalive(authenticated: true, NextSeq(), _helloAckNonce));

        var kpAck = await _cat.WaitForZzTypeAsync(0x0e, StepTimeout, ct);
        if (kpAck is null)
            _log.LogWarning("Port 50001 keepalive ACK not received — continuing");

        // Drain any queued 0x18 packets (SCU sends these unsolicited)
        int drained = 0;
        while (true)
        {
            var extra = await _cat.WaitForZzTypeAsync(0x18, TimeSpan.FromMilliseconds(50), ct);
            if (extra is null)
                break;
            drained++;
        }
        if (drained > 0)
            _log.LogDebug("Drained {N} initial 0x18 packets from port 50001", drained);

        // K constants confirmed from three Yaesu sessions:
        //   0x16 → K=0x02, 0x15 → K=0x05, 0x12 (50001) → K=0x06
        _cat.Send(ZzFrameCodec.BuildCatCmd(ZzFrameCodec.Port50001Type16Template, NextSeq(), _helloAckNonce, 0x02));
        _cat.Send(ZzFrameCodec.BuildCatCmd(ZzFrameCodec.Port50001Type16Template, NextSeq(), _helloAckNonce, 0x02));
        _cat.Send(ZzFrameCodec.BuildCatCmd(ZzFrameCodec.Port50001Type15Template, NextSeq(), _helloAckNonce, 0x05));

        var catAck = await _cat.WaitForZzTypeAsync(0x18, StepTimeout, ct);
        if (catAck is null)
            _log.LogWarning("CAT channel 0x18 ACK not received — continuing");
        else
            _log.LogDebug("CAT channel ACK received");

        _cat.Send(ZzFrameCodec.BuildCatCmd(ZzFrameCodec.Port50001Type12Template, NextSeq(), _helloAckNonce, 0x06));

        await Task.Delay(30, ct);

        _log.LogInformation("CAT channel open");
        return true;
    }

    // ── Steady-state tasks ────────────────────────────────────────────────────

    private async Task CatPumpAsync()
    {
        _log.LogDebug("CAT pump started");
        try
        {
            await foreach (var frame in _cat!.Frames.ReadAllAsync(_cts.Token))
            {
                // SCU→PC: type 0x1e = CAT response (NOT 0x19)
                // type 0x19 from SCU = unsolicited CAT push
                // Both carry CAT data at dec[13:]
                if ((frame.ZzType == 0x1e || frame.ZzType == 0x19)
                    && frame.Payload.Length > 13)
                {
                    var catBytes = frame.Payload[13..];
                    string raw = ExtractCatString(catBytes);
                    if (!string.IsNullOrWhiteSpace(raw))
                    {
                        _log.LogDebug("CAT RX (0x{Type:x2}): {Cat}", frame.ZzType, raw);
                        var msg = new CatMessage(raw);
                        _catSubject.OnNext(msg);
                        _catChannel.Writer.TryWrite(msg);
                    }
                }
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) { _log.LogError(ex, "CAT pump error"); }
        _log.LogDebug("CAT pump stopped");
    }

    private async Task KeepaliveAsync()
    {
        _log.LogDebug("Keepalive task started");
        int failures = 0;

        try
        {
            while (!_cts.Token.IsCancellationRequested)
            {
                await Task.Delay(KeepaliveInterval, _cts.Token);

                // Send keepalives to all open ports (matches Yaesu behaviour)
                byte seq50000 = NextSeq();
                byte seq50001 = NextSeq();
                byte seq50003 = NextSeq();

                _control!.Send(ZzFrameCodec.BuildKeepalive(false, seq50000));
                _cat!.Send(ZzFrameCodec.BuildKeepalive(authenticated: true, seq50001, _helloAckNonce));
                _scope?.Send(ZzFrameCodec.BuildKeepalive(authenticated: true, seq50003, _helloAckNonce));

                // Port 50000 responds with type 0x0b
                var ack = await _control.WaitForZzTypeAsync(0x0b, KeepaliveTimeout, _cts.Token);

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

    /// <summary>Send a raw Yaesu ASCII CAT command, e.g. "FA014200000;" or "MD0;"</summary>
    public ValueTask SendCatAsync(string command, CancellationToken ct = default)
    {
        if (!IsConnected || _cat is null)
            throw new InvalidOperationException("Not connected.");
        SendCatRaw(Encoding.ASCII.GetBytes(command));
        return ValueTask.CompletedTask;
    }

    /// <summary>Set VFO-A (or B) frequency in Hz. e.g. 14_200_000 for 14.200 MHz.</summary>
    public ValueTask SetFrequencyAsync(long freqHz, bool vfoB = false,
                                        CancellationToken ct = default)
        => SendCatAsync((vfoB ? "FB" : "FA") + freqHz.ToString("D9") + ";", ct);

    /// <summary>Request a frequency read-back. The radio replies with FA/FB.</summary>
    public ValueTask RequestFrequencyAsync(bool vfoB = false,
                                            CancellationToken ct = default)
        => SendCatAsync(vfoB ? "FB;" : "FA;", ct);

    // ── Helpers ───────────────────────────────────────────────────────────────

    private void SendCatRaw(byte[] catData)
    {
        if (_cat is null)
            return;
        // ZZ type 0x19, CAT data at dec[13:]
        // dec structure: 0c 08 0f 00 08 <nonce^0x01> 0a 0b 04 <cmd_counter> 06 07 00 <cat_bytes>
        _cat.Send(ZzFrameCodec.BuildCatSend(NextSeq(), _helloAckNonce,
                                             ++_catCmdCounter, catData));
    }

    private static string ExtractCatString(byte[] payload)
    {
        int end = Array.IndexOf(payload, (byte)0);
        int len = end >= 0 ? end : payload.Length;
        return Encoding.ASCII.GetString(payload, 0, len).Trim();
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
        _catChannel.Writer.TryComplete();
        _cts.Dispose();
    }
}
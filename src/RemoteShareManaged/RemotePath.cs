using System.Net;
using System.Net.Sockets;
using System.Threading.Channels;
using Microsoft.Extensions.Logging;
using RemoteShareManaged.Codec;
using RemoteShareManaged.Protocol;

namespace RemoteShareManaged.Transport;

/// <summary>
/// Owns a single UDP socket connecting to one SCU-LAN10 port.
/// Handles all send/receive for that port asynchronously.
///
/// Receive loop pushes decoded frames into a Channel&lt;ReceivedFrame&gt;
/// which consumers read via ReceiveAsync() or the Frames reader.
///
/// Portability: uses System.Net.Sockets.UdpClient only — no Win32, no P/Invoke.
/// Works on Windows, Linux, and Android.
/// </summary>
public sealed class RemotePath : IAsyncDisposable
{
    private readonly ILogger<RemotePath> _log;
    private readonly string _addr;
    private readonly int _port;
    private readonly Channel<ReceivedFrame> _channel;
    private readonly CancellationTokenSource _cts = new();

    private UdpClient? _udp;
    private IPEndPoint? _remote;
    private Task? _receiveLoop;

    // ── Decode buffer — reused per-receive, not shared between calls ──────────
    private readonly byte[] _decodeBuf = new byte[BufferSizes.Remote];

    public ChannelReader<ReceivedFrame> Frames => _channel.Reader;
    public bool IsOpen => _udp != null;

    public RemotePath(string addr, int port, ILogger<RemotePath> log)
    {
        _addr = addr;
        _port = port;
        _log = log;
        _channel = Channel.CreateBounded<ReceivedFrame>(
            new BoundedChannelOptions(256)
            {
                FullMode = BoundedChannelFullMode.DropOldest,
                SingleReader = false,
                SingleWriter = true,
            });
    }

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    public void Open()
    {
        _remote = new IPEndPoint(IPAddress.Parse(_addr), _port);

        // Bind to any local port but do NOT call Connect().
        // Connect() installs a source-address filter that silently drops
        // packets from unexpected source ports — which may include the SCU's
        // KEY-ACK and other handshake responses if the SCU uses a different
        // source port than expected. Without Connect() we receive from any source.
        _udp = new UdpClient(new IPEndPoint(IPAddress.Any, 0));
        _udp.Client.SetSocketOption(SocketOptionLevel.Socket,
                                    SocketOptionName.ReuseAddress, true);

        _receiveLoop = Task.Run(ReceiveLoopAsync, _cts.Token);
        _log.LogDebug("RemotePath:{Port} opened (local port {Local})",
            _port, ((IPEndPoint)_udp.Client.LocalEndPoint!).Port);
    }

    public async ValueTask CloseAsync()
    {
        _cts.Cancel();
        _channel.Writer.TryComplete();

        if (_receiveLoop is not null)
        {
            try
            {
                await _receiveLoop.WaitAsync(TimeSpan.FromSeconds(2));
            }
            catch { /* timeout or cancelled — fine */ }
        }

        _udp?.Close();
        _udp?.Dispose();
        _udp = null;
        _log.LogDebug("RemotePath:{Port} closed", _port);
    }

    public async ValueTask DisposeAsync() => await CloseAsync();

    // ── Send ──────────────────────────────────────────────────────────────────

    /// <summary>Send a raw pre-encoded frame. Fire-and-forget.</summary>
    public void Send(byte[] frame)
    {
        if (_udp is null || _remote is null)
            throw new InvalidOperationException("Path not open.");
        _udp.Send(frame, frame.Length, _remote);
    }

    /// <summary>Send a raw pre-encoded frame asynchronously.</summary>
    public async ValueTask SendAsync(byte[] frame, CancellationToken ct = default)
    {
        if (_udp is null || _remote is null)
            throw new InvalidOperationException("Path not open.");
        await _udp.SendAsync(frame, _remote, ct);
    }

    // ── Receive loop ──────────────────────────────────────────────────────────

    private async Task ReceiveLoopAsync()
    {
        _log.LogDebug("RemotePath:{Port} receive loop started", _port);

        while (!_cts.Token.IsCancellationRequested)
        {
            try
            {
                UdpReceiveResult result = await _udp!.ReceiveAsync(_cts.Token);
                byte[] data = result.Buffer;

                // Log raw datagrams — suppress 0x18 flood to Trace level
                byte pktType = data.Length > 2 ? data[2] : (byte)0;
                if (pktType == 0x18)
                    _log.LogTrace("RemotePath:{Port} RX {Len} bytes type=0x18", _port, data.Length);
                else
                    _log.LogDebug("RemotePath:{Port} RX {Len} bytes from {Remote} type=0x{Type:x2}",
                        _port, data.Length, result.RemoteEndPoint, pktType);

                if (!TryDecodeAndParse(data, out ReceivedFrame frame))
                {
                    _log.LogWarning(
                        "RemotePath:{Port} {Len}-byte frame failed decode (from {Remote})",
                        _port, data.Length, result.RemoteEndPoint);
                    continue;
                }

                if (!_channel.Writer.TryWrite(frame))
                {
                    _log.LogWarning(
                        "RemotePath:{Port} channel full — dropped ZZ=0x{ZZ:x2} MID={Mid}",
                        _port, frame.ZzType, frame.Mid);
                }
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (SocketException ex) when (!_cts.Token.IsCancellationRequested)
            {
                _log.LogError(ex, "RemotePath:{Port} socket error", _port);
                await Task.Delay(100, _cts.Token).ConfigureAwait(false);
            }
            catch (Exception ex) when (!_cts.Token.IsCancellationRequested)
            {
                _log.LogError(ex, "RemotePath:{Port} unexpected error", _port);
            }
        }

        _log.LogDebug("RemotePath:{Port} receive loop stopped", _port);
    }

    private bool TryDecodeAndParse(byte[] data, out ReceivedFrame frame)
    {
        frame = default;
        if (!ZzFrameCodec.TryDecode(data, out byte zzType, _decodeBuf, out int decodedLen))
            return false;
        return ReceivedFrame.TryParse(zzType, _decodeBuf, decodedLen, out frame);
    }

    // ── Receive helpers ───────────────────────────────────────────────────────

    /// <summary>
    /// Wait for a frame whose ZZ-frame type byte matches <paramref name="zzType"/>.
    /// Used during the port 50000 handshake where the ZZ type IS the message ID.
    /// </summary>
    public async ValueTask<ReceivedFrame?> WaitForZzTypeAsync(
        byte zzType, TimeSpan timeout, CancellationToken ct = default)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
        linked.CancelAfter(timeout);
        try
        {
            await foreach (var frame in _channel.Reader.ReadAllAsync(linked.Token))
            {
                if (frame.ZzType == zzType)
                    return frame;
                if (frame.ZzType == 0x18)
                    _log.LogTrace("RemotePath:{Port} waiting for 0x{Expected:x2}, discarding 0x18", _port, zzType);
                else
                    _log.LogDebug("RemotePath:{Port} waiting for ZZ=0x{Expected:x2}, discarding ZZ=0x{Got:x2}",
                        _port, zzType, frame.ZzType);
            }
        }
        catch (OperationCanceledException) { }
        return null;
    }

    /// <summary>
    /// Wait for a frame with a specific Header_RS MidName.
    /// Used for DLL-level command/response packets after handshake completes.
    /// </summary>
    public async ValueTask<ReceivedFrame?> WaitForMidAsync(
        MidName expected, TimeSpan timeout, CancellationToken ct = default)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
        linked.CancelAfter(timeout);
        try
        {
            await foreach (var frame in _channel.Reader.ReadAllAsync(linked.Token))
            {
                if (frame.Mid == expected)
                    return frame;
                _log.LogDebug("RemotePath:{Port} waiting for MID={Expected}, discarding ZZ=0x{ZZ:x2} MID={Got}",
                    _port, expected, frame.ZzType, frame.Mid);
            }
        }
        catch (OperationCanceledException) { }
        return null;
    }

    /// <summary>
    /// Wait for one of two MidNames.
    /// </summary>
    public async ValueTask<ReceivedFrame?> WaitForEitherMidAsync(
        MidName a, MidName b, TimeSpan timeout, CancellationToken ct = default)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
        linked.CancelAfter(timeout);
        try
        {
            await foreach (var frame in _channel.Reader.ReadAllAsync(linked.Token))
            {
                if (frame.Mid == a || frame.Mid == b)
                    return frame;
                _log.LogDebug("RemotePath:{Port} waiting for {A}/{B}, discarding ZZ=0x{ZZ:x2} MID={Got}",
                    _port, a, b, frame.ZzType, frame.Mid);
            }
        }
        catch (OperationCanceledException) { }
        return null;
    }
}
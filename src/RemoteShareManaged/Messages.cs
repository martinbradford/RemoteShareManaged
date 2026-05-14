namespace RemoteShareManaged.Protocol;

// ── Device indices ────────────────────────────────────────────────────────────

/// <summary>
/// Device channel indices used in all Send* calls.
/// Matches the device_index_n enum in the original Yaesu RemoteShare.dll.
/// </summary>
public enum DeviceIndex : int
{
    LoginSession  = 0,
    UsbCat        = 1,
    UsbAudio      = 2,
    AnalogAudio   = 3,
    LoopbackAudio = 4,
    Rs232cCat     = 5,
    DinSpiIn      = 6,   // spectrum scope
    DinUart       = 7,
    DinSpiOut     = 8,
}

// ── Message IDs ───────────────────────────────────────────────────────────────

/// <summary>
/// Message type identifiers returned by RecvFrameValidation (Header_RS.mid).
/// Values are the exact integers from the original MID_NAME enum.
/// </summary>
public enum MidName : ushort
{
    Null                = 0,
    LoginAns            = 1,
    LoginHealthAns      = 2,
    LoginDataAns        = 3,
    LogoutAns           = 4,
    UsbCatOpenAns       = 5,
    UsbCatCloseAns      = 6,
    UsbCatConnectAns    = 7,
    UsbCatHealthAns     = 8,
    UsbCatReadData      = 9,
    UsbAudioOpenAns     = 10,
    UsbAudioCloseAns    = 11,
    UsbAudioConnectAns  = 13,
    UsbAudioHealthAns   = 14,
    UsbAudioWaveData    = 15,
    DinSpiOpenAns       = 30,
    DinSpiCloseAns      = 31,
    DinSpiConnectAns    = 32,
    DinSpiScopeData     = 34,
}

// ── Port constants ────────────────────────────────────────────────────────────

public static class ScuPorts
{
    public const int Control = 50000;
    public const int Cat     = 50001;
    public const int Audio   = 50002;
    public const int Scope   = 50003;
}

// ── Buffer size constants (matching original DLL) ─────────────────────────────

public static class BufferSizes
{
    public const int Remote  = 16640;
    public const int PcmMax  = 1280;
    public const int Scope   = 4096;
    public const int Cat     = 16384;
    public const int Command = 255;
}

// ── Response frame layout ─────────────────────────────────────────────────────

/// <summary>
/// Parsed representation of a received ZZ-frame after decoding.
///
/// ALL port 50000 packets use the ZZ-frame type byte as the message
/// discriminator — the decoded payload is NOT a Header_RS for handshake packets.
///
/// Only after the handshake completes do DLL-level packets appear, which
/// contain a Header_RS struct (dev_id, mid, len) in the decoded payload.
///
/// Two-layer structure:
///   Handshake packets (ZzType 0x18, 0x1a, 0x0e etc.):
///     ZzType is the message ID. Payload is opaque per-packet data.
///   DLL-level packets (ZzType TBD from post-handshake capture):
///     ZzType identifies the packet class.
///     Decoded payload starts with Header_RS { dev_id, mid, len }.
///
/// Memory layout of Header_RS (Pack=1, for DLL-level packets only):
///   payload[0-1]  dev_id  ushort
///   payload[2-3]  mid     ushort  ← MidName
///   payload[4-5]  len     ushort
///   payload[6+]   message-specific data
/// </summary>
public readonly record struct ReceivedFrame(
    byte    ZzType,   // ZZ-frame type byte — the primary discriminator
    MidName Mid,      // Header_RS.mid (only valid for DLL-level packets)
    ushort  DevId,
    ushort  Length,
    byte[]  Payload   // full decoded payload (everything after ZZ 9-byte header)
)
{
    /// <summary>
    /// Parse a raw decoded buffer into a ReceivedFrame.
    /// buf is the ZZ-decoded payload (data[9..] XOR key).
    /// zzType is the ZZ-frame type byte (data[2]).
    /// </summary>
    public static bool TryParse(byte zzType, byte[] buf, int count, out ReceivedFrame frame)
    {
        frame = default;
        if (count < 1) return false;

        byte[]  payload = new byte[count];
        Buffer.BlockCopy(buf, 0, payload, 0, count);

        // Try to extract Header_RS fields — only meaningful for DLL-level packets
        MidName mid    = MidName.Null;
        ushort  devId  = 0;
        ushort  length = 0;
        if (count >= 6)
        {
            devId  = BitConverter.ToUInt16(buf, 0);
            mid    = (MidName)BitConverter.ToUInt16(buf, 2);
            length = BitConverter.ToUInt16(buf, 4);
        }

        frame = new ReceivedFrame(zzType, mid, devId, length, payload);
        return true;
    }

    // ── Typed payload accessors ───────────────────────────────────────────────

    /// <summary>
    /// MID_LoginAns payload (DLL-level, payload[6+]):
    ///   [0-3]  session.sid  uint
    ///   [4-7]  result       uint  (0 = success)
    ///   [8-13] macAddr      byte[6]
    /// </summary>
    public (uint Sid, uint Result, byte[] Mac) ParseLoginAns()
    {
        var p = Payload.AsSpan(6); // skip Header_RS
        uint   sid    = BitConverter.ToUInt32(p[0..]);
        uint   result = BitConverter.ToUInt32(p[4..]);
        byte[] mac    = p.Length >= 14 ? p[8..14].ToArray() : [];
        return (sid, result, mac);
    }

    /// <summary>Open/Close/Connect answer result uint at payload[6].</summary>
    public uint ParseOpenAnsResult()
        => Payload.Length >= 10 ? BitConverter.ToUInt32(Payload, 6) : uint.MaxValue;

    /// <summary>
    /// MID_Login_DataAns: null-terminated ASCII text at payload[14].
    /// (Header_RS 6 bytes + result uint 4 bytes + data_type uint 4 bytes = 14)
    /// </summary>
    public string ParseLoginDataText()
    {
        int start = Math.Min(14, Payload.Length);
        int end   = start;
        while (end < Payload.Length && Payload[end] != 0) end++;
        return System.Text.Encoding.ASCII.GetString(Payload, start, end - start);
    }
}

// ── Typed CAT message ─────────────────────────────────────────────────────────

/// <summary>
/// A decoded CAT message received from the radio via port 50001.
/// The Raw string is the complete Yaesu ASCII CAT response e.g. "FA014200000;"
/// </summary>
public sealed class CatMessage
{
    public string         Raw       { get; }
    public DateTimeOffset Timestamp { get; }

    public CatMessage(string raw)
    {
        Raw       = raw;
        Timestamp = DateTimeOffset.UtcNow;
    }

    /// <summary>
    /// Attempt to extract a VFO-A/B frequency from FA/FB responses.
    /// Returns null if this message is not a frequency response.
    /// </summary>
    public long? TryParseFrequency()
    {
        // FA/FB: "FA014200000;" — 2-char command + 9-digit Hz
        if (Raw.Length >= 11 &&
            (Raw.StartsWith("FA") || Raw.StartsWith("FB")) &&
            long.TryParse(Raw.AsSpan(2, 9), out long faHz))
            return faHz;

        // IF: "IF{3-char-flags}{9-digit-Hz}...;" — freq starts at position 5
        if (Raw.Length >= 14 && Raw.StartsWith("IF") &&
            long.TryParse(Raw.AsSpan(5, 9), out long ifHz))
            return ifHz;

        return null;
    }

    public override string ToString() => Raw;
}

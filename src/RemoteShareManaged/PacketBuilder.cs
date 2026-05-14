using System.Text;

namespace RemoteShareManaged.Protocol;

/// <summary>
/// Builds outgoing command payloads for all Send* operations.
/// Returns raw byte arrays ready to be wrapped by ZzFrameCodec or RsFrameCodec.
///
/// All methods are pure static functions — no state, easily testable.
/// Payload layouts are derived from the RemoteShare.dll decompilation and
/// confirmed against live hardware captures.
/// </summary>
public static class PacketBuilder
{
    // ── Login payload (SendLogin → ZZ-frame on port 50000) ───────────────────

    /// <summary>
    /// Builds the inner payload for SendLogin.
    /// The DLL wraps this in a ZZ-frame and sends on port 50000.
    ///
    /// Payload layout (0x44 = 68 bytes):
    ///   [0]      auth type = 0x01
    ///   [1..32]  username, ASCII, zero-padded to 32 bytes
    ///   [33..64] password, ASCII, zero-padded to 32 bytes
    ///   [65..67] 0x00 padding
    /// </summary>
    public static byte[] LoginPayload(string username, string password)
    {
        const int payloadLen = 0x44;
        byte[] payload = new byte[payloadLen];
        payload[0] = 0x01; // auth type

        byte[] userBytes = Encoding.ASCII.GetBytes(username);
        byte[] passBytes = Encoding.ASCII.GetBytes(password);
        Buffer.BlockCopy(userBytes, 0, payload, 1, Math.Min(userBytes.Length, 32));
        Buffer.BlockCopy(passBytes, 0, payload, 33, Math.Min(passBytes.Length, 32));
        return payload;
    }

    // ── catcmd_table (SendLanUnitCmd + SendLanUnitPage on port 50000) ─────────

    /// <summary>
    /// Returns the catcmd_table ASCII text content.
    /// Sent via SendLanUnitPage after a "putfile catcmd_table" command.
    /// Tells the SCU how to frame and identify binary CAT packets from the radio.
    ///
    /// Format per line: total_byte_length,prefix_length,prefix
    /// FTdx101MP and FTdx101D use the same table (not FT710).
    /// </summary>
    public static byte[] CatCmdTable(bool isFt710 = false)
    {
        var sb = new StringBuilder();
        sb.AppendLine("16,3,SPM");
        sb.AppendLine("9,3,SPW");
        sb.AppendLine("9,3,SPR");
        sb.AppendLine("9,3,SPw");
        sb.AppendLine("9,3,SPr");
        sb.AppendLine("427,3,SPA");
        sb.AppendLine("7,3,SPN");
        sb.AppendLine("229,2,E0");
        sb.AppendLine(isFt710 ? "10674,2,E8" : "10573,2,E8");
        sb.AppendLine("21,8,EX040101");
        return Encoding.ASCII.GetBytes(sb.ToString());
    }

    // ── CAT write payload (SendCatWrite on port 50001) ────────────────────────

    /// <summary>
    /// Builds the inner payload for SendCatWrite.
    /// catData should be the raw Yaesu ASCII CAT bytes, e.g. "FA014200000;"
    /// </summary>
    public static byte[] CatWritePayload(uint sid, int dev,
                                          ReadOnlySpan<byte> catData,
                                          ushort packetId, ushort delayMs)
    {
        // Header_RS (6) + CatWrite header (8) + data
        byte[] payload = new byte[14 + catData.Length];
        int o = 0;

        // dev_id (ushort), mid (ushort = 0x0105), len (ushort)
        WriteUInt16(payload, ref o, (ushort)dev);
        WriteUInt16(payload, ref o, 0x0105);
        WriteUInt16(payload, ref o, (ushort)(catData.Length + 8));

        // CatWrite fields: sid, packetId, delayMs, dataLen
        WriteUInt32(payload, ref o, sid);
        WriteUInt16(payload, ref o, packetId);
        WriteUInt16(payload, ref o, delayMs);

        catData.CopyTo(payload.AsSpan(o));
        return payload;
    }

    // ── Open / Connect / Health payloads (on port 50000) ─────────────────────

    /// <summary>SendCatOpen payload.</summary>
    public static byte[] CatOpenPayload(uint sid, int recvPort,
                                         uint baudRate, int dev)
    {
        byte[] p = new byte[0x12];  // 18 bytes: 4×U16 + U32 + 3×U16
        int o = 0;
        WriteUInt16(p, ref o, (ushort)dev);
        WriteUInt16(p, ref o, 0x010A);          // type
        WriteUInt16(p, ref o, 0x000A);          // subtype
        WriteUInt16(p, ref o, 0x0000);          // padding
        WriteUInt32(p, ref o, sid);
        WriteUInt16(p, ref o, (ushort)recvPort);
        WriteUInt16(p, ref o, (ushort)(baudRate & 0xFFFF));
        WriteUInt16(p, ref o, (ushort)(baudRate >> 16));
        return p;
    }

    /// <summary>SendDevPortOpen payload.</summary>
    public static byte[] DevPortOpenPayload(uint sid, int recvPort, int dev)
    {
        byte[] p = new byte[0x0C];
        int o = 0;
        WriteUInt16(p, ref o, (ushort)dev);
        WriteUInt16(p, ref o, 0x0106);
        WriteUInt16(p, ref o, 0x0006);
        WriteUInt32(p, ref o, sid);
        WriteUInt16(p, ref o, (ushort)recvPort);
        return p;
    }

    /// <summary>SendDevPortConnect payload.</summary>
    public static byte[] DevPortConnectPayload(uint sid, int dev)
    {
        byte[] p = new byte[0x0A];
        int o = 0;
        WriteUInt16(p, ref o, (ushort)dev);
        WriteUInt16(p, ref o, 0x0104);
        WriteUInt16(p, ref o, 0x0004);
        WriteUInt32(p, ref o, sid);
        return p;
    }

    /// <summary>SendHchk payload (health check / keepalive).</summary>
    public static byte[] HchkPayload(uint sid, int dev)
    {
        byte[] p = new byte[0x0A];
        int o = 0;
        WriteUInt16(p, ref o, (ushort)dev);
        WriteUInt16(p, ref o, 0x0107);
        WriteUInt16(p, ref o, 0x0004);
        WriteUInt32(p, ref o, sid);
        return p;
    }

    /// <summary>SendLogout payload.</summary>
    public static byte[] LogoutPayload(uint sid, uint sleepMs)
    {
        byte[] p = new byte[0x0F];
        int o = 0;
        WriteUInt16(p, ref o, 0x0000);
        WriteUInt16(p, ref o, 0x0102);
        WriteUInt16(p, ref o, 0x0009);
        WriteUInt32(p, ref o, sid);
        WriteUInt32(p, ref o, sleepMs);
        p[o] = 0x00;
        return p;
    }

    /// <summary>SendCatRate payload.</summary>
    public static byte[] CatRatePayload(uint sid, int dev, uint bps)
    {
        byte[] p = new byte[0x0E];
        int o = 0;
        WriteUInt16(p, ref o, (ushort)dev);
        WriteUInt16(p, ref o, 0x0108);
        WriteUInt16(p, ref o, 0x0008);
        WriteUInt32(p, ref o, sid);
        WriteUInt32(p, ref o, bps);
        return p;
    }

    // ── Standard Yaesu CAT command builders ──────────────────────────────────

    /// <summary>FA/FB frequency set: "FA014200000;"</summary>
    public static byte[] FrequencyCommand(long freqHz, bool vfoB = false)
        => Encoding.ASCII.GetBytes($"{(vfoB ? "FB" : "FA")}{freqHz:D9};");

    /// <summary>FA/FB frequency read request: "FA;" or "FB;"</summary>
    public static byte[] FrequencyReadCommand(bool vfoB = false)
        => Encoding.ASCII.GetBytes(vfoB ? "FB;" : "FA;");

    /// <summary>AI (auto-information) command. n=0 → disable, n omitted → read.</summary>
    public static byte[] AutoInformation(int? n = null)
        => Encoding.ASCII.GetBytes(n.HasValue ? $"AI{n.Value};" : "AI;");

    /// <summary>PS (power status): "PS1;" = power on.</summary>
    public static byte[] PowerStatus(int state = 1)
        => Encoding.ASCII.GetBytes($"PS{state};");

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static void WriteUInt16(byte[] buf, ref int offset, ushort value)
    {
        buf[offset++] = (byte)(value & 0xFF);
        buf[offset++] = (byte)(value >> 8);
    }

    private static void WriteUInt32(byte[] buf, ref int offset, uint value)
    {
        buf[offset++] = (byte)(value & 0xFF);
        buf[offset++] = (byte)((value >> 8) & 0xFF);
        buf[offset++] = (byte)((value >> 16) & 0xFF);
        buf[offset++] = (byte)((value >> 24) & 0xFF);
    }
}
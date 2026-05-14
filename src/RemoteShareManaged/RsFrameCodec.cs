namespace RemoteShareManaged.Codec;

/// <summary>
/// Encodes and decodes RS-frames used on ports 50001, 50002, 50003.
///
/// RS-frame wire format:
///   [0-1]  0x5A 0x5A       magic
///   [2-3]  payload_len+4   total body length (little-endian ushort)
///   [4-5]  0x00 0x01       version/flags
///   [6-7]  key_word        16-bit encryption key (derived from frame counter)
///   [8+]   encoded payload
///
/// Encryption algorithm (exact — from RemoteShare.dll FUN_10003c30/FUN_10003cf0):
///   counter = ++_frameCounter
///   k = counter * 0x2000 ^ counter
///   k ^= k >> 17
///   k = (k &lt;&lt; 15) ^ k
///   encoded[i] = (~i + 1) ^ source[i] ^ (k &amp; 0xFF) ^ ((k >> 8) &amp; 0xFF)
///
/// All encode/decode methods are pure functions.
/// The frame counter is a field that must be maintained per-connection per-direction.
/// </summary>
public sealed class RsFrameCodec
{
    private uint _frameCounter;

    /// <summary>Reset the frame counter — call on new connection.</summary>
    public void Reset() => _frameCounter = 0;

    // ── Encode ────────────────────────────────────────────────────────────────

    /// <summary>
    /// Encode a payload into an RS-frame. Increments the internal frame counter.
    /// </summary>
    public byte[] Encode(ReadOnlySpan<byte> payload)
    {
        _frameCounter++;
        uint k = _frameCounter * 0x2000u ^ _frameCounter;
        k ^= k >> 17;
        k  = (k << 15) ^ k;

        byte kLo = (byte)(k & 0xFF);
        byte kHi = (byte)((k >> 8) & 0xFF);

        // Header: 8 bytes. Total frame = 8 + payload.Length
        byte[] frame = new byte[8 + payload.Length];
        frame[0] = 0x5A;
        frame[1] = 0x5A;

        ushort bodyLen = (ushort)(payload.Length + 4);
        frame[2] = (byte)(bodyLen & 0xFF);
        frame[3] = (byte)(bodyLen >> 8);

        frame[4] = 0x00;
        frame[5] = 0x01;
        frame[6] = kLo;
        frame[7] = kHi;

        for (int i = 0; i < payload.Length; i++)
            frame[8 + i] = (byte)((byte)(~i + 1) ^ payload[i] ^ kLo ^ kHi);

        return frame;
    }

    // ── Decode (stateless — key is in the frame header) ───────────────────────

    /// <summary>
    /// Decode an RS-frame. Does not use or modify the frame counter —
    /// the key is embedded in the frame header at bytes [6-7].
    /// Returns null if the frame is malformed.
    /// </summary>
    public static byte[]? Decode(ReadOnlySpan<byte> frame)
    {
        if (frame.Length < 8) return null;
        if (frame[0] != 0x5A || frame[1] != 0x5A) return null;
        if (frame[4] != 0x00 || frame[5] != 0x01) return null;

        byte kLo = frame[6];
        byte kHi = frame[7];

        int payloadLen = frame.Length - 8;
        byte[] payload = new byte[payloadLen];

        for (int i = 0; i < payloadLen; i++)
            payload[i] = (byte)((byte)(~i + 1) ^ frame[8 + i] ^ kLo ^ kHi);

        return payload;
    }

    /// <summary>
    /// Decode an RS-frame and write result into a caller-supplied span.
    /// Returns the number of decoded bytes, or -1 on error.
    /// Zero-allocation path for hot receive loops.
    /// </summary>
    public static int Decode(ReadOnlySpan<byte> frame, Span<byte> output)
    {
        if (frame.Length < 8) return -1;
        if (frame[0] != 0x5A || frame[1] != 0x5A) return -1;
        if (frame[4] != 0x00 || frame[5] != 0x01) return -1;

        byte kLo = frame[6];
        byte kHi = frame[7];

        int payloadLen = frame.Length - 8;
        if (output.Length < payloadLen) return -1;

        for (int i = 0; i < payloadLen; i++)
            output[i] = (byte)((byte)(~i + 1) ^ frame[8 + i] ^ kLo ^ kHi);

        return payloadLen;
    }
}

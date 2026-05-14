using System.Buffers;

namespace RemoteShareManaged.Codec;

/// <summary>
/// Encodes and decodes ZZ-frames used on all four SCU-LAN10 UDP ports.
///
/// ZZ-frame wire format:
///   [0-1]  0x5A 0x5A   magic
///   [2]    type        packet type byte
///   [3]    0x00
///   [4]    0x00
///   [5]    0x01
///   [6]    nonce_a     = sequence counter (increments for every outgoing packet)
///   [7]    nonce_b     = (0xe0 - seq * 0x60) &amp; 0xFF  (deterministic from counter)
///   [8]    nonce_a XOR nonce_b  (check byte)
///   [9+]   payload     each byte XOR'd with key (key = raw[12])
///
/// CRITICAL: nonce_a is a STRICT SEQUENTIAL COUNTER starting at 1.
/// It is NOT random. Every outgoing packet — keepalive, HELLO, KEY EXCHANGE,
/// everything — increments the same counter.
///
/// All encode methods are pure static functions.
/// Callers are responsible for maintaining and passing the sequence counter.
/// </summary>
public static class ZzFrameCodec
{
    private const byte Magic0 = 0x5A;
    private const byte Magic1 = 0x5A;

    /// <summary>
    /// Compute nonce_b from the sequence counter.
    /// Formula confirmed from Wireshark captures against all 8 values:
    ///   (-seq * 0x60) &amp; 0xFF
    /// seq=1→0xa0, seq=2→0x40, seq=3→0xe0, seq=4→0x80,
    /// seq=5→0x20, seq=6→0xc0, seq=7→0x60, seq=8→0x00 ...
    /// </summary>
    public static byte NonceB(byte seq) => (byte)(-seq * 0x60);

    // ── Encode ────────────────────────────────────────────────────────────────

    /// <summary>
    /// Encode a payload into a ZZ-frame ready to transmit.
    /// nonceA and nonceB should be random bytes; key is derived from them.
    /// </summary>
    public static byte[] Encode(byte type, ReadOnlySpan<byte> payload,
                                 byte nonceA, byte nonceB, byte key)
    {
        byte[] frame = new byte[9 + payload.Length];
        frame[0] = Magic0;
        frame[1] = Magic1;
        frame[2] = type;
        frame[3] = 0x00;
        frame[4] = 0x00;
        frame[5] = 0x01;
        frame[6] = nonceA;
        frame[7] = nonceB;
        frame[8] = (byte)(nonceA ^ nonceB);

        for (int i = 0; i < payload.Length; i++)
            frame[9 + i] = (byte)(payload[i] ^ key);

        return frame;
    }

    /// <summary>
    /// Encode a complete pre-built ZZ-frame packet, updating the
    /// sequence counter bytes: [6]=seq, [7]=NonceB(seq), [8]=seq^NonceB(seq).
    /// Used for fixed packets (KEY EXCHANGE, AUTH BLOB, CONFIG, INIT).
    /// </summary>
    public static byte[] EncodeWithSeq(ReadOnlySpan<byte> fixedPacket, byte seq)
    {
        byte[] frame = fixedPacket.ToArray();
        byte nonceB = NonceB(seq);
        frame[6] = seq;
        frame[7] = nonceB;
        frame[8] = (byte)(seq ^ nonceB);
        return frame;
    }

    // ── Decode ────────────────────────────────────────────────────────────────

    /// <summary>
    /// Decode a received ZZ-frame. Returns false if the frame is malformed.
    /// On success, decoded payload bytes are written to <paramref name="decoded"/>
    /// which must be at least (data.Length - 9) bytes long.
    /// </summary>
    public static bool TryDecode(ReadOnlySpan<byte> data,
                                  out byte type,
                                  Span<byte> decoded,
                                  out int decodedLength)
    {
        type = 0;
        decodedLength = 0;

        if (data.Length < 9)
            return false;
        if (data[0] != Magic0 || data[1] != Magic1)
            return false;

        type = data[2];

        // Key is at position 12 in the full packet (offset 3 into payload)
        if (data.Length <= 12)
            return false;
        byte key = data[12];

        int payloadLen = data.Length - 9;
        if (decoded.Length < payloadLen)
            return false;

        for (int i = 0; i < payloadLen; i++)
            decoded[i] = (byte)(data[9 + i] ^ key);

        decodedLength = payloadLen;
        return true;
    }

    // ── Keepalive (type 0x0e) ─────────────────────────────────────────────────

    /// <summary>
    /// Build a type 0x0e keepalive packet (18 bytes).
    /// Pre-login  (authenticated=false): dec[1]=0x01, dec[5]=helloAckNonce^0x44
    /// Post-login (authenticated=true):  dec[1]=0x02, dec[5]=helloAckNonce^0x0a
    /// helloAckNonce = dec[5] from the HELLO-ACK packet. For pre-login keepalives
    /// before HELLO-ACK is received, pass helloAckNonce=0 (dec[5]=seq is fine).
    /// Confirmed from three independent Yaesu sessions.
    /// </summary>
    public static byte[] BuildKeepalive(bool authenticated, byte seq, byte helloAckNonce = 0)
    {
        byte nonceA = seq;
        byte nonceB = NonceB(seq);
        byte key = (byte)(0xf8 ^ nonceA ^ nonceB);
        byte dec1 = authenticated ? (byte)0x02 : (byte)0x01;
        // dec[5] = helloAckNonce ^ K
        byte K = authenticated ? (byte)0x0a : (byte)0x02;
        byte dec5 = (byte)(helloAckNonce ^ K);
        // check byte: pre-login = seq^NonceB, authenticated = seq^NonceB^0x01
        byte check = authenticated
            ? (byte)((nonceA ^ nonceB) ^ 0x01)
            : (byte)(nonceA ^ nonceB);
        return
        [
            0x5a, 0x5a, 0x0e, 0x00, 0x00, 0x01,
            nonceA, nonceB, check,
            (byte)(0x07 ^ key), (byte)(dec1 ^ key), (byte)(0x04 ^ key),
            key,
            (byte)(0x03 ^ key), (byte)(dec5 ^ key),
            (byte)(0x01 ^ key), key, (byte)(0x0f ^ key)
        ];
    }

    // ── HELLO (type 0x4e) ─────────────────────────────────────────────────────

    private static ReadOnlySpan<byte> UserKey
        => [0x40, 0x4f, 0x4e, 0x4d, 0x4c, 0x4b];

    private static ReadOnlySpan<byte> FixedSeq =>
    [
        0x4a,0x49,0x48,0x57,0x56,0x55,0x54,0x53,0x52,0x51,0x50,
        0x5f,0x5e,0x5d,0x5c,0x5b,0x5a,0x59,0x58,
        0x67,0x66,0x65,0x64,0x63,0x62,0x61,0x60
    ];

    private static byte SeqVal(int i) => i switch
    {
        < 8 => (byte)(0x6f - i),
        < 16 => (byte)(0x77 - (i - 8)),
        < 24 => (byte)(0x7f - (i - 16)),
        < 32 => (byte)(0x07 - (i - 24)),
        _ => 0x0f
    };

    /// <summary>
    /// Build a type 0x4e HELLO packet (82 bytes).
    /// Username must be exactly 6 ASCII characters.
    /// seq = the current outgoing sequence counter value (nonce_a).
    /// </summary>
    public static byte[] BuildHello(string username, string password, byte seq)
    {
        if (username.Length != 6)
            throw new ArgumentException("Username must be exactly 6 characters.", nameof(username));

        byte[] user = System.Text.Encoding.ASCII.GetBytes(username);
        byte[] pass = System.Text.Encoding.ASCII.GetBytes(password);
        byte nonceA = seq;
        byte nonceB = NonceB(seq);
        byte key = (byte)((nonceA ^ nonceB) ^ 0xb8);
        byte enc(byte v) => (byte)(v ^ key);

        byte[] pkt = new byte[82];
        pkt[0] = 0x5a;
        pkt[1] = 0x5a;
        pkt[2] = 0x4e;
        pkt[3] = 0x00;
        pkt[4] = 0x00;
        pkt[5] = 0x01;
        pkt[6] = nonceA;
        pkt[7] = nonceB;
        pkt[8] = enc(0xb8);
        pkt[9] = enc(0x47);
        pkt[10] = enc(0x47);
        pkt[11] = enc(0x44);
        pkt[12] = key;
        pkt[13] = enc(0x43);
        pkt[14] = enc(0x43);
        pkt[15] = enc(0x41);

        var userKey = UserKey;
        for (int i = 0; i < 6; i++)
            pkt[16 + i] = enc((byte)(user[i] ^ userKey[i]));

        var fixedSeq = FixedSeq;
        for (int i = 0; i < fixedSeq.Length; i++)
            pkt[22 + i] = enc(fixedSeq[i]);

        for (int i = 0; i < 33; i++)
        {
            byte v = i < pass.Length ? (byte)(pass[i] ^ SeqVal(i)) : SeqVal(i);
            pkt[49 + i] = enc(v);
        }
        return pkt;
    }

    // ── Fixed handshake packets ───────────────────────────────────────────────

    // These are sent via EncodeWithSeq — only bytes [6] and [8] change.

    /// <summary>
    /// Build a KEY EXCHANGE packet (type 0x12, 278 bytes) incorporating the
    /// HELLO-ACK nonce. Only ONE decoded byte depends on the nonce:
    ///
    ///   dec[5] = helloAckNonce ^ 0x06
    ///   raw[14] = (helloAckNonce ^ 0x06) ^ 0x93
    ///
    /// The constant 0x06 is fixed regardless of the actual HELLO seq counter.
    /// dec[43] = 0x20 and dec[45] = 0x26 are constant across all sessions.
    ///
    /// Confirmed against three independent Yaesu sessions.
    /// </summary>
    public static byte[] BuildKeyExchange(byte seq, byte helloAckNonce)
    {
        byte[] frame = KeyExchangeTemplate.ToArray();
        byte nonceB = NonceB(seq);
        frame[6] = seq;
        frame[7] = nonceB;
        frame[8] = (byte)(seq ^ nonceB);

        // Only raw[14] needs patching: dec[5] = nonce ^ 0x06
        // template[12] = 0x93 is the fixed ZZ key
        const byte zzKey = 0x93;
        const byte constant = 0x06;
        frame[14] = (byte)((helloAckNonce ^ constant) ^ zzKey);
        return frame;
    }

    public static ReadOnlySpan<byte> KeyExchangeTemplate =>
    [
        0x5a,0x5a,0x12,0x01,0x00,0x01,0xa5,0x20,0x85,0x98,0x9c,0x9b,0x93,0x9d,0xb3,0x9e,
        0x9f,0x90,0x91,0x92,0x93,0x94,0xe5,0xe3,0xe3,0xee,0xe0,0xe6,0xee,0xac,0xee,0xef,
        0xfb,0xe3,0xec,0xe6,0xdc,0xf0,0xe4,0xe4,0xeb,0xdd,0xb9,0xba,0xbb,0xbc,0xbd,0xbe,
        0xbf,0xb0,0xb1,0xb2,0xb3,0xb4,0xb5,0xb6,0xb7,0xa8,0xa9,0xaa,0xab,0xac,0xad,0xae,
        0xaf,0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,0xd8,0xd9,0xda,0xdb,0xdc,0xdd,0xde,
        0xdf,0xd0,0xd1,0xd2,0xd3,0xd4,0xd5,0xd6,0xd7,0xc8,0xc9,0xca,0xcb,0xcc,0xcd,0xce,
        0xcf,0xc0,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7,0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,
        0xff,0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xe8,0xe9,0xea,0xeb,0xec,0xed,0xee,
        0xef,0xe0,0xe1,0xe2,0xe3,0xe4,0xe5,0xe6,0xe7,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,
        0x1f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,
        0x0f,0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x38,0x39,0x3a,0x3b,0x3c,0x3d,0x3e,
        0x3f,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,
        0x2f,0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x58,0x59,0x5a,0x5b,0x5c,0x5d,0x5e,
        0x5f,0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57,0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,
        0x4f,0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x78,0x79,0x7a,0x7b,0x7c,0x7d,0x7e,
        0x7f,0x70,0x71,0x72,0x73,0x74,0x75,0x76,0x77,0x68,0x69,0x6a,0x6b,0x6c,0x6d,0x6e,
        0x6f,0x60,0x61,0x62,0x63,0x64,0x65,0x66,0x67,0x98,0x99,0x9a,0x9b,0x9c,0x9d,0x9e,
        0x9f,0x90,0x91,0x92,0x93,0x94,
    ];

    /// <summary>
    /// Build a port 50001 command packet (types 0x15, 0x16, 0x12) from a template.
    /// dec[5] = helloAckNonce ^ K  where K is hardcoded per packet type:
    ///   0x16 → K=0x02, 0x15 → K=0x05, 0x12 (port 50001) → K=0x06
    /// raw[14] = (helloAckNonce ^ K) ^ template[12]
    ///
    /// WARNING: Do NOT compute K from the template bytes — the templates were
    /// captured with nonce=0x46, so template[14]^template[12] = 0x46^K, not K.
    /// </summary>
    public static byte[] BuildCatCmd(ReadOnlySpan<byte> template, byte seq,
                                      byte helloAckNonce, byte K)
    {
        byte[] frame = template.ToArray();
        byte nonceB = NonceB(seq);
        frame[6] = seq;
        frame[7] = nonceB;
        frame[8] = (byte)(seq ^ nonceB);

        byte zzKey = frame[12];
        frame[14] = (byte)((helloAckNonce ^ K) ^ zzKey);
        return frame;
    }

    /// <summary>
    /// Build a type 0x19 CAT send packet.
    /// dec structure: 0c 08 0f 00 08 [nonce^0x01] 0a 0b 04 [cmdCounter] 06 07 00 [catBytes]
    /// catBytes are raw ASCII CAT command bytes, e.g. "FA;" — NOT XOR'd.
    /// </summary>
    public static byte[] BuildCatSend(byte seq, byte helloAckNonce,
                                       byte cmdCounter, ReadOnlySpan<byte> catBytes)
    {
        // Payload (decoded):
        // [0-12] fixed header, [5]=nonce^0x01, [9]=cmdCounter
        // [13..] catBytes
        const byte zzKeyBase = 0x61; // typical ZZ key for type 0x19
        byte nonceB = NonceB(seq);

        // Build decoded payload
        int payloadLen = 13 + catBytes.Length;
        Span<byte> dec = stackalloc byte[payloadLen];
        dec[0] = 0x0c;
        dec[1] = 0x08;
        dec[2] = 0x0f;
        dec[3] = 0x00;
        dec[4] = 0x08;
        dec[5] = (byte)(helloAckNonce ^ 0x01);
        dec[6] = 0x0a;
        dec[7] = 0x0b;
        dec[8] = 0x04;
        dec[9] = cmdCounter;
        dec[10] = 0x06;
        dec[11] = 0x07;
        dec[12] = 0x00;
        catBytes.CopyTo(dec[13..]);

        // Encode: choose ZZ key = dec[3] XOR ... actually the ZZ key is raw[12] = dec[3] ^ key
        // For type 0x19, from the capture: the ZZ key is at dec[3]=0x00 position in payload
        // which means raw[12] = dec[3] ^ key — but we need to pick key carefully.
        // From captured packets: raw[12] varies. The simplest approach: use key = dec[3] since
        // dec[3] ^ key = raw[12], and we want raw[12] to be some value. From the capture
        // raw[12] = d6 for one packet. Let's use the nonce itself as the ZZ key basis.
        // Actually: ZZ key = raw[12]. It's just the byte at position 12 in the raw packet.
        // We can freely choose it. From capture: raw[12] of 0x19 varies.
        // Most consistent: set ZZ key = zzKeyBase and encode accordingly.
        byte key = zzKeyBase;

        byte[] frame = new byte[9 + payloadLen];
        frame[0] = 0x5a;
        frame[1] = 0x5a;
        frame[2] = 0x19;
        frame[3] = 0x00;
        frame[4] = 0x00;
        frame[5] = 0x01;
        frame[6] = seq;
        frame[7] = nonceB;
        frame[8] = (byte)((seq ^ nonceB) ^ 0x01);  // extra 0x01 confirmed for type 0x19
        for (int i = 0; i < payloadLen; i++)
            frame[9 + i] = (byte)(dec[i] ^ key);
        // Fix key position: raw[12] must equal the actual ZZ key we used
        frame[12] = key;

        return frame;
    }

    // ── Port 50001 fixed packet templates ─────────────────────────────────────
    // Extracted from live Wireshark capture. dec[5] = helloAckNonce ^ K.
    // BuildCatCmd() patches raw[14] = (nonce ^ K) ^ template[12] automatically.

    /// <summary>Type 0x16 catcmd_table command (len=26, K=0x02)</summary>
    public static ReadOnlySpan<byte> Port50001Type16Template =>
    [
        0x5a,0x5a,0x16,0x00,0x00,0x01,0xa5,0x20,0x85,0x6e,0x6a,0x6d,0x61,0x6a,0x25,0x68,
        0x69,0x66,0x66,0x64,0x65,0x62,0x33,0x33,0x50,0x45,
    ];

    /// <summary>Type 0x15 catcmd_table page (len=25, K=0x05)</summary>
    public static ReadOnlySpan<byte> Port50001Type15Template =>
    [
        0x5a,0x5a,0x15,0x00,0x00,0x01,0xa5,0x20,0x85,0x2c,0x28,0x2f,0x24,0x28,0x67,0x2a,
        0x2b,0x24,0x26,0x26,0x27,0x20,0x60,0x6b,0x18,
    ];

    /// <summary>Type 0x12 session confirm on port 50001 (len=22, K=0x06)</summary>
    public static ReadOnlySpan<byte> Port50001Type12Template =>
    [
        0x5a,0x5a,0x12,0x00,0x00,0x01,0xa5,0x20,0x85,0xdd,0xd9,0xde,0xd6,0xd9,0x96,0xdb,
        0xda,0xd5,0xd6,0xd7,0xd6,0xd1,
    ];
    /// Only dec[5] depends on the nonce: dec[5] = helloAckNonce ^ 0x79
    /// raw[14] = (helloAckNonce ^ 0x79) ^ 0x83   (template ZZ key = 0x83)
    /// Confirmed across three independent sessions.
    /// </summary>
    public static byte[] BuildAuthBlob(byte seq, byte helloAckNonce)
    {
        byte[] frame = AuthBlobTemplate.ToArray();
        byte nonceB = NonceB(seq);
        frame[6] = seq;
        frame[7] = nonceB;
        frame[8] = (byte)(seq ^ nonceB);

        const byte zzKey = 0x83;
        const byte constant = 0x79;
        frame[14] = (byte)((helloAckNonce ^ constant) ^ zzKey);
        return frame;
    }

    /// <summary>
    /// Build a CONFIG packet (type 0x14) incorporating the nonce.
    /// dec[5] = helloAckNonce ^ 0x04.
    /// raw[8] check byte: for CONFIG, check = (seq ^ NonceB(seq)) ^ 0x01
    /// (extra 0x01 confirmed from three Yaesu sessions).
    /// </summary>
    public static byte[] BuildConfig(ReadOnlySpan<byte> template, byte seq, byte helloAckNonce)
    {
        byte[] frame = template.ToArray();
        byte nonceB = NonceB(seq);
        frame[6] = seq;
        frame[7] = nonceB;
        frame[8] = (byte)((seq ^ nonceB) ^ 0x01);  // extra 0x01 for CONFIG

        byte zzKey = frame[12];
        frame[14] = (byte)((helloAckNonce ^ 0x04) ^ zzKey);
        return frame;
    }

    /// <summary>
    /// Build an INIT packet (type 0x10) incorporating the nonce.
    /// dec[5] = helloAckNonce ^ 0x08.
    /// raw[8] check byte extra per INIT position:
    ///   INIT A (InitATemplate) = 0x02
    ///   INIT B (InitBTemplate) = 0x02
    ///   INIT C (InitCTemplate) = 0x06
    ///   INIT D (InitDTemplate) = 0x06
    /// Pass the appropriate checkExtra for each template.
    /// </summary>
    public static byte[] BuildInit(ReadOnlySpan<byte> template, byte seq,
                                    byte helloAckNonce, byte checkExtra)
    {
        byte[] frame = template.ToArray();
        byte nonceB = NonceB(seq);
        frame[6] = seq;
        frame[7] = nonceB;
        frame[8] = (byte)((seq ^ nonceB) ^ checkExtra);

        byte zzKey = frame[12];
        frame[14] = (byte)((helloAckNonce ^ 0x08) ^ zzKey);
        return frame;
    }

    public static ReadOnlySpan<byte> AuthBlobTemplate =>
    [
        0x5a,0x5a,0x81,0x00,0x00,0x01,0xa5,0x20,0x85,0xf7,0xf3,0xf4,0x83,0xf3,0xdc,0xf1,
        0xf0,0xff,0xff,0xfd,0xfc,0xfb,0xfa,0xf9,0x9f,0xe7,0xe6,0xe4,0xe4,0xe3,0xd3,0xd7,
        0xcc,0xdc,0xc2,0xbe,0xbc,0xa6,0xe7,0xe3,0xd1,0xfb,0xe5,0xf9,0x87,0x83,0x85,0xdc,
        0xda,0xe6,0xf2,0xee,0xf0,0x88,0x8a,0x8b,0xd5,0xcd,0xff,0xe9,0xf7,0xef,0x91,0x91,
        0xb7,0xc2,0xc4,0xf4,0xe0,0xf8,0xe6,0x9a,0x98,0xc5,0xbb,0xbf,0x80,0x81,0x85,0x9d,
        0x83,0x93,0xed,0xed,0xfd,0xb6,0xb0,0x8e,0x94,0x94,0x8a,0xf6,0xf4,0xed,0xaf,0xab,
        0x92,0x9d,0x97,0x81,0x9e,0x87,0xef,0x99,0xa5,0x9d,0xa7,0xa5,0xa1,0xa4,0xa1,0xbd,
        0xa2,0xb3,0xdb,0xa5,0x91,0x91,0xa8,0xa8,0xb4,0xbf,0xaa,0xc0,0xdc,0xb3,0xb6,0xb1,
        0xb1,0xbf,0xbf,0x80,0x86,
    ];

    // Confirmed from Wireshark capture (body bytes); nonce placeholder = 0xa5/0x20/0x85
    public static ReadOnlySpan<byte> ConfigATemplate =>
    [
        0x5a,0x5a,0x14,0x00,0x00,0x01,0xa5,0x20,0x85,0x56,0x54,0x55,
        0x5f,0x52,0x7d,0x50,0x51,0x5e,0x0e,0x9f,0x5d,0xcc,0x5b,0x58
    ];

    public static ReadOnlySpan<byte> ConfigBTemplate =>
    [
        0x5a,0x5a,0x14,0x00,0x00,0x01,0xa5,0x20,0x85,0xb5,0xb7,0xb6,
        0xbc,0xb1,0x9e,0xb3,0xb2,0xbd,0xed,0x7c,0xbe,0x2f,0xb8,0xbb
    ];

    public static ReadOnlySpan<byte> InitATemplate =>
    [
        0x5a,0x5a,0x10,0x00,0x00,0x01,0xa5,0x20,0x85,0x14,0x16,0x17,
        0x11,0x10,0x3f,0x12,0x13,0x1c,0x4f,0xdd
    ];

    // InitB/C/D not in Wireshark capture — bodies from original CLAUDE.md
    public static ReadOnlySpan<byte> InitBTemplate =>
    [
        0x5a,0x5a,0x10,0x00,0x00,0x01,0xa5,0x20,0x85,0x73,0x71,0x70,
        0x76,0x77,0x77,0x75,0x74,0x7b,0x28,0xba
    ];

    public static ReadOnlySpan<byte> InitCTemplate =>
    [
        0x5a,0x5a,0x10,0x00,0x00,0x01,0xa5,0x20,0x85,0xd2,0xd0,0xd1,
        0xd7,0xd6,0xd6,0xd4,0xd5,0xda,0x88,0x1b
    ];

    public static ReadOnlySpan<byte> InitDTemplate =>
    [
        0x5a,0x5a,0x10,0x00,0x00,0x01,0xa5,0x20,0x85,0x31,0x33,0x32,
        0x34,0x35,0x35,0x37,0x36,0x39,0x6b,0xf8
    ];
}
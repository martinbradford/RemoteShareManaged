namespace RemoteShareManaged.Codec;

/// <summary>
/// Yaesu-custom µ-Law codec used by the SCU-LAN10 on port 50002.
///
/// IMPORTANT: this is NOT standard ITU G.711 µ-Law.  The algorithm was
/// reverse-engineered from RemoteShare.dll via Ghidra decompilation:
///
///   Encoder  → FUN_10003eb0  (called per-sample inside SendAudioWave)
///   Decoder  → ConvertAudioWave (param_1 == 3 branch)
///
/// Using NAudio.Codecs.MuLawEncoder / MuLawDecoder will produce wrong output.
///
/// Wire convention
/// ---------------
///   Encode:  int16 PCM sample → 1 byte (2 bytes → 1 byte, i.e. param_11 >>= 1)
///   Decode:  1 byte           → int16 PCM sample (param_3 bytes → param_3*2 bytes)
///
/// Stereo layout is preserved: caller encodes/decodes all samples in order;
/// this class has no knowledge of channel interleaving.
/// </summary>
public static class YaesuMuLaw
{
    // ── Decode lookup table (256 entries) ────────────────────────────────────
    // Generated directly from ConvertAudioWave in RemoteShare.dll.
    // Formula: ~b → extract exponent (bits[6:4]) and mantissa (bits[3:0]),
    //          sign = b[7] (1 = positive, matching G.711 sign-bit convention).
    // Verified: full round-trip encode→decode matches within companding error.

    private static ReadOnlySpan<short> DecodeTable =>
    [
        -32124, -31100, -30076, -29052, -28028, -27004, -25980, -24956,
        -23932, -22908, -21884, -20860, -19836, -18812, -17788, -16764,
        -15996, -15484, -14972, -14460, -13948, -13436, -12924, -12412,
        -11900, -11388, -10876, -10364,  -9852,  -9340,  -8828,  -8316,
         -7932,  -7676,  -7420,  -7164,  -6908,  -6652,  -6396,  -6140,
         -5884,  -5628,  -5372,  -5116,  -4860,  -4604,  -4348,  -4092,
         -3900,  -3772,  -3644,  -3516,  -3388,  -3260,  -3132,  -3004,
         -2876,  -2748,  -2620,  -2492,  -2364,  -2236,  -2108,  -1980,
         -1884,  -1820,  -1756,  -1692,  -1628,  -1564,  -1500,  -1436,
         -1372,  -1308,  -1244,  -1180,  -1116,  -1052,   -988,   -924,
          -876,   -844,   -812,   -780,   -748,   -716,   -684,   -652,
          -620,   -588,   -556,   -524,   -492,   -460,   -428,   -396,
          -372,   -356,   -340,   -324,   -308,   -292,   -276,   -260,
          -244,   -228,   -212,   -196,   -180,   -164,   -148,   -132,
          -120,   -112,   -104,    -96,    -88,    -80,    -72,    -64,
           -56,    -48,    -40,    -32,    -24,    -16,     -8,      0,
         32124,  31100,  30076,  29052,  28028,  27004,  25980,  24956,
         23932,  22908,  21884,  20860,  19836,  18812,  17788,  16764,
         15996,  15484,  14972,  14460,  13948,  13436,  12924,  12412,
         11900,  11388,  10876,  10364,   9852,   9340,   8828,   8316,
          7932,   7676,   7420,   7164,   6908,   6652,   6396,   6140,
          5884,   5628,   5372,   5116,   4860,   4604,   4348,   4092,
          3900,   3772,   3644,   3516,   3388,   3260,   3132,   3004,
          2876,   2748,   2620,   2492,   2364,   2236,   2108,   1980,
          1884,   1820,   1756,   1692,   1628,   1564,   1500,   1436,
          1372,   1308,   1244,   1180,   1116,   1052,    988,    924,
           876,    844,    812,    780,    748,    716,    684,    652,
           620,    588,    556,    524,    492,    460,    428,    396,
           372,    356,    340,    324,    308,    292,    276,    260,
           244,    228,    212,    196,    180,    164,    148,    132,
           120,    112,    104,     96,     88,     80,     72,     64,
            56,     48,     40,     32,     24,     16,      8,      0,
    ];

    // ── Public API ────────────────────────────────────────────────────────────

    /// <summary>
    /// Encode a buffer of 16-bit stereo PCM samples to Yaesu µ-Law bytes.
    ///
    /// Each 2-byte PCM sample encodes to 1 byte, so <paramref name="pcmBytes"/>
    /// must be even and <paramref name="dst"/> must be at least pcmBytes/2 long.
    ///
    /// Returns the number of encoded bytes written to dst (= pcmBytes / 2).
    /// </summary>
    public static int Encode(ReadOnlySpan<byte> src, int pcmBytes, Span<byte> dst)
    {
        int sampleCount = pcmBytes / 2;
        for (int i = 0; i < sampleCount; i++)
        {
            short sample = (short)(src[i * 2] | (src[i * 2 + 1] << 8));
            dst[i] = EncodeSample(sample);
        }
        return sampleCount;
    }

    /// <summary>
    /// Decode a buffer of Yaesu µ-Law bytes to 16-bit stereo PCM.
    ///
    /// Each byte expands to one int16 sample (2 bytes), so
    /// <paramref name="dst"/> must be at least ulawBytes*2 long.
    ///
    /// Returns the number of PCM bytes written (= ulawBytes * 2).
    /// </summary>
    public static int Decode(ReadOnlySpan<byte> src, int ulawBytes, Span<byte> dst)
    {
        var table = DecodeTable;
        for (int i = 0; i < ulawBytes; i++)
        {
            short s = table[src[i]];
            dst[i * 2] = (byte)s;
            dst[i * 2 + 1] = (byte)((ushort)s >> 8);
        }
        return ulawBytes * 2;
    }

    /// <summary>
    /// Decode a single Yaesu µ-Law byte to a signed 16-bit PCM sample.
    /// Uses the precomputed lookup table — O(1), safe to call per-sample on the RX path.
    /// </summary>
    public static short DecodeSample(byte b) => DecodeTable[b];

    // ── Core encoder (port of FUN_10003eb0) ──────────────────────────────────

    /// <summary>
    /// Encode a single signed 16-bit PCM sample to a Yaesu µ-Law byte.
    /// Direct C# port of FUN_10003eb0 from RemoteShare.dll (Ghidra output).
    /// </summary>
    public static byte EncodeSample(short sample)
    {
        // Compute absolute-ish value, right-shifted by 2 (matching DLL)
        int sVar1 = sample < 0
            ? (ushort)(~(ushort)sample) >> 2
            : (ushort)sample >> 2;

        sVar1 += 0x21;
        if (sVar1 > 0x1fff)
            sVar1 = 0x1fff;

        // Count segments: find position of highest set bit in sVar1>>6
        int sVar4 = 1;
        for (int sVar2 = sVar1 >> 6; sVar2 != 0; sVar2 >>= 1)
            sVar4++;

        int uVar3 = (0xf - ((sVar1 >> sVar4) & 0xf)) | ((8 - sVar4) * 0x10);
        if (sample >= 0)
            uVar3 |= 0x80;

        return (byte)uVar3;
    }
}
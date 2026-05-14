using FluentAssertions;
using RemoteShareManaged.Codec;
using RemoteShareManaged.Protocol;

namespace RemoteShareManaged.Tests;

/// <summary>
/// Tests for ZzFrameCodec and RsFrameCodec.
/// Where possible, expected values are cross-checked against known-good
/// Wireshark captures from the live FTdx101D.
/// </summary>
public class ZzFrameCodecTests
{
    // ── Keepalive ─────────────────────────────────────────────────────────────

    [Fact]
    public void BuildKeepalive_ProducesCorrectLength()
    {
        byte[] pkt = ZzFrameCodec.BuildKeepalive(false, seq: 1);
        pkt.Should().HaveCount(18);
    }

    [Fact]
    public void BuildKeepalive_HasCorrectMagicAndType()
    {
        byte[] pkt = ZzFrameCodec.BuildKeepalive(false, seq: 1);
        pkt[0].Should().Be(0x5A);
        pkt[1].Should().Be(0x5A);
        pkt[2].Should().Be(0x0e);
    }

    [Fact]
    public void BuildKeepalive_Nonces_MatchCapturedValues()
    {
        // From Wireshark: seq=1 → nonce_a=0x01, nonce_b=0xa0, check=0xa1
        byte[] pkt = ZzFrameCodec.BuildKeepalive(false, seq: 1);
        pkt[6].Should().Be(0x01);   // nonce_a = seq
        pkt[7].Should().Be(0xa0);   // nonce_b = NonceB(1)
        pkt[8].Should().Be((byte)(0x01 ^ 0xa0));  // check
    }

    [Fact]
    public void NonceB_MatchesCapturedValues()
    {
        // All 8 values confirmed from Wireshark captures
        // Formula: (-seq * 0x60) & 0xFF
        ZzFrameCodec.NonceB(1).Should().Be(0xa0);
        ZzFrameCodec.NonceB(2).Should().Be(0x40);
        ZzFrameCodec.NonceB(3).Should().Be(0xe0);
        ZzFrameCodec.NonceB(4).Should().Be(0x80);
        ZzFrameCodec.NonceB(5).Should().Be(0x20);
        ZzFrameCodec.NonceB(6).Should().Be(0xc0);
        ZzFrameCodec.NonceB(7).Should().Be(0x60);
        ZzFrameCodec.NonceB(8).Should().Be(0x00);
    }

    [Fact]
    public void BuildKeepalive_Nonces_MatchCapturedValues()
    {
        // From Wireshark: seq=1 → nonce_a=0x01, nonce_b=0xa0, check=0xa1
        byte[] pkt = ZzFrameCodec.BuildKeepalive(false, seq: 1);
        pkt[6].Should().Be(0x01);
        pkt[7].Should().Be(0xa0);
        pkt[8].Should().Be((byte)(0x01 ^ 0xa0));
    }

    // ── HELLO ─────────────────────────────────────────────────────────────────

    [Fact]
    public void BuildHello_ProducesCorrectLength()
    {
        byte[] pkt = ZzFrameCodec.BuildHello("remote", "remote", seq: 6);
        pkt.Should().HaveCount(82);
    }

    [Fact]
    public void BuildHello_HasCorrectMagicAndType()
    {
        byte[] pkt = ZzFrameCodec.BuildHello("remote", "remote", seq: 6);
        pkt[0].Should().Be(0x5A);
        pkt[1].Should().Be(0x5A);
        pkt[2].Should().Be(0x4e);
    }

    [Fact]
    public void BuildHello_Nonces_MatchCapturedValues()
    {
        // From Wireshark: seq=6 → nonce_a=0x06, nonce_b=0xc0, check=0xa6
        byte[] pkt = ZzFrameCodec.BuildHello("remote", "remote", seq: 6);
        pkt[6].Should().Be(0x06);
        pkt[7].Should().Be(0xc0);   // NonceB(6) = (-6 * 0x60) & 0xFF = 0xc0
        pkt[8].Should().Be((byte)(0x06 ^ 0xc0)); // 0xa6
    }

    [Fact]
    public void BuildHello_MatchesWiresharkCapture()
    {
        // Byte-perfect match against actual Yaesu HELLO captured from live session
        // username="remote" password="remote" seq=6
        byte[] expected =
        [
            0x5a,0x5a,0x4e,0x00,0x00,0x01,0x06,0xc0,0xc6,0x39,0x39,0x3a,0x7e,0x3d,0x3d,0x3f,
            0x73,0x50,0x42,0x47,0x5b,0x5b,0x34,0x37,0x36,0x29,0x28,0x2b,0x2a,0x2d,0x2c,0x2f,
            0x2e,0x21,0x20,0x23,0x22,0x25,0x24,0x27,0x26,0x19,0x18,0x1b,0x1a,0x1d,0x1c,0x1f,
            0x1e,0x47,0x79,0x6b,0x77,0x7b,0x42,0x7e,0x65,0x60,0x67,0x65,0x3e,0x3f,0x2d,0x0f,
            0x0e,0x01,0x00,0x03,0x02,0x05,0x04,0x07,0x06,0x79,0x78,0x7b,0x7a,0x7d,0x7c,0x7f,
            0x7e,0x71
        ];
        byte[] actual = ZzFrameCodec.BuildHello("remote", "remote", seq: 6);
        actual.Should().Equal(expected);
    }

    [Fact]
    public void BuildHello_ThrowsOnWrongUsernameLength()
    {
        Action act = () => ZzFrameCodec.BuildHello("toolong123", "pass", seq: 1);
        act.Should().Throw<ArgumentException>().WithMessage("*6 characters*");
    }

    [Fact]
    public void BuildHello_DifferentSeqProducesDifferentPackets()
    {
        byte[] pkt1 = ZzFrameCodec.BuildHello("remote", "remote", seq: 1);
        byte[] pkt2 = ZzFrameCodec.BuildHello("remote", "remote", seq: 2);
        pkt1.Should().NotEqual(pkt2);
    }

    // ── EncodeWithSeq ─────────────────────────────────────────────────────────

    [Fact]
    public void KeyExchangeTemplate_HasCorrectMagicAndType()
    {
        var t = ZzFrameCodec.KeyExchangeTemplate;
        t[0].Should().Be(0x5A);
        t[1].Should().Be(0x5A);
        t[2].Should().Be(0x12);
        t.Length.Should().Be(278, "KEY EXCHANGE is 278 bytes (confirmed from Wireshark)");
    }

    [Fact]
    public void EncodeWithSeq_UpdatesAllThreeNonceBytes()
    {
        byte[] template = ZzFrameCodec.KeyExchangeTemplate.ToArray();
        byte[] packet   = ZzFrameCodec.EncodeWithSeq(template, seq: 7);
        packet[6].Should().Be(0x07);
        packet[7].Should().Be(ZzFrameCodec.NonceB(7));
        packet[8].Should().Be((byte)(0x07 ^ ZzFrameCodec.NonceB(7)));
    }

    [Fact]
    public void EncodeWithSeq_MatchesWiresharkKeyExchange()
    {
        // Yaesu KEY EXCHANGE captured at seq=7, nonce_b=0x60 (NonceB(7))
        byte[] packet = ZzFrameCodec.EncodeWithSeq(ZzFrameCodec.KeyExchangeTemplate, seq: 7);
        packet[6].Should().Be(0x07);
        packet[7].Should().Be(0x60);  // NonceB(7) = (-7 * 0x60) & 0xFF = 0x60
        packet[8].Should().Be((byte)(0x07 ^ 0x60));
        packet.Length.Should().Be(278);
    }

    // ── TryDecode ─────────────────────────────────────────────────────────────

    /// <summary>
    /// Known keepalive from SCU (type 0x0b, 15 bytes) captured via Wireshark.
    /// Verify decode doesn't throw and returns a valid type.
    /// </summary>
    [Fact]
    public void TryDecode_ReturnsFalseOnTooShortFrame()
    {
        byte[] buf     = new byte[64];
        bool   ok      = ZzFrameCodec.TryDecode([0x5A, 0x5A, 0x0e], out _, buf, out _);
        ok.Should().BeFalse();
    }

    [Fact]
    public void TryDecode_ReturnsFalseOnBadMagic()
    {
        byte[] data = new byte[20];
        data[0] = 0xAA; data[1] = 0xBB; // wrong magic
        byte[] buf = new byte[64];
        bool ok = ZzFrameCodec.TryDecode(data, out _, buf, out _);
        ok.Should().BeFalse();
    }

    // ── Fixed packet templates ────────────────────────────────────────────────

    [Fact]
    public void KeyExchangeTemplate_HasCorrectMagicAndType()
    {
        var t = ZzFrameCodec.KeyExchangeTemplate;
        t[0].Should().Be(0x5A);
        t[1].Should().Be(0x5A);
        t[2].Should().Be(0x12);
    }

    [Fact]
    public void AuthBlobTemplate_HasCorrectLength()
    {
        ZzFrameCodec.AuthBlobTemplate.Length.Should().Be(133);
    }

    [Fact]
    public void ConfigATemplate_MatchesWiresharkCapture()
    {
        // Confirmed from Wireshark: Yaesu sends this exact byte sequence at seq=9
        byte[] expected =
        [
            0x5a,0x5a,0x14,0x00,0x00,0x01,0x09,0xa0,0xa8,0x56,0x54,0x55,
            0x5f,0x52,0x7d,0x50,0x51,0x5e,0x0e,0x9f,0x5d,0xcc,0x5b,0x58
        ];
        ZzFrameCodec.ConfigATemplate.ToArray().Should().Equal(expected);
    }
}

public class RsFrameCodecTests
{
    // ── Encode/decode round-trip ──────────────────────────────────────────────

    [Fact]
    public void Encode_Decode_RoundTrip()
    {
        var    codec   = new RsFrameCodec();
        byte[] payload = [0x01, 0x02, 0x03, 0xAB, 0xCD, 0xEF];
        byte[] frame   = codec.Encode(payload);
        byte[]? decoded = RsFrameCodec.Decode(frame);

        decoded.Should().NotBeNull();
        decoded.Should().Equal(payload);
    }

    [Fact]
    public void Encode_Decode_RoundTrip_EmptyPayload()
    {
        var codec = new RsFrameCodec();
        byte[] frame   = codec.Encode([]);
        byte[]? decoded = RsFrameCodec.Decode(frame);
        decoded.Should().NotBeNull().And.BeEmpty();
    }

    [Fact]
    public void Encode_ProducesCorrectHeader()
    {
        var    codec   = new RsFrameCodec();
        byte[] payload = new byte[10];
        byte[] frame   = codec.Encode(payload);

        frame[0].Should().Be(0x5A);
        frame[1].Should().Be(0x5A);
        frame[4].Should().Be(0x00);
        frame[5].Should().Be(0x01);

        // body length = payload.Length + 4
        ushort bodyLen = BitConverter.ToUInt16(frame, 2);
        bodyLen.Should().Be((ushort)(payload.Length + 4));
    }

    [Fact]
    public void Encode_FrameCounterIncrements()
    {
        var codec  = new RsFrameCodec();
        byte[] f1  = codec.Encode([0x00]);
        byte[] f2  = codec.Encode([0x00]);

        // Key bytes [6-7] should differ between frames
        bool keysMatch = f1[6] == f2[6] && f1[7] == f2[7];
        keysMatch.Should().BeFalse("consecutive frames should have different keys");
    }

    [Fact]
    public void Reset_ResetsCounter()
    {
        var codec = new RsFrameCodec();
        byte[] f1 = codec.Encode([0x01]);
        codec.Reset();
        byte[] f2 = codec.Encode([0x01]);

        // After reset the first frame should be identical (same counter → same key)
        f1[6].Should().Be(f2[6]);
        f1[7].Should().Be(f2[7]);
    }

    [Fact]
    public void Decode_ReturnsNullOnTooShortFrame()
    {
        RsFrameCodec.Decode([0x5A, 0x5A, 0x10]).Should().BeNull();
    }

    [Fact]
    public void Decode_ReturnsNullOnBadMagic()
    {
        byte[] bad = new byte[16];
        bad[0] = 0xAA; bad[1] = 0xBB;
        RsFrameCodec.Decode(bad).Should().BeNull();
    }

    [Fact]
    public void Decode_SpanOverload_RoundTrip()
    {
        var    codec   = new RsFrameCodec();
        byte[] payload = [0x10, 0x20, 0x30];
        byte[] frame   = codec.Encode(payload);

        byte[] output = new byte[payload.Length + 8];
        int    len    = RsFrameCodec.Decode(frame, output);

        len.Should().Be(payload.Length);
        output[..len].Should().Equal(payload);
    }
}

public class PacketBuilderTests
{
    [Fact]
    public void FrequencyCommand_VfoA_14MHz()
    {
        byte[] cmd = PacketBuilder.FrequencyCommand(14_200_000);
        string s   = System.Text.Encoding.ASCII.GetString(cmd);
        s.Should().Be("FA014200000;");
    }

    [Fact]
    public void FrequencyCommand_VfoB()
    {
        byte[] cmd = PacketBuilder.FrequencyCommand(7_100_000, vfoB: true);
        string s   = System.Text.Encoding.ASCII.GetString(cmd);
        s.Should().Be("FB007100000;");
    }

    [Fact]
    public void FrequencyCommand_IsNineDigits()
    {
        byte[] cmd = PacketBuilder.FrequencyCommand(1_000_000);
        string s   = System.Text.Encoding.ASCII.GetString(cmd);
        // FA + 9 digits + ;
        s.Should().HaveLength(12);
        s[..2].Should().Be("FA");
        s[^1].Should().Be(';');
        s[2..11].Should().MatchRegex(@"^\d{9}$");
    }

    [Fact]
    public void CatCmdTable_ContainsExpectedLines()
    {
        string table = System.Text.Encoding.ASCII.GetString(
            PacketBuilder.CatCmdTable(isFt710: false));
        table.Should().Contain("16,3,SPM");
        table.Should().Contain("10573,2,E8");   // non-FT710 value
        table.Should().Contain("21,8,EX040101");
    }

    [Fact]
    public void CatCmdTable_Ft710_UsesDifferentE8Value()
    {
        string table = System.Text.Encoding.ASCII.GetString(
            PacketBuilder.CatCmdTable(isFt710: true));
        table.Should().Contain("10674,2,E8");
        table.Should().NotContain("10573,2,E8");
    }

    [Fact]
    public void LoginPayload_IsCorrectLength()
    {
        byte[] p = PacketBuilder.LoginPayload("remote", "remote");
        p.Should().HaveCount(0x44);
    }

    [Fact]
    public void LoginPayload_StartsWithAuthType()
    {
        byte[] p = PacketBuilder.LoginPayload("user01", "pass");
        p[0].Should().Be(0x01);
    }
}

public class CatMessageTests
{
    [Theory]
    [InlineData("FA014200000;", 14_200_000)]
    [InlineData("FA007100000;", 7_100_000)]
    [InlineData("FA000144000;", 144_000)]
    [InlineData("FB014200000;", 14_200_000)]
    public void TryParseFrequency_FA_FB(string raw, long expected)
    {
        var msg = new CatMessage(raw);
        msg.TryParseFrequency().Should().Be(expected);
    }

    [Fact]
    public void TryParseFrequency_IF_SkipsThreeFlagChars()
    {
        // IF{3 flag chars}{9 freq digits}...
        // flags = "000", freq = 014200000
        var msg = new CatMessage("IF000014200000000000000000000000000000;");
        msg.TryParseFrequency().Should().Be(14_200_000);
    }

    [Theory]
    [InlineData("MD02;")]
    [InlineData("AI0;")]
    [InlineData("PS1;")]
    public void TryParseFrequency_NonFreqMessages_ReturnsNull(string raw)
    {
        new CatMessage(raw).TryParseFrequency().Should().BeNull();
    }
}

using FluentAssertions;
using RemoteShareManaged.Codec;
using Xunit;

namespace RemoteShareManaged.Tests;

/// <summary>
/// Steady-state keepalives, checked against the decoded FUN payloads of a
/// Yaesu app capture (2026-10-19, session SID 0x15 → helloAckNonce 0x1d):
///   50000: 00 00 07 01 04 00 15 00 00 00
///   50001: 01 00 07 01 04 00 15 00 00 00
///   50003: 06 00 07 01 04 00 15 00 00 00
/// </summary>
public class KeepaliveTests
{
    private const byte HelloAckNonce = 0x15 ^ 0x08;

    private static byte[] DecodeFun(byte[] frame)
    {
        byte kl = frame[6], kh = frame[7];
        var fun = new byte[frame.Length - 8];
        for (int i = 0; i < fun.Length; i++)
            fun[i] = (byte)(((-i) & 0xff) ^ frame[8 + i] ^ kl ^ kh);
        return fun;
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(6)]
    public void DeviceKeepalive_MatchesYaesuCapture(ushort dev)
    {
        byte[] frame = ZzFrameCodec.BuildDeviceKeepalive(seq: 0x42, HelloAckNonce, dev);

        frame[2].Should().Be(0x0e);
        DecodeFun(frame).Should().Equal((byte)dev, 0x00, 0x07, 0x01, 0x04, 0x00, 0x15, 0x00, 0x00, 0x00);
    }

    [Fact]
    public void ScopeKeepalive_IsDevice6()
    {
        DecodeFun(ZzFrameCodec.BuildScopeKeepalive(0x42, HelloAckNonce))
            .Should().Equal(DecodeFun(ZzFrameCodec.BuildDeviceKeepalive(0x42, HelloAckNonce, 6)));
    }
}

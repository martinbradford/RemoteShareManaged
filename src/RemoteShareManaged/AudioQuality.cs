namespace RemoteShareManaged.Protocol;

/// <summary>
/// Audio quality modes supported by the SCU-LAN10.
/// Maps directly to the format byte and sample rate in the
/// <c>SendAudioOpen</c> (ZZ type 0x26) packet.
///
/// Confirmed from four Wireshark captures of the Yaesu app:
///   PCM 16 kHz  — format=0x01, rate=16000  (best quality, highest bandwidth)
///   u-Law 16 kHz — format=0x03, rate=16000  (companded, lower effective bandwidth)
///   PCM 8 kHz   — format=0x01, rate=8000   (half bandwidth, ~50% less data)
///   u-Law 8 kHz  — format=0x03, rate=8000   (lowest bandwidth, best for slow WAN)
///
/// Use <see cref="Pcm16k"/> for local LAN or good broadband.
/// Use <see cref="ULaw16k"/> or <see cref="ULaw8k"/> for slow or lossy WAN links.
///
/// When u-Law is selected, <see cref="AudioChannel"/> automatically applies
/// µ-law→PCM decoding in the RX pump before feeding the playback buffer.
/// </summary>
public enum AudioQuality
{
    /// <summary>PCM stereo 16 kHz — best quality, ~160 kbps RX audio stream.</summary>
    Pcm16k,

    /// <summary>µ-Law stereo 16 kHz — companded, natural HF rolloff above ~3.5 kHz.</summary>
    ULaw16k,

    /// <summary>PCM stereo 8 kHz — half bandwidth, suitable for moderate WAN links.</summary>
    Pcm8k,

    /// <summary>µ-Law stereo 8 kHz — lowest bandwidth, best for slow or lossy WAN.</summary>
    ULaw8k,
}
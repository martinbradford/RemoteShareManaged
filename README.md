# RemoteShareManaged

A .NET client library for the **SCU-LAN10** network remote controller, reverse-engineered
to provide programmatic access to a remotely connected transceiver: **CAT command control**,
**bidirectional audio streaming**, and **spectrum / waterfall (scope) data**.

> **Status:** early release (`0.1.0`). The API is functional and in real use, but may still
> change before `1.0`. Feedback and issues are very welcome.

## Requirements

- **.NET 10** SDK / runtime
- **Windows** — the library uses WinMM audio (via [NAudio](https://github.com/naudio/NAudio))
  for capture and playback, so it is currently Windows-only.
- A reachable **SCU-LAN10** unit on your network, and its username / password.

## Installation

Until a NuGet package is published, reference the project directly:

```bash
git clone https://github.com/martinbradford/RemoteShareManaged.git
dotnet add <your-project> reference RemoteShareManaged/src/RemoteShareManaged/RemoteShareManaged.csproj
```

## Quick start

```csharp
using RemoteShareManaged;

await using var session = new ScuSession();

// Observe decoded CAT messages as they arrive
using var sub = session.CatMessages.Subscribe(msg => Console.WriteLine($"CAT: {msg}"));

bool ok = await session.ConnectAsync(
    addr: "192.168.1.50",   // your SCU-LAN10 address
    username: "admin",
    password: "••••••••",
    audioQuality: AudioQuality.Pcm16k);

if (!ok)
{
    Console.WriteLine("Connection failed.");
    return;
}

// Tune the radio
await session.SetFrequencyAsync(14_074_000);   // 14.074 MHz (FT8)
await session.SendCatAsync("MD0C;");           // raw CAT passthrough

// Start receiving/transmitting audio on the default devices
var audio = session.CreateAudioChannel(waveOutDevice: 0, waveInDevice: 0);

// Start the spectrum scope
var scope = session.CreateScopeChannel();
await scope.StartAsync();

Console.ReadLine();
await session.DisconnectAsync();
```

## Key types

| Type | Purpose |
|------|---------|
| `ScuSession` | Main entry point. Connect/disconnect, CAT control, and factory for audio/scope channels. Implements `IAsyncDisposable`. |
| `AudioChannel` | Bidirectional audio (RX playback + TX capture). Supports PCM and µ-law at 8 kHz / 16 kHz. |
| `ScopeChannel` | Spectrum data stream feeding the waterfall/panadapter. |
| `WaterfallBuffer` / `WaterfallColourmap` | Helpers for rendering spectrum data to a waterfall display. |
| `AudioQuality` | Codec/sample-rate selection (`Pcm16k`, `Pcm8k`, `MuLaw8k`, …). |

Diagnostics use `Microsoft.Extensions.Logging` — pass an `ILoggerFactory` to `ScuSession`
to route logs into your host.

## Project layout

```
src/RemoteShareManaged/          the library
tests/RemoteShareManaged.Tests/  xUnit tests (codec round-trips, etc.)
```

## Building

```bash
dotnet build
dotnet test
```

## Acknowledgements

This library is the result of a substantial reverse-engineering effort of the SCU-LAN10
protocol. It is not affiliated with or endorsed by the manufacturer. **SCU-LAN10** and
related product names are trademarks of their respective owners.

## License

[MIT](LICENSE) © 2026 Martin Bradford

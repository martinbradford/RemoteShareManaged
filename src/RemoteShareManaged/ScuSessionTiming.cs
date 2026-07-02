namespace RemoteShareManaged
{
    /// <summary>
    /// All timing constants used during the SCU-LAN10 connection sequence.
    ///
    /// The defaults match the confirmed-working Yaesu reference capture timings.
    /// Reduce values cautiously — the SCU silently ignores packets sent before it
    /// is ready; a step that "works" with shorter delays may fail intermittently.
    ///
    /// Typical tuning starting points:
    ///   • <see cref="CatRoundDelayMs"/>    — try 10ms (was 30ms)
    ///   • <see cref="RoutingStepDelayMs"/> — try 5ms  (was 15ms)
    ///   • <see cref="RoutingDrainMs"/>     — try 50ms (was 200ms)
    ///   • <see cref="AudioSettleMs"/>      — try 20ms (was 60ms)
    ///   • <see cref="ScopeAckTimeoutMs"/>  — try 100ms (was 200ms)
    ///
    /// Pass a customised instance to <see cref="ScuSession.ConnectAsync"/>:
    /// <code>
    ///   var timing = ScuSessionTiming.Default with { CatRoundDelayMs = 10 };
    ///   await session.ConnectAsync(addr, user, pass, timing: timing);
    /// </code>
    /// </summary>
    public sealed record ScuSessionTiming
    {
        // ── Steady-state ─────────────────────────────────────────────────────

        /// <summary>Keepalive send interval on port 50000 (ms). Default 5000.</summary>
        public int KeepaliveIntervalMs { get; init; } = 5_000;

        /// <summary>Keepalive response timeout (ms). Default 2000.</summary>
        public int KeepaliveTimeoutMs  { get; init; } = 2_000;

        // ── Handshake timeouts (port 50000) ───────────────────────────────────

        /// <summary>
        /// Timeout for each major handshake step: HELLO-ACK, KEY-ACK,
        /// CAT DevPortConnect ACK, etc. (ms). Default 3000.
        /// </summary>
        public int StepTimeoutMs       { get; init; } = 3_000;

        /// <summary>AUTH-ACK timeout — longer because the radio may need to
        /// decrypt/authenticate (ms). Default 20000.</summary>
        public int AuthTimeoutMs       { get; init; } = 20_000;

        /// <summary>Short CONFIG/INIT/FINAL-ACK wait after sending CONFIG packets
        /// on port 50000 (ms). Default 500.</summary>
        public int ConfigAckTimeoutMs  { get; init; } = 500;

        // ── CAT channel open (port 50001) ─────────────────────────────────────

        /// <summary>
        /// Delay before each round of PS1/AI0/AI CAT-Write packets.
        /// Gives the SCU time to process SendDevPortConnect before accepting
        /// CatWrites. Default 30ms — try 10ms.
        /// </summary>
        public int CatRoundDelayMs     { get; init; } = 30;

        /// <summary>Drain window after the CAT init sequence (ms). Default 100.</summary>
        public int CatDrainMs          { get; init; } = 100;

        // ── Audio routing init (JP/SP commands, still on port 50001) ─────────

        /// <summary>
        /// Gap between each JP/SP/FD routing command packet.
        /// Matches the ~15ms inter-packet gap in the Yaesu reference capture.
        /// Default 15ms — try 5ms.
        /// </summary>
        public int RoutingStepDelayMs  { get; init; } = 15;

        /// <summary>
        /// Drain window at the end of the routing init sequence, waiting for
        /// the SCU to respond to the FD/IF/MD queries (ms). Default 200ms — try 50ms.
        /// </summary>
        public int RoutingDrainMs      { get; init; } = 200;

        // ── Audio channel open (port 50002) ───────────────────────────────────

        /// <summary>
        /// Settle delay after sending SendAudioOpen, before the RX stream
        /// is expected to arrive (ms). Default 60ms — try 20ms.
        /// </summary>
        public int AudioSettleMs       { get; init; } = 60;

        /// <summary>
        /// SCU-side RX (playback) buffer in ms, sent in SendAudioOpen fun[26:28]
        /// and in every TX audio packet fun[26:28].
        /// Controls how much audio the SCU buffers before delivering it to the radio.
        /// Lower values reduce end-to-end latency and help WSJT-X delta-T accuracy.
        /// Valid range: 100–2000 ms (Yaesu app UI range). Default 500ms.
        /// </summary>
        public ushort AudioPlaybackLatencyMs { get; init; } = 500;

        /// <summary>
        /// SCU-side TX (record) buffer in ms, sent in SendAudioOpen fun[28:30]
        /// and in every TX audio packet fun[28:30].
        /// Controls how much TX audio the SCU buffers before transmitting.
        /// Lower values reduce TX latency. Valid range: 100–2000 ms. Default 500ms.
        /// </summary>
        public ushort AudioRecordLatencyMs   { get; init; } = 500;

        /// <summary>
        /// Drain delay after opening the audio socket, before setting up the
        /// NAudio chain (ms). Lets the receive loop start and drains any stale
        /// ICMP Port Unreachable replies. Default 100ms.
        /// </summary>
        public int AudioSocketDrainMs        { get; init; } = 100;

        /// <summary>
        /// NAudio WaveOutEvent desired latency (ms). This is real latency introduced
        /// by the Windows MME audio stack between the receive pump and the speakers /
        /// virtual cable. Smaller values directly reduce WSJT-X delta-T.
        /// Default 150ms. Minimum safe value is ~80ms on most systems.
        /// </summary>
        public int WaveOutDesiredLatencyMs   { get; init; } = 150;

        /// <summary>
        /// Delay after sending the 8k-mode silence trigger frames before starting
        /// the RX/TX pumps (ms). Default 80ms.
        /// </summary>
        public int Audio8kTriggerDelayMs     { get; init; } = 80;

        /// <summary>
        /// Timeout waiting for the scope DevPortConnect ACK before SendAudioOpen.
        /// The ACK typically arrives in 35–86ms. Default 200ms — try 100ms.
        /// </summary>
        public int ScopeAckTimeoutMs   { get; init; } = 200;

        // ── Miscellaneous ────────────────────────────────────────────────────

        /// <summary>Delay after sending CAT init query before starting poll loop (ms). Default 50.</summary>
        public int PostConnectDelayMs  { get; init; } = 50;

        /// <summary>
        /// Render every Nth scope frame; the rest are decoded but not raised.
        /// 1 = every frame (~25 fps), 2 = ~12 fps, 3 = ~8 fps, 5 = ~5 fps.
        /// On WAN links, setting this to 3–5 dramatically reduces Dispatcher
        /// queue pressure without changing the wire bandwidth.
        /// Applied automatically when CreateScopeChannel() is called.
        /// Default 1 (full frame rate).
        /// </summary>
        public int ScopeFrameDecimation { get; init; } = 1;

        /// <summary>Delay before closing the control socket during disconnect (ms). Default 50.</summary>
        public int DisconnectDelayMs   { get; init; } = 50;

        // ── Presets ───────────────────────────────────────────────────────────

        /// <summary>
        /// Default timing — all values at the confirmed-working Yaesu reference
        /// timings.  A reasonable starting point if you are unsure which preset
        /// to use.
        /// </summary>
        public static readonly ScuSessionTiming Default = new();

        /// <summary>
        /// Fast / home-LAN preset.  All waits reduced to the minimum that should
        /// still work reliably on a low-latency, low-jitter local network
        /// (typically &lt;1ms round-trip).  Use as a starting point for tuning;
        /// revert individual values if a step becomes unreliable.
        /// </summary>
        public static readonly ScuSessionTiming Fast = new()
        {
            CatRoundDelayMs      = 10,
            CatDrainMs           = 50,
            RoutingStepDelayMs   = 5,
            RoutingDrainMs       = 50,
            AudioSettleMs        = 20,
            ScopeAckTimeoutMs    = 100,
            PostConnectDelayMs   = 20,
            DisconnectDelayMs    = 20,
            AudioPlaybackLatencyMs = 100,
            AudioRecordLatencyMs   = 100,
            AudioSocketDrainMs     = 20,
            WaveOutDesiredLatencyMs = 100,
            Audio8kTriggerDelayMs  = 40,
        };

        /// <summary>
        /// WAN / 4G preset.  All timeouts inflated for high-latency, jittery
        /// mobile links (typically 50–200ms RTT, occasional 500ms+ spikes).
        ///
        /// <list type="bullet">
        ///   <item>Step timeouts doubled to 6 s — gives the SCU ACK time to
        ///         arrive even through a 4G cell handover.</item>
        ///   <item>Auth timeout raised to 30 s — the radio's auth decrypt is
        ///         unaffected by network latency but the ACK can be delayed.</item>
        ///   <item>CAT round delay raised to 60 ms and drain windows to
        ///         300 ms — prevents CAT writes racing ahead of the SCU's
        ///         slower responses over a lossy link.</item>
        ///   <item>Scope ACK timeout raised to 500 ms — 4G latency spikes can
        ///         easily exceed the normal 35–86 ms ACK window.</item>
        ///   <item>Keepalive interval lowered to 3 s and keepalive timeout
        ///         raised to 5 s — detects link loss quickly while tolerating
        ///         occasional late ACKs.</item>
        /// </list>
        /// </summary>
        //public static readonly ScuSessionTiming Wan = new()
        //{
        //    // Handshake — every step gets extra headroom for high RTT
        //    StepTimeoutMs      = 6_000,
        //    AuthTimeoutMs      = 30_000,
        //    ConfigAckTimeoutMs = 1_000,

        //    // CAT channel — slower inter-packet cadence, bigger drain windows
        //    CatRoundDelayMs    = 60,
        //    CatDrainMs         = 300,
        //    RoutingStepDelayMs = 30,
        //    RoutingDrainMs     = 400,

        //    // Audio / scope — more time for the SCU ACK to arrive
        //    AudioSettleMs      = 100,
        //    ScopeAckTimeoutMs  = 500,

        //    // Miscellaneous
        //    PostConnectDelayMs = 100,
        //    DisconnectDelayMs  = 100,

        //    // Keepalive — tighter polling, generous timeout
        //    KeepaliveIntervalMs = 3_000,
        //    KeepaliveTimeoutMs  = 5_000,

        //    // Audio buffers — larger buffers absorb WAN jitter
        //    AudioPlaybackLatencyMs  = 1000,
        //    AudioRecordLatencyMs    = 1000,
        //    AudioSocketDrainMs      = 100,
        //    WaveOutDesiredLatencyMs = 300,
        //    Audio8kTriggerDelayMs   = 80,

        //    // Scope — 5 fps (~25 fps ÷ 5) reduces Dispatcher load on slow links
        //    ScopeFrameDecimation = 5,
        //};

        public static readonly ScuSessionTiming Wan = new()
        {
            CatRoundDelayMs = 10,
            CatDrainMs = 50,
            RoutingStepDelayMs = 5,
            RoutingDrainMs = 50,
            AudioSettleMs = 20,
            ScopeAckTimeoutMs = 100,
            PostConnectDelayMs = 20,
            DisconnectDelayMs = 20,
            AudioPlaybackLatencyMs = 200,
            AudioRecordLatencyMs = 100,
            AudioSocketDrainMs = 20,
            WaveOutDesiredLatencyMs = 200,
            Audio8kTriggerDelayMs = 40,
            ScopeFrameDecimation = 0,
        };

        public static readonly ScuSessionTiming Lan = new()
        {
            CatRoundDelayMs = 10,
            CatDrainMs = 50,
            RoutingStepDelayMs = 5,
            RoutingDrainMs = 50,
            AudioSettleMs = 20,
            ScopeAckTimeoutMs = 100,
            PostConnectDelayMs = 20,
            DisconnectDelayMs = 20,
            AudioPlaybackLatencyMs = 100,
            AudioRecordLatencyMs = 100,
            AudioSocketDrainMs = 20,
            WaveOutDesiredLatencyMs = 100,
            Audio8kTriggerDelayMs = 40,
            ScopeFrameDecimation = 0,
        };
    }
}

using System;

namespace RemoteShareManaged
{
    /// <summary>
    /// Predefined waterfall colour maps and Gray8→BGRA32 conversion.
    ///
    /// Each map is a 256-entry uint[] where entry[i] = 0xAARRGGBB.
    /// When written as a little-endian uint32 into a pixel buffer the bytes
    /// appear as B, G, R, A — matching WPF's <c>Bgra32</c> and Avalonia's
    /// <c>Bgra8888</c> pixel formats directly.
    ///
    /// Usage:
    /// <code>
    ///   WaterfallBuffer buf = ...;
    ///   byte[]  gray  = new byte[w * h];
    ///   byte[]  bgra  = new byte[w * h * 4];
    ///   buf.CopyToGray8(gray, w, h);
    ///   WaterfallColourmap.ApplyToBgra32(gray, bgra, WaterfallColourmap.Sdr);
    ///   // blit bgra → WriteableBitmap (WPF/Avalonia Bgra32)
    /// </code>
    /// </summary>
    public static class WaterfallColourmap
    {
        // ── Predefined maps ──────────────────────────────────────────────────

        /// <summary>Classic SDR waterfall: dark blue → cyan → green → yellow → red.</summary>
        public static readonly uint[] Sdr = BuildSdr();

        /// <summary>Grayscale: black (no signal) → white (strong).</summary>
        public static readonly uint[] Gray = BuildGray();

        /// <summary>Phosphor green: black → dark green → bright green.</summary>
        public static readonly uint[] Green = BuildGreen();

        // ── Conversion ───────────────────────────────────────────────────────

        /// <summary>
        /// Expand a Gray8 buffer into BGRA32 pixels using the given colour map.
        /// <paramref name="gray8"/> and <paramref name="bgra32"/> must be the
        /// same pixel count; <paramref name="bgra32"/> must be 4× as long.
        /// </summary>
        public static void ApplyToBgra32(
            ReadOnlySpan<byte> gray8,
            Span<byte>         bgra32,
            uint[]             map)
        {
            int pixels = gray8.Length;
            for (int i = 0; i < pixels; i++)
            {
                uint  c    = map[gray8[i]];
                int   base4 = i * 4;
                // 0xAARRGGBB → bytes: B, G, R, A
                bgra32[base4 + 0] = (byte) c;          // B
                bgra32[base4 + 1] = (byte)(c >>  8);   // G
                bgra32[base4 + 2] = (byte)(c >> 16);   // R
                bgra32[base4 + 3] = (byte)(c >> 24);   // A
            }
        }

        // ── Builders ─────────────────────────────────────────────────────────

        private static uint[] BuildSdr()
        {
            // Keyframes: (value, R, G, B)
            // 0   → very dark blue          (no signal)
            // 48  → medium blue
            // 100 → cyan
            // 150 → green
            // 200 → yellow
            // 230 → orange
            // 255 → red / near-white peak
            var kf = new (int v, int r, int g, int b)[]
            {
                (  0,   0,   0,  60),
                ( 48,   0,  30, 200),
                (100,   0, 200, 220),
                (150,   0, 210,  40),
                (200, 220, 210,   0),
                (230, 255,  80,   0),
                (255, 255,  20,  20),
            };
            return BuildFromKeyframes(kf);
        }

        private static uint[] BuildGray()
        {
            var map = new uint[256];
            for (int i = 0; i < 256; i++)
                map[i] = Rgba(i, i, i);
            return map;
        }

        private static uint[] BuildGreen()
        {
            var map = new uint[256];
            for (int i = 0; i < 256; i++)
            {
                int g = (int)(i * 0.85f);
                int b = (int)(i * 0.10f);
                map[i] = Rgba(0, Math.Min(255, g + 20), b);
            }
            return map;
        }

        // Linearly interpolate between (v,r,g,b) keyframes.
        private static uint[] BuildFromKeyframes(
            (int v, int r, int g, int b)[] kf)
        {
            var map = new uint[256];
            for (int seg = 0; seg < kf.Length - 1; seg++)
            {
                var (v0, r0, g0, b0) = kf[seg];
                var (v1, r1, g1, b1) = kf[seg + 1];
                int span = v1 - v0;
                for (int v = v0; v <= v1; v++)
                {
                    float t = span == 0 ? 0f : (float)(v - v0) / span;
                    int r = (int)(r0 + t * (r1 - r0));
                    int g = (int)(g0 + t * (g1 - g0));
                    int b = (int)(b0 + t * (b1 - b0));
                    map[v] = Rgba(r, g, b);
                }
            }
            return map;
        }

        // Pack as 0xAARRGGBB (fully opaque).
        private static uint Rgba(int r, int g, int b)
            => 0xFF000000u | ((uint)r << 16) | ((uint)g << 8) | (uint)b;
    }
}

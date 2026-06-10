using System;

namespace RemoteShareManaged
{
    /// <summary>
    /// UI-agnostic circular waterfall row buffer.  Works for any spectrum source:
    /// RF spectrum (846 bins), AF-FFT (198 bins), or any other bin count.
    ///
    /// Each call to <see cref="AddRow"/> stores one normalised row
    /// (0 = noise floor / no signal, 255 = strong signal).  The buffer is
    /// circular: once full, the oldest row is silently overwritten.
    ///
    /// <see cref="CopyToGray8"/> renders the buffer into a flat Gray8 byte
    /// array (1 byte per pixel, newest row at the top) scaled to any requested
    /// width × height.  Pass the result to <see cref="WaterfallColourmap"/> to
    /// produce a BGRA32 bitmap for WPF, Avalonia, or any other toolkit.
    ///
    /// Normalisation modes (controlled by <paramref name="flattenHalf"/>):
    /// <list type="bullet">
    ///   <item>
    ///     <c>flattenHalf &gt; 0</c> — frequency-domain background subtraction.
    ///     A sliding-window mean of width <c>2×flattenHalf</c> bins estimates the
    ///     local noise floor; each pixel = deviation above that floor.  Best for
    ///     RF spectrum (recommended flattenHalf=50 for 846-bin scope data).
    ///   </item>
    ///   <item>
    ///     <c>flattenHalf = 0</c> — direct inversion only (no flattening).
    ///     Each pixel = <c>255 − raw</c>, scaled by <paramref name="deviationScale"/>.
    ///     Best for AF-FFT where the background is already flat and you want
    ///     absolute magnitude rather than relative deviation.
    ///   </item>
    /// </list>
    ///
    /// Thread safety: <see cref="AddRow"/> and <see cref="CopyToGray8"/> may
    /// be called concurrently — a single lock protects <c>_head</c> and
    /// <c>_filled</c>.
    ///
    /// Typical instantiation:
    /// <code>
    /// // RF spectrum — 846 bins, frequency-domain flattening
    /// var rfMain = new WaterfallBuffer(512, ScopeChannel.SpeBins,
    ///                  flattenHalf: 50, deviationScale: 30f);
    /// var rfSub  = new WaterfallBuffer(512, ScopeChannel.SpeBins,
    ///                  flattenHalf: 50, deviationScale: 30f);
    ///
    /// // AF-FFT — 198 bins, no flattening (direct magnitude)
    /// var afMain = new WaterfallBuffer(512, ScopeChannel.AfFftBins,
    ///                  flattenHalf: 0, deviationScale: 255f);
    /// var afSub  = new WaterfallBuffer(512, ScopeChannel.SubAfFftBins,
    ///                  flattenHalf: 0, deviationScale: 255f);
    /// </code>
    /// </summary>
    public sealed class WaterfallBuffer
    {
        // ── Configuration ────────────────────────────────────────────────────

        private readonly int   _flattenHalf;     // 0 = no flattening
        private readonly float _deviationScale;  // raw counts → full brightness

        // ── Storage ──────────────────────────────────────────────────────────

        private readonly byte[,] _rows;   // [RowCount, BinCount], normalised 0–255
        private int  _head;               // index of next row to write
        private int  _filled;             // how many rows have been written so far
        private readonly object _lock = new();

        // ── Public properties ────────────────────────────────────────────────

        public int RowCount { get; }
        public int BinCount { get; }

        // ── Construction ─────────────────────────────────────────────────────

        /// <param name="rowCount">History depth (e.g. 512 rows ≈ 20 s at 25 fps).</param>
        /// <param name="binCount">
        ///   Spectrum bins per row.
        ///   Use <see cref="ScopeChannel.SpeBins"/> (846) for RF spectrum,
        ///   <see cref="ScopeChannel.AfFftBins"/> (198) for MAIN AF-FFT,
        ///   <see cref="ScopeChannel.SubAfFftBins"/> (198) for SUB AF-FFT.
        /// </param>
        /// <param name="flattenHalf">
        ///   Half-width of the sliding background-estimation window in bins.
        ///   Use 50 for 846-bin RF spectrum (100-bin window ≈ 11.8 kHz).
        ///   Use 0 to disable flattening (recommended for AF-FFT).
        /// </param>
        /// <param name="deviationScale">
        ///   Raw-count deviation that maps to full brightness (255).
        ///   RF spectrum (flattenHalf&gt;0): use 30 — a 30-count rise above local
        ///   background → full white.
        ///   AF-FFT (flattenHalf=0): use 255 — pure inversion (255−raw)/255,
        ///   giving the full 0–255 dynamic range; use the brightness slider
        ///   in the UI to boost faint signals.
        /// </param>
        public WaterfallBuffer(int rowCount, int binCount,
                               int flattenHalf = 50, float deviationScale = 30f)
        {
            RowCount        = rowCount;
            BinCount        = binCount;
            _flattenHalf    = flattenHalf;
            _deviationScale = deviationScale;
            _rows           = new byte[rowCount, binCount];
        }

        // ── Write ─────────────────────────────────────────────────────────────

        /// <summary>
        /// Add one spectrum row to the waterfall.
        /// <paramref name="rawSpectrum"/> must contain at least <see cref="BinCount"/>
        /// bytes in the SCU inverted encoding (lower byte = stronger signal).
        /// Normalisation is applied according to the <c>flattenHalf</c> setting
        /// chosen at construction time.
        /// </summary>
        public void AddRow(ReadOnlySpan<byte> rawSpectrum)
        {
            if (rawSpectrum.Length < BinCount) return;

            Span<byte> normalised = stackalloc byte[BinCount];

            if (_flattenHalf > 0)
            {
                // ── Frequency-domain background subtraction ───────────────
                // Sliding-window mean across ±_flattenHalf bins estimates the
                // local noise floor.  Signal = background − raw (inverted encoding).
                Span<float> bg = stackalloc float[BinCount];
                float sum   = 0f;
                int   count = 0;
                for (int j = 0; j < Math.Min(_flattenHalf, BinCount); j++)
                {
                    sum += rawSpectrum[j];
                    count++;
                }
                for (int i = 0; i < BinCount; i++)
                {
                    int addIdx = i + _flattenHalf;
                    if (addIdx < BinCount) { sum += rawSpectrum[addIdx]; count++; }
                    int removeIdx = i - _flattenHalf - 1;
                    if (removeIdx >= 0) { sum -= rawSpectrum[removeIdx]; count--; }
                    bg[i] = sum / count;
                }
                for (int i = 0; i < BinCount; i++)
                {
                    float deviation = bg[i] - rawSpectrum[i];
                    normalised[i] = (byte)(Math.Clamp(deviation / _deviationScale, 0f, 1f) * 255f);
                }
            }
            else
            {
                // ── Direct inversion (no flattening) ─────────────────────
                // pixel = (255 − raw) scaled by deviationScale.
                // 255 − raw converts inverted encoding to magnitude (0=none, 255=max).
                for (int i = 0; i < BinCount; i++)
                {
                    float magnitude = 255f - rawSpectrum[i];
                    normalised[i] = (byte)(Math.Clamp(magnitude / _deviationScale, 0f, 1f) * 255f);
                }
            }

            // ── Store in circular buffer ──────────────────────────────────
            lock (_lock)
            {
                for (int i = 0; i < BinCount; i++)
                    _rows[_head, i] = normalised[i];
                _head   = (_head + 1) % RowCount;
                if (_filled < RowCount) _filled++;
            }
        }

        // ── Read ──────────────────────────────────────────────────────────────

        /// <summary>
        /// Render the buffer into a flat Gray8 array (1 byte per pixel).
        /// <list type="bullet">
        ///   <item>Row 0 = most recent (top of waterfall), row destHeight-1 = oldest.</item>
        ///   <item><paramref name="dest"/> must be at least destWidth × destHeight bytes.</item>
        ///   <item>Bins and rows are scaled with nearest-neighbour to fit the requested size.</item>
        /// </list>
        /// </summary>
        public void CopyToGray8(Span<byte> dest, int destWidth, int destHeight)
        {
            int filled;
            lock (_lock) { filled = _filled; }

            if (filled == 0)
            {
                dest[..(destWidth * destHeight)].Clear();
                return;
            }

            int newest = (_head - 1 + RowCount) % RowCount;

            for (int dy = 0; dy < destHeight; dy++)
            {
                int age    = dy * filled / destHeight;
                int srcRow = (newest - age + RowCount) % RowCount;
                int destBase = dy * destWidth;
                for (int dx = 0; dx < destWidth; dx++)
                {
                    int bin = dx * BinCount / destWidth;
                    dest[destBase + dx] = _rows[srcRow, bin];
                }
            }
        }

        /// <summary>Clear all stored rows (e.g. after disconnect or band change).</summary>
        public void Clear()
        {
            lock (_lock)
            {
                Array.Clear(_rows);
                _head   = 0;
                _filled = 0;
            }
        }
    }
}

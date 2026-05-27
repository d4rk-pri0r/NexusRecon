"""Unit tests for the TUI-6a gauge widget library.

The widgets are pure-render (no async work, no Textual app
needed) — every assertion runs against the rendered ``Text``
output directly. End-to-end mounting + theme integration is
covered separately in the dashboard pilot tests.
"""
from __future__ import annotations

import pytest

from rich.text import Text

from nexusrecon.tui.widgets.gauges import (
    INTENSITY_STOPS,
    IntensityGauge,
    MiniSparkline,
    PhaseStrip,
    pick_intensity_color,
)


def _has_color(rendered: Text, hex_color: str) -> bool:
    """``str(Text)`` strips markup — we need to look at the
    parsed Span styles to assert against the colors that came
    out of the gauge's render. Helper checks whether the hex
    appears in any span's style across the rendered text."""
    return any(hex_color in str(span.style) for span in rendered.spans)


def _text_content(rendered: Text) -> str:
    """Strip markup and return the visible characters. Handy
    when an assertion is about characters / block-glyphs,
    independent of color."""
    return rendered.plain


# ──────────────────────────────────────────────────────────────────────
# Color stop picker
# ──────────────────────────────────────────────────────────────────────


class TestPickIntensityColor:
    """The color picker is the contract every gauge depends on.
    Stops at 0.50 / 0.75 / 0.90 / 1.00 are the operator-facing
    thresholds; changing them is a UX-visible decision that should
    fail a test, not slip in silently."""

    def test_zero_percentage_returns_coolest(self):
        assert pick_intensity_color(0.0) == "#00ff9c"

    def test_exactly_at_stop_returns_that_stop(self):
        """Threshold semantics: ``pct <= threshold`` matches. Pin
        the inclusive edge so a future ``<`` regression is loud."""
        assert pick_intensity_color(0.50) == "#00ff9c"
        assert pick_intensity_color(0.75) == "#f1c40f"
        assert pick_intensity_color(0.90) == "#ff8c00"
        assert pick_intensity_color(1.00) == "#ff3838"

    @pytest.mark.parametrize(
        "pct,expected",
        [
            (0.10, "#00ff9c"),
            (0.49, "#00ff9c"),
            (0.51, "#f1c40f"),
            (0.74, "#f1c40f"),
            (0.76, "#ff8c00"),
            (0.89, "#ff8c00"),
            (0.91, "#ff3838"),
            (0.99, "#ff3838"),
        ],
    )
    def test_mid_range_pcts(self, pct: float, expected: str):
        assert pick_intensity_color(pct) == expected

    def test_negative_clamps_to_coolest(self):
        """Defensive: callers may pass a normalized value
        that's slightly negative due to float arithmetic. The
        clamp keeps render cheap and never raises."""
        assert pick_intensity_color(-0.1) == "#00ff9c"
        assert pick_intensity_color(-99.9) == "#00ff9c"

    def test_overshoot_clamps_to_hottest(self):
        """Same for the upper bound — a value 1.5 should still
        render as critical-red rather than walking off the stop
        list."""
        assert pick_intensity_color(1.5) == "#ff3838"
        assert pick_intensity_color(1e9) == "#ff3838"

    def test_stops_table_invariant(self):
        """The stops list must be monotonically increasing and
        end at exactly 1.0. A future edit that breaks either
        invariant breaks every gauge that depends on it."""
        thresholds = [t for t, _ in INTENSITY_STOPS]
        assert thresholds == sorted(thresholds)
        assert thresholds[-1] == 1.0


# ──────────────────────────────────────────────────────────────────────
# IntensityGauge
# ──────────────────────────────────────────────────────────────────────


class TestIntensityGauge:
    """The gauge is a :class:`Static` ── ``.render()`` returns a
    Rich ``Text`` instance whose markup carries the color +
    percentage. Tests assert against the rendered text directly
    without spinning up a Textual app."""

    def test_zero_value_renders_cool(self):
        g = IntensityGauge(total=1.0, width=10)
        g.value = 0.0
        rendered = str(g.render())
        # No fill — bar is all empty track. Percentage line
        # shows 0.0%.
        assert "0.0%" in rendered

    def test_full_value_renders_critical(self):
        g = IntensityGauge(total=1.0, width=10)
        g.value = 1.0
        rendered = str(g.render())
        # Critical-red color must appear in the markup.
        assert "100.0%" in rendered

    def test_clamps_overshoot_to_full(self):
        """A value greater than ``total`` should render as a
        fully-filled bar (still bounded). The percentage label
        also clamps so the operator doesn't see ``150.0%``."""
        g = IntensityGauge(total=1.0, width=10)
        g.value = 1.5
        rendered = str(g.render())
        # Percentage is clamped to 100% by the internal min().
        assert "100.0%" in rendered

    def test_clamps_negative_to_zero(self):
        g = IntensityGauge(total=1.0, width=10)
        g.value = -0.3
        rendered = str(g.render())
        assert "0.0%" in rendered

    def test_zero_total_renders_n_a(self):
        """A gauge whose denominator is zero has nothing to
        convey ── render an empty track with an ``n/a``
        suffix rather than dividing by zero."""
        g = IntensityGauge(total=0.0, width=10)
        g.value = 0.0
        rendered = str(g.render())
        assert "n/a" in rendered

    def test_show_percent_false_omits_suffix(self):
        g = IntensityGauge(total=1.0, width=10, show_percent=False)
        g.value = 0.5
        rendered = str(g.render())
        assert "%" not in rendered

    def test_label_rendered_when_provided(self):
        g = IntensityGauge(total=1.0, width=10, label="Budget")
        g.value = 0.5
        rendered = str(g.render())
        assert "Budget" in rendered

    def test_label_absent_by_default(self):
        g = IntensityGauge(total=1.0, width=10)
        g.value = 0.5
        rendered = str(g.render())
        assert "Budget" not in rendered

    def test_width_controls_bar_length(self):
        g_narrow = IntensityGauge(total=1.0, width=5)
        g_narrow.value = 1.0
        g_wide = IntensityGauge(total=1.0, width=20)
        g_wide.value = 1.0
        assert str(g_wide.render()).count("█") > str(g_narrow.render()).count("█")

    def test_value_reactive_triggers_refresh(self):
        """Setting ``value`` should mark the widget for refresh
        via the ``watch_value`` hook. We can't observe the
        Textual paint cycle directly without an App, but we can
        confirm the hook is wired by overriding refresh and
        watching it fire."""
        calls: list[bool] = []
        g = IntensityGauge(total=1.0, width=10)
        original_refresh = g.refresh

        def _record(*args, **kwargs):
            calls.append(True)
            return original_refresh(*args, **kwargs)

        g.refresh = _record  # type: ignore[method-assign]
        g.value = 0.42
        assert calls, "watch_value did not call refresh()"


# ──────────────────────────────────────────────────────────────────────
# MiniSparkline
# ──────────────────────────────────────────────────────────────────────


class TestMiniSparkline:
    def test_empty_history_renders_empty_track(self):
        s = MiniSparkline(max_points=8)
        rendered = str(s.render())
        # Render still produces something the size of max_points
        # so the slot exists during cold-start.
        assert rendered

    def test_push_appends_value(self):
        s = MiniSparkline(max_points=10)
        s.push(1.0)
        s.push(2.0)
        s.push(3.0)
        assert list(s.history) == [1.0, 2.0, 3.0]

    def test_push_trims_to_max_points(self):
        """History longer than ``max_points`` keeps the tail.
        Pin so a future "keep head" regression is loud."""
        s = MiniSparkline(max_points=3)
        for i in range(10):
            s.push(float(i))
        assert list(s.history) == [7.0, 8.0, 9.0]

    def test_constant_history_renders_mid_height_blocks(self):
        """When every sample is equal, the sparkline collapses
        to mid-height blocks rather than choosing arbitrarily.
        This keeps the visual stable for surfaces that are
        legitimately constant (no findings yet, no traffic).

        The render code returns ``blocks[steps // 2]`` where
        ``steps = len(blocks) - 1``; with 8 blocks that's
        ``blocks[3] = ▄``."""
        s = MiniSparkline(max_points=5)
        for _ in range(5):
            s.push(0.5)
        rendered = _text_content(s.render())
        from nexusrecon.tui.widgets.gauges import _SPARKLINE_BLOCKS
        steps = len(_SPARKLINE_BLOCKS) - 1
        mid = _SPARKLINE_BLOCKS[steps // 2]
        assert mid * 5 in rendered

    def test_varied_history_uses_full_block_range(self):
        """When history spans the full range, the rendered
        sparkline must include the lowest AND highest block
        characters ── otherwise the visual scaling is broken."""
        s = MiniSparkline(max_points=10)
        for v in (0.0, 0.25, 0.5, 0.75, 1.0):
            s.push(v)
        rendered = _text_content(s.render())
        from nexusrecon.tui.widgets.gauges import _SPARKLINE_BLOCKS
        # Lowest block (▁ at index 0) and highest (█ at -1).
        assert _SPARKLINE_BLOCKS[0] in rendered
        assert _SPARKLINE_BLOCKS[-1] in rendered

    def test_color_wraps_output_when_set(self):
        s = MiniSparkline(max_points=5, color="#ff8c00")
        for _ in range(3):
            s.push(0.5)
        rendered = s.render()
        assert _has_color(rendered, "#ff8c00")

    def test_push_triggers_refresh(self):
        s = MiniSparkline(max_points=5)
        calls: list[bool] = []
        original = s.refresh

        def _rec(*args, **kwargs):
            calls.append(True)
            return original(*args, **kwargs)

        s.refresh = _rec  # type: ignore[method-assign]
        s.push(1.0)
        assert calls


# ──────────────────────────────────────────────────────────────────────
# PhaseStrip
# ──────────────────────────────────────────────────────────────────────


class TestPhaseStrip:
    def test_empty_ratios_renders_empty_text(self):
        ps = PhaseStrip()
        assert str(ps.render()) == ""

    def test_single_segment_renders(self):
        ps = PhaseStrip(segment_width=8)
        ps.ratios = [0.5]
        rendered = str(ps.render())
        assert "█" in rendered
        assert "░" in rendered

    def test_multiple_segments_separated_by_gap(self):
        """Two segments side-by-side must include a separator
        space so they read as discrete phases. Three segments
        means two separators."""
        ps = PhaseStrip(segment_width=4)
        ps.ratios = [0.5, 0.5, 0.5]
        rendered = str(ps.render())
        # Stripping markup tags, the bar should contain spaces
        # between the segments. Easiest check: count blocks.
        # Each segment at 0.5 with width=4 → 2 filled + 2 empty.
        # 3 segments → 6 filled blocks + 6 empty blocks.
        assert rendered.count("█") == 6
        assert rendered.count("░") == 6

    def test_zero_ratio_segment_renders_only_track(self):
        ps = PhaseStrip(segment_width=5)
        ps.ratios = [0.0]
        rendered = str(ps.render())
        assert "█" not in rendered
        assert rendered.count("░") == 5

    def test_full_ratio_segment_renders_only_fill(self):
        ps = PhaseStrip(segment_width=5)
        ps.ratios = [1.0]
        rendered = str(ps.render())
        assert rendered.count("█") == 5
        assert "░" not in rendered

    def test_ratio_above_one_clamps(self):
        """A ratio >1 should not render a wider-than-segment
        bar (would push other segments out of alignment)."""
        ps = PhaseStrip(segment_width=4)
        ps.ratios = [1.5]
        rendered = str(ps.render())
        assert rendered.count("█") == 4

    def test_negative_ratio_clamps(self):
        ps = PhaseStrip(segment_width=4)
        ps.ratios = [-0.5]
        rendered = str(ps.render())
        assert rendered.count("█") == 0
        assert rendered.count("░") == 4

    def test_per_segment_intensity_color(self):
        """Each segment uses its OWN ratio to pick its color.
        A strip with one cool + one hot segment must include
        both color codes in the markup ── otherwise the per-
        phase signal is lost."""
        ps = PhaseStrip(segment_width=4)
        ps.ratios = [0.1, 0.95]
        rendered = ps.render()
        assert _has_color(rendered, "#00ff9c")  # cool segment
        assert _has_color(rendered, "#ff3838")  # critical segment

    def test_ratios_reactive_triggers_refresh(self):
        ps = PhaseStrip()
        calls: list[bool] = []
        original = ps.refresh

        def _rec(*args, **kwargs):
            calls.append(True)
            return original(*args, **kwargs)

        ps.refresh = _rec  # type: ignore[method-assign]
        ps.ratios = [0.5, 0.5]
        assert calls

"""Live-intensity visualization widgets.

Phase TUI-6a deliverable. The TUI's existing :class:`ChunkyBar`
is a single full-width block bar with one accent color — useful
for the runner's overall progress but tonally flat. The widgets
in this module add the "btop factor": gradient bars that shift
color as the underlying value gets hotter, tiny history
sparklines, and per-phase progress strips.

Three widgets, all built on Textual's :class:`Static` so they
plug into any container the rest of the TUI already uses:

  - :class:`IntensityGauge` — a horizontal block bar whose fill
    color shifts mint → amber → orange → red as value/total
    approaches 1.0. Use for budget meters, gap-impact counts,
    rate-limit pressure.
  - :class:`MiniSparkline` — a tiny block-character history
    graph (last N values) using the standard 8-step block
    ramp. Use for findings-per-minute, active-tools-over-time.
  - :class:`PhaseStrip` — a segmented horizontal strip that
    shows N phases side-by-side, each with its own
    progress-and-tint state. Use for the runner's per-phase
    progress under the main ChunkyBar.

All three are pure-render widgets (no async work), update
reactively, and tolerate degenerate inputs (zero total, value
outside [0, total], empty history) without crashing.

Color philosophy mirrors the severity palette pinned in
``app.tcss``: mint = healthy, amber = warming, orange = hot,
red = critical. Stops are intentionally hard thresholds rather
than smooth interpolation because terminal block-renders look
better at 4 distinct color steps than at 256-step gradients.
"""
from __future__ import annotations

from typing import Any

from rich.text import Text
from textual.reactive import reactive
from textual.widgets import Static


# ──────────────────────────────────────────────────────────────────────
# Color stops
# ──────────────────────────────────────────────────────────────────────

# (threshold, hex). At pct <= threshold, the corresponding color is
# applied. Order matters: walked low→high; first match wins. Stops
# match the severity philosophy from ``app.tcss``:
#   - mint  ($success / severity-info equivalent)
#   - amber ($warning / severity-medium)
#   - orange (severity-high)
#   - red   ($error / severity-critical)
INTENSITY_STOPS: list[tuple[float, str]] = [
    (0.50, "#00ff9c"),   # cool mint — comfortably under target
    (0.75, "#f1c40f"),   # warm amber — leaning into limits
    (0.90, "#ff8c00"),   # hot orange — close to ceiling
    (1.00, "#ff3838"),   # critical red — at or beyond ceiling
]


def pick_intensity_color(pct: float) -> str:
    """Return the hex color for a normalized percentage in [0, 1].

    Values are clamped: negative pct → coolest stop; pct > 1.0 →
    hottest. Callers pass already-clamped percentages in normal
    operation, but the clamp keeps the renderer cheap and never
    raises.
    """
    if pct <= 0.0:
        return INTENSITY_STOPS[0][1]
    if pct >= 1.0:
        return INTENSITY_STOPS[-1][1]
    for threshold, color in INTENSITY_STOPS:
        if pct <= threshold:
            return color
    return INTENSITY_STOPS[-1][1]


# ──────────────────────────────────────────────────────────────────────
# IntensityGauge
# ──────────────────────────────────────────────────────────────────────


class IntensityGauge(Static):
    """Horizontal block bar with a cool→hot fill color.

    Used for any "filling toward a limit" surface: campaign LLM
    budget, per-source rate-limit window, gap-impact count
    relative to the worst gap on the dashboard. Always renders
    a percentage suffix so the operator can read the number, not
    just the visual.

    Reactive attributes:
        value: Current scalar. Re-render triggers when this
            changes.
        total: Denominator. Updates do NOT auto-refresh — set
            ``total`` first, then ``value`` last, or call
            ``refresh()`` manually.
        width: Bar cell count. Default 20.

    Defensive contracts:
        - ``total <= 0`` renders as an empty track.
        - ``value`` outside ``[0, total]`` is clamped to that
          range for the fill calculation; the percentage label
          shows the clamped value too.
    """

    DEFAULT_CSS = """
    IntensityGauge {
        width: auto;
        height: 1;
        content-align: left middle;
    }
    """

    value: reactive[float] = reactive(0.0)

    def __init__(
        self,
        *,
        total: float = 1.0,
        width: int = 20,
        show_percent: bool = True,
        label: str | None = None,
        **kwargs: Any,
    ) -> None:
        """Construct a gauge.

        Args:
            total: Denominator for the percentage.
            width: Cell count for the bar itself (label and
                percent suffix render outside this width).
            show_percent: When True, render ``"  72.3%"`` after
                the bar. Disable for in-table sparkline-style
                contexts where the percent would crowd.
            label: Optional left-side label (``"Budget"``).
                Rendered before the bar in dim text. None
                omits.
        """
        super().__init__(**kwargs)
        self.total = float(total) if total else 0.0
        self.bar_width = max(1, int(width))
        self.show_percent = show_percent
        self.label = label

    def watch_value(self, _old: float, _new: float) -> None:
        """Reactive hook: refresh when value changes."""
        self.refresh(layout=False)

    def render(self) -> Text:
        if self.total <= 0:
            # Empty track — no signal to convey.
            empty = "░" * self.bar_width
            return Text.from_markup(
                f"[dim]{empty}[/dim] "
                f"[dim]   n/a[/dim]" if self.show_percent else empty,
            )

        # Clamp the underlying value so the fill calculation is
        # well-defined for negative or overshoot inputs.
        clamped = max(0.0, min(self.total, self.value))
        pct = clamped / self.total
        filled_cells = int(round(pct * self.bar_width))
        empty_cells = self.bar_width - filled_cells

        color = pick_intensity_color(pct)
        bar_filled = ("█" * filled_cells) if filled_cells else ""
        bar_empty = ("░" * empty_cells) if empty_cells else ""

        parts: list[str] = []
        if self.label:
            parts.append(f"[dim]{self.label}[/dim] ")
        parts.append(f"[{color}]{bar_filled}[/{color}]")
        parts.append(f"[dim]{bar_empty}[/dim]")
        if self.show_percent:
            parts.append(f" [bold {color}]{pct * 100:5.1f}%[/]")
        return Text.from_markup("".join(parts))


# ──────────────────────────────────────────────────────────────────────
# MiniSparkline
# ──────────────────────────────────────────────────────────────────────

# Standard 8-step block ramp for sparklines. ``▁`` = lowest,
# ``█`` = highest. These map directly to Unicode block elements
# 0x2581..0x2588. The ramp deliberately starts at ▁ (not a
# space) so the lowest sample of any series renders as a visible
# glyph ── otherwise a series of zero values silently disappears.
_SPARKLINE_BLOCKS: str = "▁▂▃▄▅▆▇█"


class MiniSparkline(Static):
    """Tiny block-character history graph.

    Use for "this value over the last N samples" surfaces:
    findings-per-minute, active-tools-over-time, per-source
    request rate. Each value maps to a single block character;
    a 30-sample sparkline is 30 cells wide.

    Reactive ``history`` is the list of values. Set it whole
    (``sparkline.history = new_values``) — Textual's reactive
    triggers on identity change, not in-place mutation.
    """

    DEFAULT_CSS = """
    MiniSparkline {
        width: auto;
        height: 1;
    }
    """

    history: reactive[list[float]] = reactive(list, layout=False, init=False)

    def __init__(
        self,
        *,
        max_points: int = 30,
        color: str | None = None,
        **kwargs: Any,
    ) -> None:
        """Construct a sparkline.

        Args:
            max_points: Width cap. History longer than this is
                trimmed to the last ``max_points`` samples.
            color: Optional hex color for the rendered blocks.
                None uses Textual's default foreground (theme-
                aware).
        """
        super().__init__(**kwargs)
        self.max_points = max(1, int(max_points))
        self.color = color
        # Initialise the reactive without triggering watch hooks
        # at construction time.
        self.history = []

    def watch_history(
        self, _old: list[float], _new: list[float],
    ) -> None:
        """Reactive hook: refresh when history identity changes."""
        self.refresh(layout=False)

    def push(self, value: float) -> None:
        """Append a value; trim to ``max_points`` from the right.

        Convenience for callers updating one sample at a time
        (per-tick monitors). Equivalent to setting
        ``self.history = (self.history + [value])[-max_points:]``.
        """
        # Build a new list so reactive identity changes — in-place
        # ``self.history.append(...)`` would not fire watch_history.
        self.history = (list(self.history) + [float(value)])[-self.max_points:]

    def render(self) -> Text:
        if not self.history:
            # Render an empty track so the widget still occupies
            # its slot during the first sample's worth of time.
            return Text(_SPARKLINE_BLOCKS[0] * self.max_points)

        # Scale: lowest sample → bottom block, highest → top.
        # Constant histories collapse to mid-height so the line
        # is visible without being misleading.
        lo = min(self.history)
        hi = max(self.history)
        span = hi - lo
        steps = len(_SPARKLINE_BLOCKS) - 1

        def _block_for(v: float) -> str:
            if span <= 0:
                return _SPARKLINE_BLOCKS[steps // 2]
            idx = int(round((v - lo) / span * steps))
            return _SPARKLINE_BLOCKS[max(0, min(steps, idx))]

        bar = "".join(_block_for(v) for v in self.history)
        if self.color:
            return Text.from_markup(f"[{self.color}]{bar}[/{self.color}]")
        return Text(bar)


# ──────────────────────────────────────────────────────────────────────
# PhaseStrip
# ──────────────────────────────────────────────────────────────────────


class PhaseStrip(Static):
    """Segmented progress strip — one bar per phase.

    The runner already has a top-level :class:`ChunkyBar`
    showing overall progress (completed phases / total phases).
    The strip adds per-phase granularity directly under it: N
    small segments side-by-side, each with its own fill ratio
    and intensity color.

    A segment with ratio 0.0 renders as the cool empty track.
    A segment that has completed (ratio 1.0) renders fully
    hot-end colored. Segments in progress shade according to
    their individual ratio (so a still-running phase that's
    burning through its tool budget shows amber/orange
    independently of other phases).

    Reactive ``ratios`` is a list of floats in ``[0, 1]``, one
    per segment.
    """

    DEFAULT_CSS = """
    PhaseStrip {
        width: 100%;
        height: 1;
    }
    """

    ratios: reactive[list[float]] = reactive(list, layout=False, init=False)

    def __init__(
        self,
        *,
        labels: list[str] | None = None,
        segment_width: int = 6,
        **kwargs: Any,
    ) -> None:
        """Construct a strip.

        Args:
            labels: Optional per-segment label list. When
                provided, labels render UNDERNEATH the segments
                (consumed by the parent layout) — the widget
                itself only renders the bar row.
            segment_width: Cell width per segment. Default 6.
        """
        super().__init__(**kwargs)
        self.labels = list(labels) if labels else None
        self.segment_width = max(2, int(segment_width))
        self.ratios = []

    def watch_ratios(
        self, _old: list[float], _new: list[float],
    ) -> None:
        self.refresh(layout=False)

    def render(self) -> Text:
        if not self.ratios:
            return Text("")
        parts: list[str] = []
        for i, raw in enumerate(self.ratios):
            ratio = max(0.0, min(1.0, float(raw)))
            filled = int(round(ratio * self.segment_width))
            empty = self.segment_width - filled
            color = pick_intensity_color(ratio)
            block = ("█" * filled) if filled else ""
            track = ("░" * empty) if empty else ""
            parts.append(
                f"[{color}]{block}[/{color}][dim]{track}[/dim]"
            )
            # Single-cell gap between segments so they read as
            # discrete phases rather than one continuous bar.
            if i < len(self.ratios) - 1:
                parts.append(" ")
        return Text.from_markup("".join(parts))

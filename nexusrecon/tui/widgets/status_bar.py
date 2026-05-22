"""Persistent status-bar widget.

Lives at the top of every screen. Surfaces the always-on operator
context: NexusRecon version, current activity ("Idle" or the active
campaign's target), tool / availability counters, LLM provider,
budget gauge (when a campaign is running). Refreshes every second so
the elapsed-time and cost figures stay live without manual remount.

Spec ref: ``docs/TUI_DESIGN_SPEC.md§5.6``.

Sample idle render::

    NEXUSRECON v0.5.0  •  Idle  •  97 tools / 81 active / 1 stub  •  opus-4-7  •  $0.00 budget

Sample active-campaign render::

    NEXUSRECON v0.5.0  •  juice-shop.herokuapp.com  •  Phase 4/10  •  [████░░░░] $4.23 / $20.00  •  ●● 23

The widget is *informational only* — keypresses on the underlying
screen still drive navigation. There's no focus state.
"""
from __future__ import annotations

from typing import Any

from textual.widgets import Static

# ──────────────────────────────────────────────────────────────────────
# Cheap state readers
# ──────────────────────────────────────────────────────────────────────


def _read_app_state(app: Any) -> dict[str, Any]:
    """Best-effort: pull the live campaign state off the app.

    The runner screen attaches an in-progress campaign to
    ``app.active_campaign`` (set by TUI-4 follow-up). For now the
    field may not exist; we treat ``None`` as "idle". Reads are
    defensive — the status bar must never crash the screen on a
    missing attribute.
    """
    active = getattr(app, "active_campaign", None)
    if not isinstance(active, dict):
        return {"idle": True}
    return {
        "idle": False,
        "target": active.get("target", ""),
        "phase_label": active.get("phase_label", ""),
        "phase_index": active.get("phase_index"),
        "phase_total": active.get("phase_total"),
        "llm_cost_usd": float(active.get("llm_cost_usd", 0.0) or 0.0),
        "budget_usd": float(active.get("budget_usd", 0.0) or 0.0),
        "finding_count": int(active.get("finding_count", 0) or 0),
    }


def _read_tool_counts() -> tuple[int, int, int]:
    """Return ``(total, active, stubbed)`` for the registered tools."""
    try:
        from nexusrecon.tools.registry import get_registry
        total = 0
        active = 0
        stubbed = 0
        for tool in get_registry()._tools.values():
            total += 1
            if getattr(tool, "stubbed", False):
                stubbed += 1
                continue
            if tool.is_available():
                active += 1
        return total, active, stubbed
    except Exception:
        return 0, 0, 0


def _read_llm_provider() -> str:
    try:
        from nexusrecon.core.config import get_config
        return get_config().llm_provider or "unknown"
    except Exception:
        return "unknown"


def _read_version() -> str:
    try:
        from nexusrecon import __version__
        return __version__
    except Exception:
        return "?.?.?"


# ──────────────────────────────────────────────────────────────────────
# Render helpers
# ──────────────────────────────────────────────────────────────────────


def _render_gauge(value: float, total: float, width: int = 10) -> str:
    """Tiny in-line block bar. Empty when ``total <= 0``."""
    if total <= 0:
        return "[░░░░░░░░░░]"
    pct = max(0.0, min(1.0, value / total))
    filled = int(round(pct * width))
    return "[" + ("█" * filled) + ("░" * (width - filled)) + "]"


def render_status_bar(
    *,
    active_state: dict[str, Any] | None = None,
    tool_counts: tuple[int, int, int] | None = None,
    llm_provider: str | None = None,
    version: str | None = None,
) -> str:
    """Pure-function version of the status-bar contents.

    The widget renders by stamping the result into a Static. Pulled
    out so tests can pin the exact string output for a given
    state without spinning up Textual.

    The dependency-injection signature (every input optional +
    None-triggers-default-read) means tests pass a complete state
    snapshot, but the live widget can call this with everything
    None and get a real snapshot from the running app.
    """
    if active_state is None:
        active_state = {"idle": True}
    if tool_counts is None:
        tool_counts = _read_tool_counts()
    if llm_provider is None:
        llm_provider = _read_llm_provider()
    if version is None:
        version = _read_version()

    total, active, stubbed = tool_counts
    if total > 0:
        tool_segment = f"{total} tools / {active} active"
        if stubbed:
            tool_segment += f" / {stubbed} stub"
    else:
        tool_segment = "(no tools loaded)"

    parts: list[str] = [
        f"[bold $primary]NEXUSRECON[/bold $primary] v{version}",
    ]

    if active_state.get("idle"):
        parts.append("[dim]Idle[/dim]")
        parts.append(tool_segment)
        parts.append(f"LLM: [bold]{llm_provider}[/bold]")
        parts.append("[dim]$0.00 budget[/dim]")
    else:
        target = active_state.get("target") or "(no target)"
        phase_label = active_state.get("phase_label") or ""
        phase_index = active_state.get("phase_index")
        phase_total = active_state.get("phase_total")
        if phase_index is not None and phase_total:
            phase_segment = f"Phase {phase_index}/{phase_total}"
        else:
            phase_segment = phase_label or "running"

        cost = active_state.get("llm_cost_usd", 0.0)
        budget = active_state.get("budget_usd", 0.0)
        gauge = _render_gauge(cost, budget) if budget else ""
        cost_label = f"${cost:.2f}"
        if budget > 0:
            cost_label += f" / ${budget:.2f}"

        parts.append(f"[bold]{target}[/bold]")
        parts.append(f"[$secondary]{phase_segment}[/$secondary]")
        if gauge:
            parts.append(f"{gauge} {cost_label}")
        else:
            parts.append(cost_label)
        findings = active_state.get("finding_count", 0)
        if findings:
            parts.append(f"[$warning]●● {findings}[/$warning]")

    return "  •  ".join(parts)


# ──────────────────────────────────────────────────────────────────────
# Widget
# ──────────────────────────────────────────────────────────────────────


class StatusBar(Static):
    """One-line live status bar.

    Mount at the top of every screen via composition::

        def compose(self) -> ComposeResult:
            yield StatusBar()
            ...

    Refreshes itself on a 1-second interval. The interval is
    cancelled automatically when the widget unmounts (Textual's
    set_interval owns the lifecycle).

    Implementation note: subclasses :class:`Static` directly rather
    than wrapping one inside a container. Wrapping turned out to
    confuse Textual's render tree (a wrapped Static child rendered
    as a bare string the parent tried to lay out), so the
    simplest viable shape is "the widget IS the renderable".
    """

    DEFAULT_CSS = """
    StatusBar {
        height: 1;
        width: 100%;
        background: $background;
        color: $foreground;
        padding: 0 1;
    }
    """

    #: Refresh cadence in seconds. 1.0 matches the runner's stats
    #: panel so on-screen numbers tick in sync.
    REFRESH_SECONDS: float = 1.0

    def on_mount(self) -> None:
        # Paint immediately so the operator never sees an empty bar
        # on first frame; the periodic refresh keeps it current.
        self.update(self._compose_text())
        try:
            self.set_interval(self.REFRESH_SECONDS, self._refresh)
        except Exception:
            pass

    def _refresh(self) -> None:
        try:
            self.update(self._compose_text())
        except Exception:
            pass

    def _compose_text(self) -> str:
        """Build the current text payload.

        Named ``_compose_text`` (not ``_render``) on purpose: Textual's
        Widget base class uses ``_render`` as an internal method that
        must return a Visual, not a string. Overriding it with a
        string-returning method silently breaks rendering with an
        ``AttributeError: 'str' object has no attribute 'render_strips'``
        the moment Textual tries to lay the widget out. Cost me an
        afternoon during TUI-3; keep the name.
        """
        try:
            state = _read_app_state(self.app)
        except Exception:
            state = {"idle": True}
        return render_status_bar(active_state=state)

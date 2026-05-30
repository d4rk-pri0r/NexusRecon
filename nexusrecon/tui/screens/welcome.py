"""Backwards-compat shim for the old WelcomeScreen module.

TUI-3 replaced the welcome screen with the new
:class:`~nexusrecon.tui.screens.dashboard.DashboardScreen` (status
bar + sidebar + recent campaigns table). This module re-exports the
new class under the legacy name AND the helper functions the old
TUI-1 tests imported, so any external code (tests, plugin authors,
custom launchers) that still imports from this module keeps working
without modification.

Operator-facing behaviour is unchanged: the dashboard mounts on
app startup; only the class lineage and the location of the helper
functions changed.
"""
from __future__ import annotations

from nexusrecon.tui.screens.dashboard import (
    DashboardScreen,
    _persist_onboarding_dismissal,
    _should_show_onboarding,
)

# The original class name. Anything importing WelcomeScreen gets the
# Dashboard ── identical bindings + menu actions, richer layout.
WelcomeScreen = DashboardScreen


# ──────────────────────────────────────────────────────────────────────
# Helper re-exports
# ──────────────────────────────────────────────────────────────────────
# These names existed on the original welcome.py module and are
# referenced by tests + (potentially) external plugin code. The
# implementation lives in ``dashboard.py``; re-exporting under the
# old names keeps import-by-name compatible.


def _quick_stats() -> str:
    """Top-line: ``X tools registered · Y campaigns · LLM provider``."""
    from pathlib import Path

    tool_count = 0
    campaigns_on_disk = 0
    llm_provider = "unknown"
    try:
        from nexusrecon.tools.registry import get_registry
        tool_count = len(get_registry()._tools)
    except Exception:
        pass
    try:
        from nexusrecon.core.config import get_config
        cfg = get_config()
        llm_provider = cfg.llm_provider
        out_dir = Path(cfg.output_dir)
        if out_dir.exists():
            campaigns_on_disk = sum(1 for _ in out_dir.rglob("state.json"))
    except Exception:
        pass
    return (
        f"{tool_count} tools registered · "
        f"{campaigns_on_disk} campaign(s) on disk · "
        f"LLM provider: {llm_provider}"
    )


def _tool_availability_breakdown() -> str:
    """``N active · M missing keys · K missing binaries``. The original
    TUI-1 string format (leads with active, no total, unlike the
    dashboard's ``_tool_breakdown``), now sourced from the F-A3
    ``availability_report`` so a missing binary is not mislabelled as a
    missing key."""
    try:
        from nexusrecon.tools.registry import get_registry
        counts = get_registry().availability_report()["counts"]
        active = counts.get("active", 0)
        need_keys = counts.get("missing_key", 0)
        need_install = counts.get("missing_binary", 0)
        stubbed = counts.get("stubbed", 0)
        parts = [f"{active} active"]
        if need_keys:
            parts.append(f"{need_keys} missing keys")
        if need_install:
            parts.append(f"{need_install} missing binaries")
        if stubbed:
            parts.append(f"{stubbed} stub(s)")
        return " · ".join(parts)
    except Exception:
        return ""


def _last_campaign_hint() -> str:
    """``Last run: <when> · <seed-or-id>`` (empty when no campaigns)."""
    from datetime import UTC, datetime
    from pathlib import Path

    try:
        from nexusrecon.core.config import get_config
        cfg = get_config()
        out_dir = Path(cfg.output_dir)
        if not out_dir.exists():
            return ""
        candidates = list(out_dir.rglob("state.json"))
        if not candidates:
            return ""
        latest = max(candidates, key=lambda p: p.stat().st_mtime)
        when = datetime.fromtimestamp(latest.stat().st_mtime, tz=UTC)
        label = latest.parent.name
        try:
            import json
            data = json.loads(latest.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                seeds = data.get("seeds") or []
                if isinstance(seeds, list) and seeds:
                    label = str(seeds[0])
                elif data.get("campaign_id"):
                    label = str(data["campaign_id"])
        except Exception:
            pass
        return f"Last run: {_human_when(when)} · {label}"
    except Exception:
        return ""


def _human_when(when) -> str:
    from datetime import UTC, datetime

    try:
        now = datetime.now(UTC)
        diff = (now - when).total_seconds()
        if diff < 60:
            return "just now"
        if diff < 3600:
            return f"{int(diff // 60)}m ago"
        if diff < 86400:
            return f"{int(diff // 3600)}h ago"
        if diff < 86400 * 2:
            return "yesterday"
        if diff < 86400 * 7:
            return f"{int(diff // 86400)}d ago"
        return when.strftime("%Y-%m-%d")
    except Exception:
        return "earlier"


__all__ = [
    "WelcomeScreen",
    "_quick_stats",
    "_tool_availability_breakdown",
    "_last_campaign_hint",
    "_should_show_onboarding",
    "_persist_onboarding_dismissal",
]

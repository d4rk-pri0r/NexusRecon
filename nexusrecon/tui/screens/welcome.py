"""Welcome screen — banner, live status panel, main menu.

The welcome screen is the operator's first impression and the only
place the splash-style branding ships. TUI-1 polish layered on top
of the original 0.5.x version:

  - **Live status line** refreshes every 5 seconds instead of
    snapshotting once on mount. After a campaign completes the
    "Last run" indicator updates without an app restart.
  - **Tools breakdown** surfaces "N active · M skipped (missing
    keys)" so the operator sees the configuration health at a
    glance ── closes the roadmap "first-run UX polish" item.
  - **First-run onboarding nudge** appears when the framework
    detects no past campaigns AND no LLM provider key configured.
    Dismissed automatically the first time the operator opens the
    Config screen, OR persistently if they tap ``d``.
  - **Help overlay** triggered by ``?`` — inherited from the App
    binding, listed in the menu hint for discoverability.
"""
from __future__ import annotations

import asyncio
from datetime import UTC
from pathlib import Path

from textual import work
from textual.app import ComposeResult
from textual.containers import Center, Container, Vertical
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Static

from nexusrecon.tui.banner import (
    render_attribution,
    render_banner,
    render_version,
)

# ──────────────────────────────────────────────────────────────────────
# Cheap status snapshots
# ──────────────────────────────────────────────────────────────────────


def _quick_stats() -> str:
    """Top stats line — tools registered, campaigns on disk, LLM provider.

    Cheap enough to run on every refresh (5-second cadence). Reads
    only from in-process state + a single directory scan.
    """
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
    """Second stats line — "N active · M skipped (missing keys)".

    Closes the roadmap first-run UX item ── operators see at launch
    how many tools are functional vs gated on a missing API key.
    """
    try:
        from nexusrecon.tools.registry import get_registry
        registry = get_registry()
        total = 0
        active = 0
        stubbed = 0
        for tool in registry._tools.values():
            total += 1
            if getattr(tool, "stubbed", False):
                stubbed += 1
                continue
            if tool.is_available():
                active += 1
        skipped = total - active - stubbed
        parts = [f"{active} active"]
        if skipped:
            parts.append(f"{skipped} skipped (missing keys)")
        if stubbed:
            parts.append(f"{stubbed} stub(s)")
        return " · ".join(parts)
    except Exception:
        return ""


def _last_campaign_hint() -> str:
    """Third stats line — most recent campaign on disk.

    Format: ``Last run: <when> · <seed-or-id>``. Returns an empty
    string when no campaigns have run yet so the welcome screen
    stays clean on fresh installs (the first-run nudge handles
    that case separately).
    """
    try:
        from datetime import datetime

        from nexusrecon.core.config import get_config
        cfg = get_config()
        out_dir = Path(cfg.output_dir)
        if not out_dir.exists():
            return ""
        candidates = list(out_dir.rglob("state.json"))
        if not candidates:
            return ""
        # Pick the most-recently-modified state.json.
        latest = max(candidates, key=lambda p: p.stat().st_mtime)
        when = datetime.fromtimestamp(latest.stat().st_mtime, tz=UTC)
        # Try to read a useful label from the state file (campaign_id
        # or seeds). Fall back to the parent directory name.
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
    """Render a datetime as a relative-ish string (``2h ago``,
    ``yesterday``, ``2026-05-19``)."""
    try:
        from datetime import datetime
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


def _should_show_onboarding() -> bool:
    """First-run heuristic: no past campaigns AND no LLM key.

    The persistent dismissal flag lives at
    ``~/.nexusrecon/.onboarding_dismissed``. If the file exists
    we never show the nudge again, regardless of state.
    """
    try:
        flag = Path.home() / ".nexusrecon" / ".onboarding_dismissed"
        if flag.exists():
            return False
        from nexusrecon.core.config import get_config
        cfg = get_config()
        out_dir = Path(cfg.output_dir)
        has_campaigns = (
            out_dir.exists()
            and any(out_dir.rglob("state.json"))
        )
        if has_campaigns:
            return False
        # No campaigns yet — check whether an LLM provider key is set.
        # The exact secret name depends on the provider but the
        # heuristic is: if get_secret returns anything for the
        # default-provider key, we treat the operator as configured.
        for key in ("anthropic_api_key", "openai_api_key"):
            if cfg.get_secret(key):
                return False
        return True
    except Exception:
        return False


def _persist_onboarding_dismissal() -> None:
    """Mark the onboarding nudge as permanently dismissed."""
    try:
        flag_dir = Path.home() / ".nexusrecon"
        flag_dir.mkdir(parents=True, exist_ok=True)
        (flag_dir / ".onboarding_dismissed").touch()
    except Exception:
        pass


# ──────────────────────────────────────────────────────────────────────
# Screen
# ──────────────────────────────────────────────────────────────────────


class WelcomeScreen(Screen):
    """Splash + main menu.

    Keyboard-first: ↑/↓ cycle focus through the menu buttons; the letter
    shortcuts (n/r/p/c/t/q) fire each option directly without needing
    to focus its button first. The first button is focused on mount so
    a single Enter launches the highlighted item.
    """

    BINDINGS = [
        ("n", "menu_new", "New Campaign"),
        ("r", "menu_resume", "Resume"),
        ("p", "menu_past", "Past"),
        ("c", "menu_config", "Config"),
        ("t", "menu_tools", "Tools"),
        ("d", "dismiss_onboarding", "Dismiss nudge"),
        ("q", "quit_app", "Quit"),
        ("ctrl+q", "quit_app", "Quit"),
        ("escape", "quit_app", "Quit"),
        ("up", "focus_prev", "↑"),
        ("down", "focus_next_btn", "↓"),
    ]

    # Refresh cadence for the live status block. 5 seconds is slow
    # enough to be free (one directory scan + registry walk) and fast
    # enough that the "Last run" indicator catches up shortly after a
    # campaign completes.
    REFRESH_SECONDS: float = 5.0

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        with Container(id="welcome-content"):
            with Vertical(id="welcome-stack"):
                with Center():
                    yield Static(render_banner(), id="welcome-banner")
                version_text = render_version()
                if version_text:
                    with Center():
                        yield Static(version_text, id="welcome-version")
                attribution_text = render_attribution()
                if attribution_text:
                    with Center():
                        yield Static(attribution_text, id="welcome-attribution")
                with Center():
                    yield Static(
                        "Agentic OSINT Orchestration Framework",
                        id="welcome-subtitle",
                    )
                with Center():
                    yield Static(_quick_stats(), id="welcome-stats")
                # Tool availability + last-campaign hint live in their
                # own Statics so the periodic refresh job can swap
                # their text independently without re-rendering the
                # rest of the layout.
                with Center():
                    yield Static(_tool_availability_breakdown(), id="welcome-availability")
                with Center():
                    yield Static(_last_campaign_hint(), id="welcome-status")
                if _should_show_onboarding():
                    with Center():
                        yield Static(
                            "👋  First time? Press [bold]c[/bold] to "
                            "open Configuration and add an LLM provider "
                            "key. ([dim]d[/dim] to dismiss)",
                            id="welcome-onboarding",
                        )
                with Center():
                    yield Static(
                        "[dim]↑/↓ navigate · Enter select · "
                        "n/r/p/c/t quick · ? help · q quit[/dim]",
                        id="welcome-hint",
                    )
                with Center():
                    with Vertical(id="welcome-menu"):
                        yield Button("🎯  New Campaign  (n)", id="btn-new", classes="-primary")
                        yield Button("🔄  Resume Campaign  (r)", id="btn-resume")
                        yield Button("📊  View Past Campaigns  (p)", id="btn-past")
                        yield Button("🔧  Configuration  (c)", id="btn-config")
                        yield Button("🛠   Tools  (t)", id="btn-tools")
                        yield Button("❌  Quit  (q)", id="btn-quit")
        yield Footer()

    def on_mount(self) -> None:
        try:
            self.query_one("#btn-new", Button).focus()
        except Exception:
            pass
        self._warm_imports()
        # Kick off the periodic refresh so the status block stays
        # accurate without a manual remount. Textual's set_interval
        # returns a Timer; we don't need the handle because the
        # screen's lifecycle owns it.
        try:
            self.set_interval(self.REFRESH_SECONDS, self._refresh_status)
        except Exception:
            # Older Textual versions in tests sometimes mock set_interval —
            # missing refresh shouldn't break the screen.
            pass

    def _refresh_status(self) -> None:
        """Re-render the live status block. Called every
        :attr:`REFRESH_SECONDS` from the periodic timer.

        Each Static is updated independently so a no-op
        (text unchanged) is essentially free. Onboarding nudge
        appears/disappears as state changes ── once an operator
        configures a key OR runs a campaign, the nudge auto-vanishes
        on the next tick."""
        try:
            self.query_one("#welcome-stats", Static).update(_quick_stats())
        except Exception:
            pass
        try:
            self.query_one("#welcome-availability", Static).update(
                _tool_availability_breakdown(),
            )
        except Exception:
            pass
        try:
            self.query_one("#welcome-status", Static).update(
                _last_campaign_hint(),
            )
        except Exception:
            pass
        # Onboarding nudge auto-hides when the user has configured a
        # key. We can't add/remove a widget cleanly mid-screen, so
        # we just blank its text when the trigger goes away.
        try:
            nudge = self.query_one("#welcome-onboarding", Static)
            if not _should_show_onboarding():
                nudge.update("")
        except Exception:
            # Widget doesn't exist (not first-run state); nothing to do.
            pass

    @work(thread=True, exclusive=True, group="warmup")
    def _warm_imports(self) -> None:
        """Background warm-up of heavy imports the runner needs."""
        try:
            import nexusrecon.core.campaign  # noqa: F401
            import nexusrecon.core.campaign_runner  # noqa: F401
            import nexusrecon.core.scope  # noqa: F401
            import nexusrecon.graph.dynamic_dispatcher  # noqa: F401
            import nexusrecon.graph.workflow  # noqa: F401
            import nexusrecon.models.campaign  # noqa: F401
            import nexusrecon.reports.engine  # noqa: F401
            import nexusrecon.tools.registry  # noqa: F401
        except Exception:
            pass

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        mapping = {
            "btn-new": self.action_menu_new,
            "btn-resume": self.action_menu_resume,
            "btn-past": self.action_menu_past,
            "btn-config": self.action_menu_config,
            "btn-tools": self.action_menu_tools,
            "btn-quit": self.action_quit_app,
        }
        handler = mapping.get(event.button.id or "")
        if handler is None:
            return
        result = handler()
        if asyncio.iscoroutine(result):
            await result

    # ── Actions ─────────────────────────────────────────────────────

    async def action_menu_new(self) -> None:
        from nexusrecon.tui.screens.wizard import WizardScreen
        await self.app.push_screen(WizardScreen())

    async def action_menu_resume(self) -> None:
        from nexusrecon.tui.screens.campaigns import CampaignsScreen
        await self.app.push_screen(CampaignsScreen(resume_mode=True))

    async def action_menu_past(self) -> None:
        from nexusrecon.tui.screens.campaigns import CampaignsScreen
        await self.app.push_screen(CampaignsScreen(resume_mode=False))

    async def action_menu_config(self) -> None:
        # Opening Config implicitly dismisses the first-run nudge ──
        # the operator is already on the right path.
        _persist_onboarding_dismissal()
        from nexusrecon.tui.screens.config import ConfigScreen
        await self.app.push_screen(ConfigScreen())

    async def action_menu_tools(self) -> None:
        from nexusrecon.tui.screens.config import ToolsScreen
        await self.app.push_screen(ToolsScreen())

    def action_quit_app(self) -> None:
        self.app.exit()

    def action_dismiss_onboarding(self) -> None:
        """Explicit ``d`` keystroke ── permanently hide the first-run
        nudge. The same effect happens implicitly when the operator
        opens the Config screen."""
        _persist_onboarding_dismissal()
        try:
            self.query_one("#welcome-onboarding", Static).update("")
        except Exception:
            pass

    def action_focus_prev(self) -> None:
        try:
            self.focus_previous()
        except Exception:
            pass

    def action_focus_next_btn(self) -> None:
        try:
            self.focus_next()
        except Exception:
            pass

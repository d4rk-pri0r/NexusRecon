"""Dashboard screen — the operator's launchpad and persistent home.

Replaces the prior welcome screen as the primary view. Builds on
top of the TUI-1 / TUI-2 foundation:

  - **Persistent status bar** at the top (lives on every screen).
  - **Sidebar** rail on the left with navigation entries.
  - **Main content** in the centre: compact ASCII banner,
    promoted recent-campaigns list, quick-stats panel, recent
    activity, action hints.

The screen is the first visual NexusRecon shows after launch and
shapes the operator's entire mental model of the tool. Goal per the
spec: dense, useful, beautiful — an operations center, not a
splash screen.

Spec ref: ``docs/TUI_DESIGN_SPEC.md§6.1``.
"""
from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path

from textual import work
from textual.app import ComposeResult
from textual.containers import Center, Container, Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, DataTable, Footer, Header, Static

from nexusrecon.tui.banner import (
    render_attribution,
    render_banner,
    render_version,
)
from nexusrecon.tui.widgets import Sidebar, StatusBar

# ──────────────────────────────────────────────────────────────────────
# Cheap snapshot helpers
# ──────────────────────────────────────────────────────────────────────


def _recent_campaigns(limit: int = 5) -> list[dict]:
    """Return up to ``limit`` most-recently-modified campaign
    snapshots. Each entry is a dict suitable for direct rendering
    in the dashboard table.

    Defensive: returns an empty list on any error so the screen
    keeps rendering when no campaigns exist or the config can't
    be loaded."""
    try:
        from nexusrecon.core.config import get_config
        cfg = get_config()
        out_dir = Path(cfg.output_dir)
        if not out_dir.exists():
            return []
        states = list(out_dir.rglob("state.json"))
        if not states:
            return []
        states.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        rows: list[dict] = []
        for state_path in states[:limit]:
            entry = _summarise_campaign_dir(state_path)
            if entry:
                rows.append(entry)
        return rows
    except Exception:
        return []


def _summarise_campaign_dir(state_path: Path) -> dict | None:
    try:
        import json
        data = json.loads(state_path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return None
        seeds = data.get("seeds") or []
        target = (
            str(seeds[0])
            if isinstance(seeds, list) and seeds
            else state_path.parent.name
        )
        findings = data.get("findings") or []
        finding_count = len(findings) if isinstance(findings, list) else 0
        cost = float(data.get("llm_cost_usd", 0.0) or 0.0)
        completed = data.get("completed_phases") or []
        status_text = (
            "✓ done" if "phase9" in completed
            else f"partial · {len(completed)} phases"
        )
        when = datetime.fromtimestamp(state_path.stat().st_mtime, tz=UTC)
        return {
            "target": target,
            "when": when,
            "findings": finding_count,
            "cost": cost,
            "status": status_text,
            "path": str(state_path),
        }
    except Exception:
        return None


def _human_when(when: datetime) -> str:
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


def _tool_breakdown() -> str:
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
        parts = [f"{total} tools", f"{active} active"]
        if skipped:
            parts.append(f"{skipped} skipped (missing keys)")
        if stubbed:
            parts.append(f"{stubbed} stub(s)")
        return " · ".join(parts)
    except Exception:
        return ""


def _should_show_onboarding() -> bool:
    """Same first-run check the previous welcome screen used."""
    try:
        flag = Path.home() / ".nexusrecon" / ".onboarding_dismissed"
        if flag.exists():
            return False
        from nexusrecon.core.config import get_config
        cfg = get_config()
        out_dir = Path(cfg.output_dir)
        has_campaigns = (
            out_dir.exists() and any(out_dir.rglob("state.json"))
        )
        if has_campaigns:
            return False
        for key in ("anthropic_api_key", "openai_api_key"):
            if cfg.get_secret(key):
                return False
        return True
    except Exception:
        return False


def _persist_onboarding_dismissal() -> None:
    try:
        flag_dir = Path.home() / ".nexusrecon"
        flag_dir.mkdir(parents=True, exist_ok=True)
        (flag_dir / ".onboarding_dismissed").touch()
    except Exception:
        pass


# ──────────────────────────────────────────────────────────────────────
# Screen
# ──────────────────────────────────────────────────────────────────────


class DashboardScreen(Screen):
    """Operator's home screen.

    Keyboard model mirrors the original welcome screen so muscle
    memory carries over. Newcomers see the persistent shell
    (status bar + sidebar + main).
    """

    BINDINGS = [
        ("n", "menu_new", "New Campaign"),
        ("r", "menu_resume", "Resume"),
        ("p", "menu_past", "Past"),
        ("c", "menu_config", "Config"),
        ("t", "menu_tools", "Tools"),
        ("d", "dismiss_onboarding", "Dismiss nudge"),
        ("close_bracket", "toggle_sidebar", "Toggle sidebar"),
        ("q", "quit_app", "Quit"),
        ("ctrl+q", "quit_app", "Quit"),
        ("escape", "quit_app", "Quit"),
    ]

    REFRESH_SECONDS: float = 5.0

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        yield StatusBar()
        with Horizontal(id="dashboard-shell"):
            yield Sidebar(id="dashboard-sidebar")
            with Container(id="dashboard-main"):
                with Vertical(id="dashboard-stack"):
                    with Center():
                        yield Static(render_banner(), id="dashboard-banner")
                    version_text = render_version()
                    if version_text:
                        with Center():
                            yield Static(version_text, id="dashboard-version")
                    attribution_text = render_attribution()
                    if attribution_text:
                        with Center():
                            yield Static(
                                attribution_text, id="dashboard-attribution",
                            )
                    with Center():
                        yield Static(
                            "Agentic OSINT Orchestration Framework",
                            id="dashboard-subtitle",
                        )
                    # Recent campaigns table.
                    yield Static(
                        "[bold $primary]Recent campaigns[/bold $primary]",
                        id="dashboard-recents-title",
                    )
                    yield DataTable(
                        id="dashboard-recents",
                        zebra_stripes=True,
                        cursor_type="row",
                        show_cursor=False,
                    )
                    # Quick stats panel.
                    with Horizontal(id="dashboard-bottom"):
                        with Vertical(classes="dashboard-stat-card"):
                            yield Static(
                                "[bold $primary]Quick stats[/bold $primary]",
                                classes="dashboard-card-title",
                            )
                            yield Static(
                                _tool_breakdown(),
                                id="dashboard-tools",
                            )
                        with Vertical(classes="dashboard-stat-card"):
                            yield Static(
                                "[bold $primary]Actions[/bold $primary]",
                                classes="dashboard-card-title",
                            )
                            with Vertical(id="dashboard-menu"):
                                yield Button("🎯  New campaign  (n)",
                                              id="btn-new", classes="-primary")
                                yield Button("🔄  Resume last  (r)",
                                              id="btn-resume")
                                yield Button("📁  Browse past  (p)",
                                              id="btn-past")
                                yield Button("🛠   Tools  (t)", id="btn-tools")
                                yield Button("🔧  Config  (c)", id="btn-config")
                    if _should_show_onboarding():
                        with Center():
                            yield Static(
                                "👋  First time? Press [bold]c[/bold] to "
                                "open Configuration and add an LLM provider "
                                "key. ([dim]d[/dim] to dismiss)",
                                id="dashboard-onboarding",
                            )
                    with Center():
                        yield Static(
                            "[dim]↑/↓ navigate · Enter select · "
                            "n/r/p/c/t quick · Ctrl+P palette · "
                            "? help · ] sidebar · q quit[/dim]",
                            id="dashboard-hint",
                        )
        yield Footer()

    def on_mount(self) -> None:
        self._populate_recents()
        try:
            self.query_one("#btn-new", Button).focus()
        except Exception:
            pass
        self._warm_imports()
        try:
            self.set_interval(self.REFRESH_SECONDS, self._refresh)
        except Exception:
            pass

    # ── Refresh ─────────────────────────────────────────────────────

    def _refresh(self) -> None:
        try:
            self.query_one("#dashboard-tools", Static).update(_tool_breakdown())
        except Exception:
            pass
        self._populate_recents()
        try:
            nudge = self.query_one("#dashboard-onboarding", Static)
            if not _should_show_onboarding():
                nudge.update("")
        except Exception:
            pass

    def _populate_recents(self) -> None:
        try:
            table = self.query_one("#dashboard-recents", DataTable)
        except Exception:
            return
        table.clear(columns=True)
        table.add_columns("Target", "When", "Findings", "Cost", "Status")
        rows = _recent_campaigns(limit=5)
        if not rows:
            table.add_row(
                "[dim]No campaigns yet[/dim]",
                "—", "—", "—",
                "[dim]Press n to start[/dim]",
            )
            return
        for row in rows:
            table.add_row(
                row["target"],
                _human_when(row["when"]),
                str(row["findings"]),
                f"${row['cost']:.2f}",
                row["status"],
            )

    # ── Lazy heavy import pre-warm ──────────────────────────────────

    @work(thread=True, exclusive=True, group="warmup")
    def _warm_imports(self) -> None:
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

    # ── Button + key actions ────────────────────────────────────────

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        mapping = {
            "btn-new": self.action_menu_new,
            "btn-resume": self.action_menu_resume,
            "btn-past": self.action_menu_past,
            "btn-config": self.action_menu_config,
            "btn-tools": self.action_menu_tools,
        }
        handler = mapping.get(event.button.id or "")
        if handler is None:
            return
        result = handler()
        if asyncio.iscoroutine(result):
            await result

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
        _persist_onboarding_dismissal()
        from nexusrecon.tui.screens.config import ConfigScreen
        await self.app.push_screen(ConfigScreen())

    async def action_menu_tools(self) -> None:
        from nexusrecon.tui.screens.tools import ToolsScreen
        await self.app.push_screen(ToolsScreen())

    def action_quit_app(self) -> None:
        self.app.exit()

    def action_dismiss_onboarding(self) -> None:
        _persist_onboarding_dismissal()
        try:
            self.query_one("#dashboard-onboarding", Static).update("")
        except Exception:
            pass

    def action_toggle_sidebar(self) -> None:
        """``]`` shortcut — collapse / expand the sidebar."""
        try:
            self.query_one("#dashboard-sidebar", Sidebar).toggle_collapsed()
        except Exception:
            pass

"""Welcome screen — banner, status line, and main menu."""
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from textual import work
from textual.app import ComposeResult
from textual.containers import Center, Container, Vertical
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Static

from nexusrecon.tui.banner import (
    render_banner,
    render_version,
    render_attribution,
)


def _quick_stats() -> str:
    """Cheap startup stats — registered tools, campaigns on disk, LLM provider."""
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


class WelcomeScreen(Screen):
    """Splash + main menu.

    Keyboard-first: ↑/↓ cycle focus through the menu buttons; the letter
    shortcuts (n/r/p/c/t/q) fire each option directly without needing to
    focus its button first. The first button is focused on mount so a
    single Enter launches the highlighted item.
    """

    # Letter shortcuts ARE the keyboard menu. ↑/↓ cycle focus through the
    # buttons so the visible highlight follows the user's selection. Footer
    # auto-renders these so the operator sees them at the bottom of the screen.
    BINDINGS = [
        ("n", "menu_new", "New Campaign"),
        ("r", "menu_resume", "Resume"),
        ("p", "menu_past", "Past"),
        ("c", "menu_config", "Config"),
        ("t", "menu_tools", "Tools"),
        ("q", "quit_app", "Quit"),
        ("ctrl+q", "quit_app", "Quit"),
        ("escape", "quit_app", "Quit"),
        ("up", "focus_prev", "↑"),
        ("down", "focus_next_btn", "↓"),
    ]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        # Outer container fills the screen between Header/Footer and centers
        # its children both horizontally and vertically (via CSS align rule).
        # Without this wrapper the banner + menu pin to the top-left on
        # large displays, which looks unfinished.
        # Every block below is wrapped in its own Center widget so each
        # one centers within the full screen width independently. Without
        # the per-block Center, children of a Vertical container left-align
        # to the column where the widest sibling starts — which made the
        # banner look "stuck to the left" relative to the menu box.
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
                with Center():
                    yield Static(
                        "[dim]↑/↓ navigate · Enter select · "
                        "n/r/p/c/t quick · q quit[/dim]",
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
        # Focus the first menu button so a fresh Enter launches the wizard
        # without forcing the operator to Tab in from the Header first.
        try:
            self.query_one("#btn-new", Button).focus()
        except Exception:
            pass
        # Pre-warm the heavy imports the campaign worker will need.
        # CrewAI, LangGraph, LiteLLM, and the full tool registry together
        # take ~30s on a cold start — without this, the operator would
        # stare at "Initializing campaign…" for that whole stretch after
        # pressing Save & Run. Doing it now in a background thread means
        # the imports are already cached by the time they finish the
        # wizard. ``sys.modules`` caches the result so the runner's own
        # ``import`` statements become near-free lookups.
        self._warm_imports()

    @work(thread=True, exclusive=True, group="warmup")
    def _warm_imports(self) -> None:
        """Background warm-up of the heavy imports the runner needs.
        Runs in a thread (not on the event loop) so it can't stall
        the welcome screen's input handling."""
        try:
            # Pull in the agent / graph / tool subsystems. The order
            # mirrors the runner's own imports so anything they
            # transitively pull in (CrewAI, LangGraph, LiteLLM,
            # structlog wrappers, etc.) lands in sys.modules now.
            import nexusrecon.core.campaign  # noqa: F401
            import nexusrecon.core.scope  # noqa: F401
            import nexusrecon.core.campaign_runner  # noqa: F401
            import nexusrecon.tools.registry  # noqa: F401
            import nexusrecon.reports.engine  # noqa: F401
            import nexusrecon.models.campaign  # noqa: F401
            import nexusrecon.graph.workflow  # noqa: F401
            import nexusrecon.graph.dynamic_dispatcher  # noqa: F401
        except Exception:
            # If warmup fails it's not user-visible — the runner
            # will just hit the cold-import path itself.
            pass

    # ── Mouse-button dispatcher delegates to the same actions the keys use ──

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

    # ── Actions: identical entry points for both keyboard and mouse ─────────

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
        from nexusrecon.tui.screens.config import ConfigScreen
        await self.app.push_screen(ConfigScreen())

    async def action_menu_tools(self) -> None:
        from nexusrecon.tui.screens.config import ToolsScreen
        await self.app.push_screen(ToolsScreen())

    def action_quit_app(self) -> None:
        self.app.exit()

    # ── Arrow-key focus cycling between menu buttons ────────────────────────

    def action_focus_prev(self) -> None:
        # Screen.focus_previous() cycles backwards through focusable widgets.
        # In this screen the only focusables are the 6 menu buttons.
        try:
            self.focus_previous()
        except Exception:
            pass

    def action_focus_next_btn(self) -> None:
        try:
            self.focus_next()
        except Exception:
            pass

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

from datetime import UTC, datetime
from pathlib import Path

from textual import work
from textual.app import ComposeResult
from textual.containers import Center, Container, Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header, Static

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


def _next_step_hint() -> str:
    """Single context-aware "what should I do next?" hint.

    Replaces the previous duplicate Actions button menu with a
    single concrete next action, chosen from app state:

      - No LLM key + no campaigns  → "Configure first" (c)
      - No campaigns                → "Run your first campaign" (n)
      - Campaigns + in-progress one → "Resume <id>"            (r)
      - Otherwise                   → "Run another campaign"   (n)

    The sidebar still carries the full navigation surface; this is
    a personal-trainer-style "you, specifically, should press this
    next" prompt.
    """
    try:
        from pathlib import Path as _Path

        from nexusrecon.core.config import get_config
        cfg = get_config()
        # Check for any configured LLM key first.
        has_key = any(
            cfg.get_secret(k)
            for k in ("anthropic_api_key", "openai_api_key")
        )
        out_dir = _Path(cfg.output_dir)
        campaigns = (
            list(out_dir.rglob("state.json")) if out_dir.exists() else []
        )
        if not has_key and not campaigns:
            return (
                "👋  Press [bold]c[/bold] to configure your LLM "
                "provider key — required before your first campaign."
            )
        if not campaigns:
            return (
                "🎯  Press [bold]n[/bold] to launch your first "
                "campaign."
            )
        # Look for an unfinished campaign (one missing phase9 in
        # completed_phases) and surface its resume shortcut.
        try:
            import json as _json
            campaigns.sort(key=lambda p: p.stat().st_mtime, reverse=True)
            latest = campaigns[0]
            data = _json.loads(latest.read_text(encoding="utf-8"))
            completed = data.get("completed_phases") or []
            if "phase9" not in completed:
                return (
                    "🔄  Last campaign is partial — press "
                    "[bold]r[/bold] to resume."
                )
        except Exception:
            pass
        return (
            "🎯  Press [bold]n[/bold] to start another campaign, "
            "or [bold]p[/bold] to review past runs."
        )
    except Exception:
        return ""


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


def _top_key_gaps(limit: int = 3) -> list[tuple[str, int]]:
    """Rank missing env vars by how many tools each would unlock.

    For every tool that's failing ``is_available()`` because it
    lacks a required key, accumulate that key's "impact" — the
    number of tools that would flip to active if the key were
    set. Return the top ``limit`` entries in descending order.

    Ties broken alphabetically so the order is stable for tests
    and for operators scanning the list. Binary requirements
    (``binary_required``) are deliberately excluded: those are
    installed via shell, not configurable from the TUI; surfacing
    them here would be a dead end.

    Returns:
        list of ``(env_var_name_UPPER, tool_count)`` tuples.
    """
    try:
        from nexusrecon.core.config import get_config
        from nexusrecon.tools.registry import get_registry
        registry = get_registry()
        cfg = get_config()
        # Count each missing key once per tool that needs it.
        impact: dict[str, int] = {}
        for tool in registry._tools.values():
            if getattr(tool, "stubbed", False):
                continue
            if tool.is_available():
                continue
            # The tool isn't available — figure out which of its
            # required keys are actually unset.
            for key in (tool.requires_keys or []):
                if not cfg.get_secret(key):
                    impact[key.upper()] = impact.get(key.upper(), 0) + 1
        # Sort by impact descending, then key ascending for
        # stable tie-breaking.
        ranked = sorted(
            impact.items(),
            key=lambda kv: (-kv[1], kv[0]),
        )
        return ranked[:max(0, limit)]
    except Exception:
        return []


def _render_tool_gaps(limit: int = 3) -> str:
    """Format the top key gaps for the dashboard's Tool health card.

    Returns an empty string when there are no gaps (so the card
    layout collapses cleanly). Each line names one env var + the
    number of tools it would unlock so the operator can prioritise.

    TUI-6a: each gap now carries a small intensity-tinted bar
    rendered with the same color stops as
    :class:`IntensityGauge`. The bar's fill ratio is the gap's
    impact normalised against the WORST gap shown, so the
    operator's eye lands on the highest-leverage key first.
    """
    from nexusrecon.tui.widgets.gauges import pick_intensity_color

    gaps = _top_key_gaps(limit=limit)
    if not gaps:
        return ""
    max_count = max(count for _, count in gaps)
    lines: list[str] = ["[dim]Top gaps:[/dim]"]
    bar_cells = 6
    for key, count in gaps:
        # Normalise against the worst gap so within this list,
        # the highest-impact key is always rendered fully hot
        # and lesser gaps shade down. The absolute impact is in
        # the trailing count, so the bar carries the relative
        # signal without misrepresenting a 2-tool gap as
        # "critical."
        ratio = count / max_count if max_count > 0 else 0.0
        color = pick_intensity_color(ratio)
        filled = int(round(ratio * bar_cells))
        empty = bar_cells - filled
        bar = (
            f"[{color}]{'█' * filled}[/{color}]"
            f"[dim]{'░' * empty}[/dim]"
        )
        suffix = "tool" if count == 1 else "tools"
        lines.append(
            f"  {bar} [bold $primary]{key}[/bold $primary] "
            f"[dim]would unlock {count} {suffix}[/dim]"
        )
    return "\n".join(lines)


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
        # Sidebar cursor — ↑/↓ move the highlight, Enter activates.
        # Letter shortcuts (n/p/c/t/?) still jump directly; the
        # arrow keys are an additive, more-discoverable second
        # path for operators who didn't memorize the shortcuts yet.
        ("up", "sidebar_up", "Sidebar ↑"),
        ("down", "sidebar_down", "Sidebar ↓"),
        ("enter", "sidebar_activate", "Open"),
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
                    # ``can_focus=False`` so the table never steals
                    # arrow keys from the screen-level sidebar-cursor
                    # bindings. It's a read-only summary; the operator
                    # navigates campaigns via ``p`` / the sidebar, not
                    # by scrolling this widget.
                    recents = DataTable(
                        id="dashboard-recents",
                        zebra_stripes=True,
                        cursor_type="row",
                        show_cursor=False,
                    )
                    recents.can_focus = False
                    yield recents
                    # Quick stats panel.
                    #
                    # The Sidebar on the left already provides primary
                    # navigation (Dashboard / New / Past / Tools /
                    # Config / Help) with letter shortcuts. We DON'T
                    # duplicate it here with a button menu — that was
                    # the original layout and operators called it
                    # out as redundant. Instead this bottom row
                    # surfaces information you can't get from the
                    # sidebar: tool health + a "next step" hint.
                    with Horizontal(id="dashboard-bottom"):
                        with Vertical(classes="dashboard-stat-card"):
                            yield Static(
                                "[bold $primary]Tool health[/bold $primary]",
                                classes="dashboard-card-title",
                            )
                            yield Static(
                                _tool_breakdown(),
                                id="dashboard-tools",
                            )
                            # Top-impact missing keys — the
                            # actionable half of "tool health". A
                            # bare "15 skipped" leaves the operator
                            # guessing; this names the env vars
                            # ranked by how many tools each unlocks.
                            yield Static(
                                _render_tool_gaps(),
                                id="dashboard-tool-gaps",
                            )
                            yield Static(
                                "[dim]Press [bold]t[/bold] to browse + "
                                "configure tools.[/dim]",
                                classes="dashboard-stat-hint",
                            )
                        with Vertical(classes="dashboard-stat-card"):
                            yield Static(
                                "[bold $primary]What's next[/bold $primary]",
                                classes="dashboard-card-title",
                            )
                            yield Static(
                                _next_step_hint(),
                                id="dashboard-next-step",
                            )
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
        # The dashboard is keyboard-first. We don't focus the (now-
        # removed) primary button; we focus the recent-campaigns
        # table so arrow-key scroll lands somewhere useful. The
        # letter shortcuts (n/r/p/c/t) work regardless of focus.
        try:
            self.query_one("#dashboard-recents", DataTable).focus()
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
        try:
            self.query_one("#dashboard-tool-gaps", Static).update(
                _render_tool_gaps(),
            )
        except Exception:
            pass
        try:
            self.query_one("#dashboard-next-step", Static).update(
                _next_step_hint(),
            )
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

    # ── Arrow-key sidebar navigation ────────────────────────────────

    def action_sidebar_up(self) -> None:
        """``↑`` — move the sidebar cursor to the previous entry."""
        try:
            self.query_one("#dashboard-sidebar", Sidebar).move_cursor_up()
        except Exception:
            pass

    def action_sidebar_down(self) -> None:
        """``↓`` — move the sidebar cursor to the next entry."""
        try:
            self.query_one("#dashboard-sidebar", Sidebar).move_cursor_down()
        except Exception:
            pass

    async def action_sidebar_activate(self) -> None:
        """``Enter`` — open the screen under the sidebar cursor.

        The sidebar owns the cursor state; we dispatch through the
        app's central navigator so palette and sidebar agree on
        what "go to tools" means. ``dashboard`` is a no-op because
        we're already on it (matches the palette's behavior).
        """
        try:
            sidebar = self.query_one("#dashboard-sidebar", Sidebar)
            destination = sidebar.current_destination()
        except Exception:
            return
        if destination == "dashboard":
            return
        # Reuse the app's existing navigation dispatcher so the
        # sidebar, palette, and letter shortcuts never drift apart.
        try:
            self.app._palette_navigate(destination)
        except Exception:
            pass

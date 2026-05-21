"""Tools browser (TUI-2 redesign).

Three-pane layout replacing the old flat DataTable in
``screens/config.py``:

  - **Left pane:** category list with per-category counts (and an
    "All" row at the top). Operator narrows scope by selecting a
    category.
  - **Centre pane:** filterable list of tools in the selected
    category. Press ``/`` to focus the filter input; type to
    narrow; Esc clears.
  - **Right pane:** detail card for the highlighted tool —
    description, tier, category, required keys, availability,
    stub flag. Action shortcuts at the bottom (``c`` jump to
    config screen with this tool's keys, ``t`` test connection
    when implemented per-tool).

The previous screen surfaced 97 entries as a single sorted
DataTable. With Phase E live, the count is only going up; the
new layout scales linearly and gives operators a real workflow
for finding the tool they need.
"""
from __future__ import annotations

from typing import Any

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import (
    Footer,
    Header,
    Input,
    ListItem,
    ListView,
    Static,
)

# ──────────────────────────────────────────────────────────────────────
# Data extraction
# ──────────────────────────────────────────────────────────────────────


def _load_tools() -> list[dict[str, Any]]:
    """Snapshot the registry. Cheap; called on each filter change.

    Defensive: never raises ── returns an empty list if the
    registry import / iteration fails so the screen renders an
    empty state instead of crashing.
    """
    try:
        from nexusrecon.tools.registry import get_registry
        return sorted(
            get_registry().list_tools(),
            key=lambda t: (t.get("category", ""), t.get("name", "")),
        )
    except Exception:
        return []


def _group_by_category(
    tools: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    """Bucket tools by category. Order preserved within each
    bucket so the centre pane stays alphabetical."""
    buckets: dict[str, list[dict[str, Any]]] = {}
    for tool in tools:
        cat = tool.get("category", "uncategorized")
        buckets.setdefault(cat, []).append(tool)
    return buckets


def _category_label(category: str, count: int) -> str:
    """Render a left-pane row label: ``identity  (12)``."""
    return f"{category}  [dim]({count})[/dim]"


# ──────────────────────────────────────────────────────────────────────
# Screen
# ──────────────────────────────────────────────────────────────────────


class ToolsScreen(Screen):
    """Three-pane tools browser.

    Navigation summary:
      - Tab cycles focus between the three panes.
      - ``/`` focuses the filter input (clears on Esc).
      - Enter on a tool opens a "go to config" shortcut for that
        tool's required keys.
      - ``c`` from anywhere on the screen jumps to the
        ConfigScreen for the highlighted tool's first required
        key, when one exists.
    """

    BINDINGS = [
        Binding("escape", "back", "Back"),
        Binding("slash", "focus_filter", "Filter"),
        Binding("tab", "focus_next_pane", "Cycle panes"),
        Binding("c", "jump_to_config", "Config"),
        Binding("ctrl+q", "quit_app", "Quit"),
    ]

    #: Sentinel category id used for the "show everything" row.
    ALL_CATEGORIES = "__all__"

    def __init__(self) -> None:
        super().__init__()
        self._tools: list[dict[str, Any]] = []
        self._buckets: dict[str, list[dict[str, Any]]] = {}
        self._current_category: str = self.ALL_CATEGORIES
        self._filter_text: str = ""
        # Cache the visible list (after category + filter) so the
        # selected-row → tool resolution is cheap.
        self._visible: list[dict[str, Any]] = []

    # ── Compose ─────────────────────────────────────────────────────

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        with Vertical(id="tools-stack"):
            yield Static(
                "[bold $primary]Tools[/bold $primary]   "
                "[dim]Tab cycle · / filter · c config · Esc back[/dim]",
                id="tools-header",
            )
            with Horizontal(id="tools-panes"):
                # Left: categories
                with Vertical(id="tools-cat-pane"):
                    yield Static(
                        "[bold]Categories[/bold]",
                        id="tools-cat-header",
                    )
                    yield ListView(id="tools-cat-list")
                # Centre: tools list + filter
                with Vertical(id="tools-list-pane"):
                    yield Input(
                        placeholder="Filter tools (substring or fuzzy)…",
                        id="tools-filter",
                    )
                    yield ListView(id="tools-list")
                # Right: detail card
                with Vertical(id="tools-detail-pane"):
                    yield Static(id="tools-detail-title")
                    yield Static(id="tools-detail-meta")
                    yield Static(id="tools-detail-desc")
                    yield Static(id="tools-detail-actions")
        yield Footer()

    # ── Lifecycle ───────────────────────────────────────────────────

    async def on_mount(self) -> None:
        self._refresh_data()
        self._rebuild_categories()
        self._rebuild_tools_list()
        self._render_detail(self._first_visible_tool())
        # Land focus on the centre list so the operator can scroll
        # immediately with arrow keys.
        try:
            self.query_one("#tools-list", ListView).focus()
        except Exception:
            pass

    def _refresh_data(self) -> None:
        self._tools = _load_tools()
        self._buckets = _group_by_category(self._tools)

    # ── Rendering helpers ───────────────────────────────────────────

    def _rebuild_categories(self) -> None:
        """Populate the left pane with ``All (97)`` then each
        category in alphabetical order."""
        try:
            cat_list = self.query_one("#tools-cat-list", ListView)
        except Exception:
            return
        try:
            cat_list.clear()
        except Exception:
            pass
        cat_list.append(
            ListItem(
                Static(_category_label("All", len(self._tools))),
                id=f"cat-{self.ALL_CATEGORIES}",
            ),
        )
        for cat in sorted(self._buckets.keys()):
            count = len(self._buckets[cat])
            cat_list.append(
                ListItem(Static(_category_label(cat, count)), id=f"cat-{cat}")
            )
        # Default selection: All.
        try:
            cat_list.index = 0
        except Exception:
            pass

    def _visible_tools(self) -> list[dict[str, Any]]:
        """Compute the centre-pane content under current category +
        filter."""
        if self._current_category == self.ALL_CATEGORIES:
            pool = self._tools
        else:
            pool = self._buckets.get(self._current_category, [])
        if not self._filter_text:
            return pool
        text = self._filter_text.strip().lower()
        if not text:
            return pool
        from nexusrecon.tui.command_palette import fuzzy_score
        scored = [
            (
                fuzzy_score(
                    f"{t.get('name', '')} {t.get('description', '')} "
                    f"{t.get('category', '')}",
                    text,
                ),
                t,
            )
            for t in pool
        ]
        return [t for s, t in sorted(scored, key=lambda x: -x[0]) if s > 0]

    def _rebuild_tools_list(self) -> None:
        try:
            tool_list = self.query_one("#tools-list", ListView)
        except Exception:
            return
        try:
            tool_list.clear()
        except Exception:
            pass
        self._visible = self._visible_tools()
        for tool in self._visible:
            tool_list.append(
                ListItem(Static(self._render_tool_row(tool))),
            )
        try:
            tool_list.index = 0 if self._visible else None
        except Exception:
            pass

    def _render_tool_row(self, tool: dict[str, Any]) -> str:
        """Single-line representation for the centre list."""
        name = tool.get("name", "?")
        available = tool.get("available", "False") == "True"
        stubbed = tool.get("stubbed", "False") == "True"
        if stubbed:
            icon = "[$warning]⚠[/$warning]"
        elif available:
            icon = "[$success]✓[/$success]"
        else:
            icon = "[$error]✗[/$error]"
        return f"{icon}  [bold]{name}[/bold]  [dim]{tool.get('tier', '?')}[/dim]"

    def _first_visible_tool(self) -> dict[str, Any] | None:
        return self._visible[0] if self._visible else None

    def _render_detail(self, tool: dict[str, Any] | None) -> None:
        """Update the right pane to show the selected tool's full
        metadata. ``None`` clears it."""
        try:
            title_widget = self.query_one("#tools-detail-title", Static)
            meta_widget = self.query_one("#tools-detail-meta", Static)
            desc_widget = self.query_one("#tools-detail-desc", Static)
            actions_widget = self.query_one("#tools-detail-actions", Static)
        except Exception:
            return
        if not tool:
            title_widget.update("[dim](no tool selected)[/dim]")
            meta_widget.update("")
            desc_widget.update("")
            actions_widget.update("")
            return
        name = tool.get("name", "?")
        available = tool.get("available", "False") == "True"
        stubbed = tool.get("stubbed", "False") == "True"
        if stubbed:
            status_line = "[$warning]⚠ stub (not implemented yet)[/$warning]"
        elif available:
            status_line = "[$success]✓ available[/$success]"
        else:
            status_line = "[$error]✗ requires key(s) not yet configured[/$error]"
        requires = tool.get("requires", "") or "[dim]none[/dim]"
        meta_lines = [
            f"[dim]Tier:[/dim]     {tool.get('tier', '?')}",
            f"[dim]Category:[/dim] {tool.get('category', '?')}",
            f"[dim]Requires:[/dim] {requires}",
            f"[dim]Status:[/dim]   {status_line}",
        ]
        title_widget.update(f"[bold $primary]{name}[/bold $primary]")
        meta_widget.update("\n".join(meta_lines))
        desc_widget.update((tool.get("description") or "").strip())
        # Action footer surfaces the bindings relevant to the
        # highlighted tool. We keep this static for now; the per-
        # tool live "test connection" action lands in a follow-up.
        actions_widget.update(
            "[dim]c[/dim] config keys   "
            "[dim]Esc[/dim] back",
        )

    # ── Event handlers ──────────────────────────────────────────────

    def on_list_view_highlighted(
        self, event: ListView.Highlighted,
    ) -> None:
        """Track which row is highlighted in each pane and update
        the right-side detail to match."""
        try:
            pane_id = event.list_view.id
        except Exception:
            return
        if pane_id == "tools-cat-list":
            idx = event.list_view.index
            if idx is None:
                return
            sorted_cats = sorted(self._buckets.keys())
            if idx == 0:
                self._current_category = self.ALL_CATEGORIES
            elif 1 <= idx <= len(sorted_cats):
                self._current_category = sorted_cats[idx - 1]
            else:
                return
            self._rebuild_tools_list()
            self._render_detail(self._first_visible_tool())
        elif pane_id == "tools-list":
            idx = event.list_view.index
            if idx is None or idx < 0 or idx >= len(self._visible):
                self._render_detail(None)
            else:
                self._render_detail(self._visible[idx])

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id != "tools-filter":
            return
        self._filter_text = event.value
        self._rebuild_tools_list()
        self._render_detail(self._first_visible_tool())

    # ── Actions ─────────────────────────────────────────────────────

    def action_focus_filter(self) -> None:
        try:
            self.query_one("#tools-filter", Input).focus()
        except Exception:
            pass

    def action_focus_next_pane(self) -> None:
        try:
            focused = self.focused
            focused_id = focused.id if focused else None
            order = ("tools-cat-list", "tools-filter", "tools-list")
            current_idx = order.index(focused_id) if focused_id in order else -1
            next_id = order[(current_idx + 1) % len(order)]
            self.query_one(f"#{next_id}").focus()
        except Exception:
            pass

    def action_jump_to_config(self) -> None:
        """Open the Config screen. The selected tool's first
        required key is currently surfaced in the detail pane;
        deep-link selection lands in a follow-up TUI pass."""
        try:
            from nexusrecon.tui.screens.config import ConfigScreen
            self.app.push_screen(ConfigScreen())
        except Exception:
            pass

    def action_back(self) -> None:
        try:
            self.app.pop_screen()
        except Exception:
            pass

    def action_quit_app(self) -> None:
        self.app.exit()

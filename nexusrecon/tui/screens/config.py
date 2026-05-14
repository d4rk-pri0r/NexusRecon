"""Configuration + Tools screens.

ConfigScreen is now an interactive `.env` editor: left pane lists
categories from `config_schema`, right pane shows the keys in the
selected category with their current configured-or-not status. Enter
or `e` on a key opens the EditKeyModal, which writes back to `.env`
and hot-reloads the runtime config singleton.

Values are masked by default for sensitive keys (only the last 4
characters of API keys / tokens are shown), and reveal is opt-in per
edit. Values are NEVER copied to the clipboard or echoed to logs.

ToolsScreen remains read-only (browse-only).
"""
from __future__ import annotations

import asyncio
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header, ListItem, ListView, Static

from nexusrecon.tui.config_schema import (
    BINARIES_CATEGORY,
    CATEGORIES,
    ConfigCategory,
    ConfigVar,
    all_categories,
    find_var,
)
from nexusrecon.tui.env_editor import EnvFile, mask_value


def _resolve_env_path() -> Path:
    """Locate `.env` near the project root. Falls back to CWD."""
    cwd = Path.cwd()
    if (cwd / ".env").exists():
        return cwd / ".env"
    # Walk up looking for pyproject.toml as a project-root marker
    for parent in [cwd] + list(cwd.parents):
        if (parent / "pyproject.toml").exists():
            return parent / ".env"
    return cwd / ".env"


class ConfigScreen(Screen):
    """Interactive `.env` editor — categorized two-pane layout.

    Keyboard-first: ↑/↓ navigate, Tab swaps focus between panes,
    Enter / e opens the edit modal, Esc backs out.
    """

    BINDINGS = [
        ("escape", "back", "Back"),
        ("enter", "edit_selected", "Edit"),
        ("e", "edit_selected", "Edit"),
        ("r", "refresh", "Refresh"),
        ("tab", "focus_next_pane", "Swap pane"),
        ("ctrl+q", "quit_app", "Quit"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.env_path = _resolve_env_path()
        self._cats: List[ConfigCategory] = all_categories()
        self._current_cat_idx: int = 0

    # ── Compose ────────────────────────────────────────────────────────

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        with Container(id="config-content"):
            with Vertical(id="config-stack"):
                yield Static(
                    "[bold #00ff9c]Configuration[/bold #00ff9c]  "
                    f"[dim].env at {self.env_path}[/dim]",
                    id="config-title",
                )
                yield Static(
                    "[dim]↑/↓ navigate · Tab swap pane · Enter / e edit · "
                    "r refresh · Esc back[/dim]",
                    id="config-hint",
                )
                with Horizontal(id="config-panes"):
                    # Left pane: categories
                    with Vertical(id="cat-pane"):
                        yield Static(
                            "[bold]Categories[/bold]",
                            id="cat-pane-header",
                        )
                        yield ListView(
                            *[
                                ListItem(Static(c.name), id=f"cat-{c.id}")
                                for c in self._cats
                            ],
                            id="cat-list",
                        )
                    # Right pane: keys in the selected category
                    with Vertical(id="keys-pane"):
                        yield Static(id="keys-pane-header")
                        yield Static(id="keys-pane-desc")
                        yield DataTable(
                            id="keys-table",
                            zebra_stripes=True,
                            cursor_type="row",
                        )
        yield Footer()

    # ── Lifecycle ──────────────────────────────────────────────────────

    async def on_mount(self) -> None:
        # Pre-select first category so the right pane has content immediately
        try:
            self.query_one("#cat-list", ListView).index = 0
        except Exception:
            pass
        self._render_keys_pane()
        # Focus the category list so arrow keys start working immediately
        try:
            self.query_one("#cat-list", ListView).focus()
        except Exception:
            pass

    # ── Pane sync ──────────────────────────────────────────────────────

    def _render_keys_pane(self) -> None:
        cat = self._cats[self._current_cat_idx]
        # Header + description
        try:
            self.query_one("#keys-pane-header", Static).update(
                f"[bold #00ff9c]{cat.name}[/bold #00ff9c]"
            )
            self.query_one("#keys-pane-desc", Static).update(
                f"[dim]{cat.description}[/dim]"
            )
        except Exception:
            pass
        # Table
        table = self.query_one("#keys-table", DataTable)
        table.clear(columns=True)

        if cat.id == "_binaries":
            self._populate_binaries_table(table)
            return

        table.add_columns("Variable", "Status", "Value", "Help")
        env_file = EnvFile(self.env_path)
        for var in cat.vars:
            current = env_file.get(var.key) or ""
            if not current:
                status = "[#ff5555]✗ not set[/#ff5555]"
                value_cell = "[dim](empty)[/dim]"
            else:
                status = "[#00ff9c]✓ configured[/#00ff9c]"
                value_cell = mask_value(current) if var.sensitive else current
            help_short = (var.help or "")[:60]
            table.add_row(var.key, status, value_cell, help_short)

    def _populate_binaries_table(self, table: DataTable) -> None:
        table.add_columns("Binary", "Path", "Notes")
        seen: Dict[str, str] = {}
        try:
            from nexusrecon.tools.registry import get_registry
            for t in get_registry()._tools.values():
                binary = getattr(t, "binary_required", None)
                if binary and binary not in seen:
                    seen[binary] = shutil.which(binary) or ""
        except Exception:
            pass
        # Sort so missing ones float to the top — operator sees gaps fastest
        for binary, path in sorted(seen.items(), key=lambda kv: (bool(kv[1]), kv[0])):
            if path:
                table.add_row(
                    binary, f"[#00ff9c]✓ {path}[/#00ff9c]", "ready"
                )
            else:
                table.add_row(
                    binary, "[#ff5555]✗ not on PATH[/#ff5555]",
                    "install via brew / go install / pipx",
                )

    # ── Events ─────────────────────────────────────────────────────────

    def on_list_view_highlighted(self, event) -> None:
        """Switching the highlighted category re-renders the keys pane."""
        try:
            idx = self.query_one("#cat-list", ListView).index or 0
            if 0 <= idx < len(self._cats) and idx != self._current_cat_idx:
                self._current_cat_idx = idx
                self._render_keys_pane()
        except Exception:
            pass

    def on_list_view_selected(self, event) -> None:
        """Enter on a category — move focus to the keys table."""
        try:
            self.query_one("#keys-table", DataTable).focus()
        except Exception:
            pass

    async def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Enter on a key row — open the edit modal."""
        await self.action_edit_selected()

    # ── Actions ────────────────────────────────────────────────────────

    async def action_edit_selected(self) -> None:
        cat = self._cats[self._current_cat_idx]
        if cat.id == "_binaries":
            # Binaries can't be edited from the TUI — surface a hint
            try:
                self.query_one("#keys-pane-desc", Static).update(
                    "[dim]Binaries can't be edited here. Install via "
                    "brew / go install / pipx in your shell, then press r to refresh.[/dim]"
                )
            except Exception:
                pass
            return
        table = self.query_one("#keys-table", DataTable)
        row = table.cursor_row
        if row is None or row < 0 or row >= len(cat.vars):
            return
        var = cat.vars[row]
        from nexusrecon.tui.screens.edit_key import EditKeyModal

        def _on_dismiss(result: Optional[str]) -> None:
            # result is None on cancel, the new value (or "" for clear) on save
            self._render_keys_pane()

        await self.app.push_screen(
            EditKeyModal(env_path=str(self.env_path), var=var),
            _on_dismiss,
        )

    def action_refresh(self) -> None:
        """Re-read .env from disk and re-render the active pane."""
        self._render_keys_pane()

    def action_focus_next_pane(self) -> None:
        """Tab between the category list and the keys table."""
        try:
            focused = self.focused
            if focused is None or focused.id == "cat-list":
                self.query_one("#keys-table", DataTable).focus()
            else:
                self.query_one("#cat-list", ListView).focus()
        except Exception:
            pass

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_quit_app(self) -> None:
        self.app.exit()


class ToolsScreen(Screen):
    """List every registered tool with availability."""

    BINDINGS = [
        ("escape", "back", "Back"),
        ("ctrl+q", "quit_app", "Quit"),
    ]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        yield Static(
            "[bold #00ff9c]Tools[/bold #00ff9c]  "
            "[dim](press Esc to return)[/dim]",
            classes="wizard-label",
        )
        yield DataTable(id="tools-table", zebra_stripes=True)
        yield Footer()

    async def on_mount(self) -> None:
        table = self.query_one("#tools-table", DataTable)
        table.add_columns("Name", "Category", "Tier", "Status", "Description")
        try:
            from nexusrecon.tools.registry import get_registry
            for t in sorted(
                get_registry().list_tools(),
                key=lambda x: (x.get("category", ""), x.get("name", "")),
            ):
                avail = "✓ ready" if t.get("available") == "True" else "✗ missing"
                desc = (t.get("description") or "")[:80]
                table.add_row(
                    t.get("name", ""),
                    t.get("category", ""),
                    t.get("tier", ""),
                    avail,
                    desc,
                )
        except Exception as exc:
            table.add_row("(load failed)", str(exc)[:40], "", "", "")

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_quit_app(self) -> None:
        self.app.exit()

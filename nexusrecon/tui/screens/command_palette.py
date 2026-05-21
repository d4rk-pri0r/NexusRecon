"""Command-palette modal screen (TUI-2 flagship).

Renders the palette as a centred overlay. Operator types a query;
matches refresh on every keystroke (debounced via Textual's
``Input.Changed`` event). Up/down cycles through results, Enter
executes the highlighted match, Esc dismisses.

The palette engine + sources live in
:mod:`nexusrecon.tui.command_palette` so they're unit-testable
without spinning up the TUI. This module is the Textual rendering
layer only.
"""
from __future__ import annotations

import asyncio

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.reactive import reactive
from textual.screen import ModalScreen
from textual.widgets import Input, ListItem, ListView, Static

from nexusrecon.tui.command_palette import (
    CommandMatch,
    CommandPalette,
)


class CommandPaletteScreen(ModalScreen):
    """Modal that hosts the fuzzy palette UI.

    Lifecycle:
      - Mounts, focuses the input.
      - Every keystroke queries the palette and rebuilds the list.
      - Arrow keys cycle the selection; Enter awaits the match's
        ``execute`` callable, then dismisses.
      - Esc dismisses without executing.
    """

    BINDINGS = [
        Binding("escape", "dismiss", "Cancel"),
        # Down/Up move highlight inside the result list. Listview
        # has its own bindings but the operator might still be in
        # the input field — these forward the cursor explicitly.
        Binding("down", "cursor_down", "↓"),
        Binding("up", "cursor_up", "↑"),
    ]

    #: The current ranked match set. Reactive so the on-input
    #: handler can re-render the list cleanly.
    matches: reactive[list[CommandMatch]] = reactive(list)

    def __init__(self, palette: CommandPalette) -> None:
        super().__init__()
        self._palette = palette
        # Initial open shows everything (empty query → score 1.0).
        self._initial_matches = palette.query("")

    def compose(self) -> ComposeResult:
        with Vertical(id="palette-modal"):
            yield Static("⌨  Command palette", id="palette-title")
            yield Input(
                placeholder="Search tools, navigation, reports …",
                id="palette-input",
            )
            yield ListView(id="palette-results")
            yield Static(
                "[dim]↑↓ navigate · Enter execute · Esc cancel[/dim]",
                id="palette-hint",
            )

    def on_mount(self) -> None:
        self.matches = self._initial_matches
        # Render the initial set + focus the input so typing
        # narrows the results immediately.
        self._rebuild_results()
        try:
            self.query_one("#palette-input", Input).focus()
        except Exception:
            pass

    # ── Query lifecycle ─────────────────────────────────────────────

    def on_input_changed(self, event: Input.Changed) -> None:
        """Re-query the palette on every keystroke. Cheap by
        design (sources cap their output at ~20 each)."""
        try:
            self.matches = self._palette.query(event.value or "")
        except Exception:
            self.matches = []
        self._rebuild_results()

    def _rebuild_results(self) -> None:
        """Re-render the ListView from the current ``matches``.

        We rebuild from scratch on every change ── ListView in
        Textual 8.x doesn't have a clean "update items" API and
        the result lists are small (≤40), so the cost is trivial.
        """
        try:
            results = self.query_one("#palette-results", ListView)
        except Exception:
            return
        # Snapshot the previous selection so we can preserve it
        # when re-rendering (e.g., when the same match still
        # appears in the new result set).
        previous_index = results.index

        # ListView in Textual 8.x exposes `clear()` plus
        # `append()` for items. Use them for a deterministic
        # rebuild.
        try:
            results.clear()
        except Exception:
            # Fall back to remove_children when clear isn't
            # available; defensive against framework drift.
            try:
                results.remove_children()
            except Exception:
                pass

        for match in self.matches:
            label = _render_match_label(match)
            item = ListItem(Static(label))
            try:
                results.append(item)
            except Exception:
                continue

        # Re-select the first item by default; preserves position
        # when previous selection still indexable.
        try:
            if self.matches:
                results.index = previous_index if (
                    previous_index is not None
                    and previous_index < len(self.matches)
                ) else 0
        except Exception:
            pass

    # ── Actions ─────────────────────────────────────────────────────

    def action_cursor_down(self) -> None:
        try:
            results = self.query_one("#palette-results", ListView)
            results.action_cursor_down()
        except Exception:
            pass

    def action_cursor_up(self) -> None:
        try:
            results = self.query_one("#palette-results", ListView)
            results.action_cursor_up()
        except Exception:
            pass

    async def _execute_current(self) -> None:
        """Resolve the highlighted match's ``execute`` callable +
        dismiss the modal. Coroutines are awaited; sync callables
        are invoked directly."""
        try:
            results = self.query_one("#palette-results", ListView)
            idx = results.index
        except Exception:
            return
        if idx is None or idx < 0 or idx >= len(self.matches):
            return
        match = self.matches[idx]
        # Dismiss FIRST so the executed action (which may push a
        # new screen) lands on the screen below the palette, not
        # the palette itself.
        self.dismiss(match)
        if match.execute is None:
            return
        try:
            result = match.execute()
            if asyncio.iscoroutine(result):
                await result
        except Exception:
            # Don't crash the app on a buggy executor; the
            # operator will notice the no-op and re-try.
            pass

    # Both the Input and the ListView can fire Enter ── handle
    # both. Input's "submitted" is fired by Enter; ListView's
    # "selected" by Enter as well.

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        await self._execute_current()

    async def on_list_view_selected(self, event) -> None:
        await self._execute_current()


# ──────────────────────────────────────────────────────────────────────
# Rendering helpers
# ──────────────────────────────────────────────────────────────────────


def _render_match_label(match: CommandMatch) -> str:
    """Format a CommandMatch as a two-line Rich string for ListItem.

    First line is bold title with icon prefix; second is dimmed
    subtitle. Severity / kind colouring is applied via Textual's
    Rich markup so theme variables (when CSS classes get added in
    a follow-up) still apply.
    """
    icon = match.icon or "•"
    title = match.title or "(no title)"
    if match.subtitle:
        return f"{icon}  [bold]{title}[/bold]\n   [dim]{match.subtitle}[/dim]"
    return f"{icon}  [bold]{title}[/bold]"

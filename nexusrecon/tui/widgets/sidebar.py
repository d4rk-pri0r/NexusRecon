"""Persistent sidebar navigation widget.

Mounted on the Dashboard (and, in future TUI passes, every screen)
to provide always-visible top-level navigation. Six entries map to
the canonical destinations the command palette also knows about
(see :class:`nexusrecon.tui.command_palette.NavigationSource`):

    📊 Dashboard         (d)
    🎯 New Campaign      (n)
    📁 Past Campaigns    (p)
    🛠 Tools             (t)
    🔧 Configuration     (c)
    ❓ Help              (?)

Collapsible: pressing ``]`` toggles the sidebar between full width
(24 cols) and a narrow icon-only mode (3 cols). Toggle persists for
the lifetime of the screen, not across sessions.

Spec ref: (persistent shell layout).
"""
from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.reactive import reactive
from textual.widgets import Static

# Canonical entry catalog — mirrors NavigationSource so the palette
# and sidebar stay in lockstep without manual cross-reference.
SIDEBAR_ENTRIES: list[tuple[str, str, str, str]] = [
    # (destination_id, label, key_hint, icon)
    ("dashboard", "Dashboard", "d", "📊"),
    ("new_campaign", "New", "n", "🎯"),
    ("campaigns", "Past", "p", "📁"),
    ("tools", "Tools", "t", "🛠"),
    ("config", "Config", "c", "🔧"),
    ("help", "Help", "?", "❓"),
]


class Sidebar(Vertical):
    """Always-visible navigation rail.

    Used by the dashboard today; other screens adopt it in future
    TUI passes. The widget itself does NOT handle navigation —
    individual screens map letter shortcuts to their actions. The
    sidebar is a visual aid + a discoverability surface.
    """

    DEFAULT_CSS = """
    Sidebar {
        width: 24;
        background: $background;
        border-right: tall $secondary;
        padding: 1 1;
    }

    Sidebar.-collapsed {
        width: 5;
    }

    Sidebar > .sidebar-entry {
        height: 2;
        width: 100%;
        padding: 0 1;
        color: $foreground;
    }

    Sidebar > .sidebar-entry.-active {
        background: $primary 30%;
        color: $primary;
        text-style: bold;
    }
    """

    #: Currently-active entry's id. Highlight follows. Used both as
    #: the "you are here" indicator on mount and as the cursor
    #: position when the parent screen drives arrow-key navigation
    #: into the sidebar.
    active_id: reactive[str] = reactive("dashboard")

    #: Collapsed state — toggled by the parent screen's ``]`` binding.
    collapsed: reactive[bool] = reactive(False)

    # ── Cursor movement (parent screen drives via ↑/↓) ──────────────

    def _entry_ids(self) -> list[str]:
        return [eid for eid, _, _, _ in SIDEBAR_ENTRIES]

    def _cursor_index(self) -> int:
        ids = self._entry_ids()
        try:
            return ids.index(self.active_id)
        except ValueError:
            return 0

    def move_cursor_up(self) -> None:
        """Move the highlight to the previous entry (wraps to bottom).

        Parent screens call this from an arrow-key action so the
        cursor model lives in one place — the widget that already
        owns the entry catalog and the reactive highlight class.
        """
        ids = self._entry_ids()
        if not ids:
            return
        self.active_id = ids[(self._cursor_index() - 1) % len(ids)]

    def move_cursor_down(self) -> None:
        """Move the highlight to the next entry (wraps to top)."""
        ids = self._entry_ids()
        if not ids:
            return
        self.active_id = ids[(self._cursor_index() + 1) % len(ids)]

    def current_destination(self) -> str:
        """Return the destination_id under the cursor — used by the
        parent screen's Enter binding to dispatch navigation."""
        return self.active_id

    def compose(self) -> ComposeResult:
        for entry_id, label, key, icon in SIDEBAR_ENTRIES:
            yield Static(
                self._render_entry(entry_id, label, key, icon),
                classes="sidebar-entry",
                id=f"sb-{entry_id}",
            )

    def _render_entry(self, entry_id: str, label: str, key: str, icon: str) -> str:
        # Two rendering modes: full label or icon + key.
        if self.collapsed:
            return f"{icon}"
        return f"{icon}  [bold]{label}[/bold]  [dim]{key}[/dim]"

    def watch_active_id(self, old: str, new: str) -> None:
        """Reactive: shift the ``-active`` CSS class as the highlighted
        entry changes."""
        try:
            for entry_id, _, _, _ in SIDEBAR_ENTRIES:
                widget = self.query_one(f"#sb-{entry_id}", Static)
                if entry_id == new:
                    widget.add_class("-active")
                else:
                    widget.remove_class("-active")
        except Exception:
            pass

    def watch_collapsed(self, old: bool, new: bool) -> None:
        """Reactive: swap label text based on collapsed state, plus
        toggle the ``-collapsed`` CSS class for width."""
        try:
            if new:
                self.add_class("-collapsed")
            else:
                self.remove_class("-collapsed")
            # Re-render every entry's label to match the new mode.
            for entry_id, label, key, icon in SIDEBAR_ENTRIES:
                widget = self.query_one(f"#sb-{entry_id}", Static)
                widget.update(self._render_entry(entry_id, label, key, icon))
        except Exception:
            pass

    def toggle_collapsed(self) -> None:
        """Public hook for the parent screen's binding handler."""
        self.collapsed = not self.collapsed

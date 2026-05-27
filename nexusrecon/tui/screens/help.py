"""Global ``?`` help overlay.

Pulls the BINDINGS list off whichever screen is currently active, plus
the App-level global bindings, and renders them as a two-column table
of ``key → description``. Each screen already declares its bindings
for the Footer; this modal just reformats them more legibly.

Triggered by ``?`` from any screen (binding registered on
:class:`NexusReconApp`). Closes on Escape or another ``?``.
"""
from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import DataTable, Static


class HelpModal(ModalScreen):
    """Modal that surfaces the active screen's key bindings.

    Operators get a discoverable cheat-sheet without leaving the
    current screen. The modal is read-only: navigation happens by
    pressing Escape and using the actual binding from the parent
    screen.
    """

    BINDINGS = [
        Binding("escape", "dismiss", "Close"),
        Binding("question_mark", "dismiss", "Close"),
        Binding("q", "dismiss", "Close"),
    ]

    def compose(self) -> ComposeResult:
        with Vertical(id="help-modal"):
            yield Static("⌨  Keyboard Shortcuts", id="help-title")
            yield Static(
                "[dim]Bindings active on the current screen.[/dim]",
                id="help-section-title",
            )
            table: DataTable = DataTable(id="help-table", show_cursor=False)
            table.add_columns("Key", "Action")
            yield table
            # TUI-7: cross-screen row-action vocabulary. The
            # per-screen table above shows what's bound RIGHT
            # NOW; this section documents the consistent keys
            # the operator can rely on EVERYWHERE.
            yield Static(
                "\n[bold]Cross-screen vocabulary[/bold]\n"
                "[dim]These keys mean the same thing on every "
                "list-shaped screen.[/dim]",
                id="help-vocabulary-title",
            )
            vocab_table: DataTable = DataTable(
                id="help-vocabulary-table", show_cursor=False,
            )
            vocab_table.add_columns("Key", "Meaning")
            yield vocab_table
            yield Static(
                "[dim]Press Esc, q, or ? to close.[/dim]",
                id="help-hint",
            )

    def on_mount(self) -> None:
        # Populate the table from the parent screen's bindings plus
        # the app-level globals. Dedup by key so a binding declared
        # on both surfaces only shows once.
        table = self.query_one("#help-table", DataTable)
        rows: list[tuple[str, str]] = []
        seen_keys: set[str] = set()

        # 1. App-level global bindings (?, ctrl+q, etc.)
        try:
            for binding in (self.app.BINDINGS or []):
                key, action, description = _unpack_binding(binding)
                if not description or key in seen_keys:
                    continue
                seen_keys.add(key)
                rows.append((_format_key(key), description))
        except Exception:
            pass

        # 2. Parent screen bindings (the screen below this modal).
        try:
            parent = self._parent_screen()
            if parent is not None:
                for binding in (parent.BINDINGS or []):
                    key, action, description = _unpack_binding(binding)
                    if not description or key in seen_keys:
                        continue
                    seen_keys.add(key)
                    rows.append((_format_key(key), description))
        except Exception:
            pass

        # If we couldn't find anything (unlikely), at least show a
        # placeholder so the modal isn't a blank box.
        if not rows:
            rows.append(("(none)", "No bindings declared on this screen"))

        for k, d in rows:
            table.add_row(k, d)

        # TUI-7: cross-screen vocabulary. Curated rather than
        # introspected — these are the keys we PROMISE behave the
        # same way regardless of which list view the operator is
        # in. Adding a new screen with these bindings = no work
        # to surface here; removing the binding from a screen
        # IS a regression and should be obvious in review.
        try:
            vocab_table = self.query_one(
                "#help-vocabulary-table", DataTable,
            )
            for key, meaning in (
                ("/", "Filter — substring match, case-insensitive"),
                ("Enter", "Open / activate the highlighted row"),
                ("Esc",   "Close filter (when active) or pop screen"),
                ("Tab",   "Cycle focus between panes"),
                ("c",     "Configure key (Tools) / Config (Dashboard)"),
                ("m",     "Mark/unmark reviewed (Reports)"),
                ("e",     "Open externally (Reports)"),
                ("d",     "Detail toggle (Runner) / dismiss (Dashboard)"),
                ("[ ]",   "Previous / next phase boundary (Runner)"),
                ("Space", "Pause/resume tail (Runner)"),
                ("?",     "Open this help"),
                ("Ctrl+P", "Command palette"),
                ("Ctrl+Q", "Quit the app"),
            ):
                vocab_table.add_row(key, meaning)
        except Exception:
            pass

    def _parent_screen(self):
        """Return the screen that was active when the modal was pushed."""
        try:
            stack = self.app.screen_stack
            # The modal is on top of the stack; the screen below it is
            # the one whose bindings we want to render.
            if len(stack) >= 2:
                return stack[-2]
        except Exception:
            pass
        return None


# ──────────────────────────────────────────────────────────────────────
# Binding-shape helpers
# ──────────────────────────────────────────────────────────────────────


def _unpack_binding(binding) -> tuple[str, str, str]:
    """Return ``(key, action, description)`` from a Binding object or
    the legacy 3-tuple shape. Both forms appear in the codebase ── the
    older screens use ``("n", "menu_new", "New Campaign")`` tuples,
    newer code uses :class:`textual.binding.Binding`."""
    if isinstance(binding, tuple):
        if len(binding) >= 3:
            return (binding[0], binding[1], binding[2])
        if len(binding) == 2:
            return (binding[0], binding[1], "")
        if len(binding) == 1:
            return (binding[0], "", "")
        return ("", "", "")
    # Binding instance
    key = getattr(binding, "key", "") or ""
    action = getattr(binding, "action", "") or ""
    description = getattr(binding, "description", "") or ""
    return (key, action, description)


def _format_key(key: str) -> str:
    """Pretty-print a key spec for the help table.

    Translates Textual's internal key names to something operators
    recognise (e.g. ``question_mark`` → ``?``, ``ctrl+q`` → ``Ctrl+Q``).
    Leaves single-letter shortcuts alone.
    """
    if not key:
        return ""
    aliases = {
        "question_mark": "?",
        "space": "Space",
        "enter": "Enter",
        "escape": "Esc",
        "up": "↑",
        "down": "↓",
        "left": "←",
        "right": "→",
        "tab": "Tab",
        "backspace": "Bksp",
        "delete": "Del",
        "home": "Home",
        "end": "End",
        "pageup": "PgUp",
        "pagedown": "PgDn",
    }
    parts = key.split("+")
    rendered = []
    for p in parts:
        p_lower = p.lower()
        if p_lower in aliases:
            rendered.append(aliases[p_lower])
        elif p_lower in ("ctrl", "alt", "shift", "meta", "cmd"):
            rendered.append(p_lower.capitalize())
        else:
            rendered.append(p.upper() if len(p) == 1 else p)
    return "+".join(rendered)

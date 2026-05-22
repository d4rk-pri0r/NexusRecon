"""Modal screen for editing a single config variable.

Invoked from ConfigScreen when the operator presses Enter or `e` on a
selected key. Keyboard-first: Esc cancels, Ctrl-S saves, `r` toggles
masked/revealed view of the current value, Tab moves between input
and buttons.
"""
from __future__ import annotations

import asyncio

from textual.app import ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Footer, Input, Select, Static

from nexusrecon.tui.config_schema import ConfigVar
from nexusrecon.tui.env_editor import EnvFile, mask_value


class EditKeyModal(ModalScreen[str | None]):
    """Modal: edit one env key, write to .env, hot-reload the config.

    Returns the new value (or None on cancel) via the standard
    ``dismiss()`` mechanism. The caller refreshes its display when the
    modal is dismissed.
    """

    BINDINGS = [
        ("escape", "cancel", "Cancel"),
        ("ctrl+s", "save", "Save"),
        ("ctrl+d", "delete", "Clear / Unset"),
        ("r", "toggle_reveal", "Reveal / Hide"),
        ("ctrl+q", "quit_app", "Quit"),
    ]

    def __init__(self, env_path: str, var: ConfigVar) -> None:
        super().__init__()
        self.env_path = env_path
        self.var = var
        self._env = EnvFile(env_path)
        self._current = self._env.get(var.key) or ""
        self._revealed = not var.sensitive  # non-sensitive vars start revealed
        self._status: str = ""

    def compose(self) -> ComposeResult:
        with Container(id="edit-modal"):
            with Vertical(id="edit-stack"):
                yield Static(
                    f"[bold #00ff9c]Edit: {self.var.key}[/bold #00ff9c]",
                    id="edit-title",
                )
                yield Static(self.var.help, id="edit-help")
                yield Static(self._status_text(), id="edit-current")
                # Either a Select (if choices given) or a free-text Input
                if self.var.choices:
                    yield Select.from_values(
                        self.var.choices,
                        value=self._current if self._current in self.var.choices else Select.BLANK,
                        id="edit-select",
                    )
                else:
                    yield Input(
                        value=self._current,
                        password=self.var.sensitive and not self._revealed,
                        placeholder="(leave blank to unset)",
                        id="edit-input",
                    )
                yield Static(
                    "[dim]Ctrl-S save · Esc cancel · "
                    "Ctrl-D clear · r reveal[/dim]",
                    id="edit-hint",
                )
                with Horizontal(id="edit-buttons"):
                    yield Button("Save", id="btn-save", classes="-primary")
                    yield Button("Clear", id="btn-clear")
                    yield Button("Cancel", id="btn-cancel")
        yield Footer()

    def _status_text(self) -> str:
        if not self._current:
            return "[dim italic]Currently: (not set)[/dim italic]"
        if self.var.sensitive and not self._revealed:
            return f"[dim]Currently:[/dim] {mask_value(self._current)}"
        return f"[dim]Currently:[/dim] {self._current}"

    def on_mount(self) -> None:
        # Focus the input first so the operator can just start typing
        try:
            if self.var.choices:
                self.query_one("#edit-select", Select).focus()
            else:
                self.query_one("#edit-input", Input).focus()
        except Exception:
            pass

    # ── Button dispatcher delegates to action methods (keyboard parity) ──

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        mapping = {
            "btn-save": self.action_save,
            "btn-clear": self.action_delete,
            "btn-cancel": self.action_cancel,
        }
        handler = mapping.get(event.button.id or "")
        if handler is None:
            return
        result = handler()
        if asyncio.iscoroutine(result):
            await result

    # ── Actions ──────────────────────────────────────────────────────────

    def action_cancel(self) -> None:
        """Discard changes, return None to caller."""
        self.dismiss(None)

    def action_quit_app(self) -> None:
        self.app.exit()

    def action_toggle_reveal(self) -> None:
        """Show / hide the sensitive value while editing."""
        if not self.var.sensitive:
            return
        self._revealed = not self._revealed
        # Re-render the Input with the new password setting
        try:
            inp = self.query_one("#edit-input", Input)
            inp.password = not self._revealed
        except Exception:
            pass
        try:
            self.query_one("#edit-current", Static).update(self._status_text())
        except Exception:
            pass

    def _new_value(self) -> str:
        """Read the staged value from whichever input widget is in use."""
        if self.var.choices:
            sel = self.query_one("#edit-select", Select).value
            return "" if sel is Select.BLANK else str(sel)
        return self.query_one("#edit-input", Input).value or ""

    def action_save(self) -> None:
        """Write the new value to .env and dismiss with it.

        TUI-6: success surfaces as a toast on the underlying screen
        so the operator gets concrete feedback that the save
        actually happened (the modal closes but the toast lingers
        for the standard 4 seconds)."""
        new_val = self._new_value().strip()
        try:
            self._env.set_value(self.var.key, new_val)
            self._env.write()
            self._hot_reload_config()
            label = "set" if new_val else "cleared"
            try:
                self.app.notify(
                    f"{self.var.key} {label}",
                    severity="information",
                )
            except Exception:
                pass
            self.dismiss(new_val)
        except Exception as exc:
            self._show_error(f"Save failed: {exc}")
            try:
                self.app.notify(
                    f"Save failed: {exc}",
                    severity="error",
                )
            except Exception:
                pass

    def action_delete(self) -> None:
        """Clear the key entirely (removes the line from .env).

        TUI-6: success/error toast for parity with action_save."""
        try:
            removed = self._env.delete_value(self.var.key)
            if removed:
                self._env.write()
                self._hot_reload_config()
                try:
                    self.app.notify(
                        f"{self.var.key} cleared",
                        severity="information",
                    )
                except Exception:
                    pass
            self.dismiss("")
        except Exception as exc:
            self._show_error(f"Clear failed: {exc}")
            try:
                self.app.notify(
                    f"Clear failed: {exc}",
                    severity="error",
                )
            except Exception:
                pass

    @staticmethod
    def _hot_reload_config() -> None:
        """Invalidate the cached NexusConfig singleton AND rebind
        every registered tool's ``self.config`` to the fresh
        instance so ``tool.is_available()`` immediately reflects
        the edit.

        Tools cache their config reference at construction
        (``self.config = get_config()``), so a bare
        ``cache_clear()`` is invisible to existing tool instances
        ── ``is_available()`` keeps reading the stale snapshot
        until the process restarts. That made the dashboard's
        Tool Health card and the Tools screen's status markers
        lag the operator's edits. Walking the registry here is
        cheap (~100 tool instances) and gives operators
        immediate visual feedback that the key took effect.
        """
        try:
            from nexusrecon.core.config import get_config
            get_config.cache_clear()
            new_cfg = get_config()
            from nexusrecon.tools.registry import get_registry
            for tool in get_registry()._tools.values():
                try:
                    tool.config = new_cfg
                except Exception:
                    # Defensive: a single tool barfing must not
                    # leave the others stranded with stale config.
                    pass
        except Exception:
            pass

    def _show_error(self, msg: str) -> None:
        self._status = msg
        try:
            self.query_one("#edit-current", Static).update(f"[bold #ff5555]{msg}[/bold #ff5555]")
        except Exception:
            pass

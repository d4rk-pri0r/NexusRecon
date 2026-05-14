"""NexusRecon V3 TUI — Textual app entry point."""
from __future__ import annotations

import sys

from textual.app import App


class NexusReconApp(App):
    """Top-level Textual application."""

    CSS_PATH = "app.tcss"
    TITLE = "NexusRecon — Agentic OSINT Orchestration"
    SUB_TITLE = "v3.0"

    BINDINGS = [
        ("ctrl+q", "quit", "Quit"),
    ]

    def on_mount(self) -> None:
        from nexusrecon.tui.screens.welcome import WelcomeScreen
        self.push_screen(WelcomeScreen())


def run_tui() -> None:
    """Public entry — launch the TUI if we have a TTY, fall back otherwise."""
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        sys.stderr.write(
            "[info] No TTY detected — falling back to CLI. "
            "Use 'nexusrecon run --help' for options.\n"
        )
        return
    app = NexusReconApp()
    app.run()


if __name__ == "__main__":
    run_tui()

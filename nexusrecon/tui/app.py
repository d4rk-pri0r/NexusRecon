"""NexusRecon TUI — Textual app entry point.

Internal iteration label: this module was added during the "V3 UX Polish"
development phase. The "V3" refers to the development iteration, not a
product version — see __version__ in `nexusrecon/__init__.py` for the
actual semver-tracked release number.
"""
from __future__ import annotations

import sys

from textual.app import App


class NexusReconApp(App):
    """Top-level Textual application."""

    CSS_PATH = "app.tcss"
    TITLE = "NexusRecon — Agentic OSINT Orchestration"
    # Display version pulled from the package __version__ so banner /
    # subtitle / pyproject can never drift apart.
    from nexusrecon import __version__ as _pkg_version
    SUB_TITLE = f"v{_pkg_version}"

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

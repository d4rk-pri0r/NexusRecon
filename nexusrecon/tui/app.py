"""NexusRecon TUI — Textual app entry point.

Internal iteration label: this module was added during the "V3 UX Polish"
development phase. The "V3" refers to the development iteration, not a
product version — see __version__ in `nexusrecon/__init__.py` for the
actual semver-tracked release number.
"""
from __future__ import annotations

import logging
import os
import sys
from datetime import datetime
from pathlib import Path

import structlog
from textual.app import App

from nexusrecon.tui.themes import THEMES, resolve_theme_name


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
        # Global help overlay — every screen inherits this binding.
        ("question_mark", "show_help", "Help"),
    ]

    # Path to the per-session log file (set by ``run_tui`` before
    # ``app.run()`` so screens like ``RunnerScreen`` can tail it for
    # the live Detail panel). ``None`` means "no session log
    # configured" — screens that depend on it should handle that.
    session_log_path: Path | None = None

    def on_mount(self) -> None:
        # Register NexusRecon's themes so :class:`Theme` colour
        # variables resolve in app.tcss. The active theme picks up
        # from the ``NEXUSRECON_TUI_THEME`` env var; unknown values
        # fall back to the default rather than crashing on launch.
        for theme in THEMES.values():
            try:
                self.register_theme(theme)
            except Exception:
                # register_theme is idempotent in current Textual but
                # we never want a theme registration error to keep the
                # TUI from launching.
                pass
        self.theme = resolve_theme_name(os.environ.get("NEXUSRECON_TUI_THEME"))

        from nexusrecon.tui.screens.welcome import WelcomeScreen
        self.push_screen(WelcomeScreen())

    async def action_show_help(self) -> None:
        """Open the global keyboard-help overlay (``?`` from any screen)."""
        from nexusrecon.tui.screens.help import HelpModal
        # If a help modal is already on top, don't stack a second one ──
        # the second ``?`` press should be a no-op (the binding inside
        # the modal closes it via Escape).
        try:
            top = self.screen_stack[-1] if self.screen_stack else None
            if isinstance(top, HelpModal):
                return
        except Exception:
            pass
        await self.push_screen(HelpModal())


def _open_session_log() -> tuple[Path, object]:
    """Open a per-session log file under `~/.nexusrecon/logs/`.

    Returns (path, file_object). Caller is responsible for closing the
    file on TUI exit.
    """
    log_dir = Path.home() / ".nexusrecon" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / f"tui-{datetime.utcnow():%Y%m%d-%H%M%S}.log"
    # Line-buffered so structlog entries land on disk immediately and
    # the operator can `tail -f` the log while a campaign runs.
    fh = open(log_path, "a", encoding="utf-8", buffering=1)
    return log_path, fh


def _route_logs_to_file(log_file) -> dict:
    """Reroute every chatty logging subsystem to ``log_file`` while the
    TUI owns the terminal.

    Why this exists at all: a previous version of this codebase called
    ``log.info(...)`` from inside campaign phase functions
    (``nexusrecon/graph/nodes.py`` has, for example,
    ``log.info("Phase 1: Passive footprinting")``). With structlog
    configured via ``PrintLoggerFactory(file=sys.stderr)`` (see
    ``cli/main.py::setup_logging``), each of those calls writes a line
    directly to fd 2 — the same TTY Textual is painting on top of —
    producing the "stray ``[info ]`` line floating in the middle of
    the screen" bug.

    Textual paints to the same terminal device as ``sys.stderr``, so
    we cannot redirect fd 2 itself (a previous attempt to ``dup2``
    fd 2 to the log file silently captured Textual's entire rendering
    stream and left the terminal blank). Instead, we surgically
    reconfigure each known stderr-writing subsystem to point at the
    log file:

    - **structlog**: re-run ``structlog.configure(...)`` with a
      ``PrintLoggerFactory`` bound to the log file. ``structlog.get_logger``
      returns a proxy, so every cached logger reference picks up the
      new factory the next time it's used.
    - **Python's stdlib ``logging``**: swap any stream handler on the
      root logger out for a ``FileHandler`` on the log file. LiteLLM
      and CrewAI both use stdlib logging.

    Returns the previous config so the caller can restore it on exit.
    """
    saved = {
        # We don't bother snapshotting structlog's config because we
        # always restore it to the stderr defaults the CLI started with.
        "stdlib_root_handlers": list(logging.getLogger().handlers),
        "stdlib_root_level": logging.getLogger().level,
    }

    # 1. structlog -> log file
    structlog.configure(
        wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
        logger_factory=structlog.PrintLoggerFactory(file=log_file),
        processors=[
            structlog.stdlib.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.dev.ConsoleRenderer(colors=False),
        ],
    )

    # 2. stdlib logging -> log file. Wipe existing handlers (likely
    # streaming to stderr) and install a single FileHandler.
    root = logging.getLogger()
    for h in list(root.handlers):
        root.removeHandler(h)
    file_handler = logging.FileHandler(str(log_file.name), encoding="utf-8")
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(
        logging.Formatter(
            "%(asctime)s %(name)s [%(levelname)s] %(message)s"
        )
    )
    root.addHandler(file_handler)
    root.setLevel(logging.INFO)

    return saved


def _restore_logs(saved: dict) -> None:
    """Restore the stdlib logging handlers we replaced on entry. We
    deliberately leave the structlog config pointed at whatever the
    caller wants — the CLI re-runs ``setup_logging`` on next entry if
    needed."""
    root = logging.getLogger()
    for h in list(root.handlers):
        root.removeHandler(h)
    for h in saved.get("stdlib_root_handlers", []):
        root.addHandler(h)
    root.setLevel(saved.get("stdlib_root_level", logging.WARNING))


def run_tui() -> None:
    """Public entry — launch the TUI if we have a TTY, fall back otherwise.

    Before handing the terminal to Textual we reroute structlog and the
    stdlib ``logging`` module to a per-session file under
    ``~/.nexusrecon/logs/tui-<ts>.log``. We do NOT redirect file
    descriptor 2 itself: Textual's terminal driver writes some of its
    rendering output to fd 2, so any blanket redirect of that fd
    blanks the screen. See ``_route_logs_to_file`` for the surgical
    approach used instead.
    """
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        sys.stderr.write(
            "[info] No TTY detected — falling back to CLI. "
            "Use 'nexusrecon run --help' for options.\n"
        )
        return

    log_path, log_file = _open_session_log()
    # Tell the operator where the log lives so they can tail it during
    # a run for diagnostic detail. Printed to the real stderr before
    # any log rerouting so it lands on their terminal, not the log file.
    sys.stderr.write(
        f"[info] NexusRecon TUI starting — diagnostic log: {log_path}\n"
    )
    sys.stderr.flush()

    saved = _route_logs_to_file(log_file)
    log_file.write(
        f"---- NexusRecon TUI session start "
        f"{datetime.utcnow().isoformat()}Z ----\n"
    )
    log_file.flush()

    try:
        app = NexusReconApp()
        app.session_log_path = log_path
        app.run()
    finally:
        _restore_logs(saved)
        try:
            log_file.flush()
            log_file.close()
        except Exception:
            pass
        sys.stderr.write(
            f"[info] NexusRecon TUI exited — diagnostic log: {log_path}\n"
        )
        sys.stderr.flush()


if __name__ == "__main__":
    run_tui()

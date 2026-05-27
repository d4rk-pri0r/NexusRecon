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

from nexusrecon.tui.command_palette import (
    CommandPalette,
    NavigationSource,
    ReportsSource,
    ToolsSource,
)
from nexusrecon.tui.themes import all_themes, resolve_theme_name


class NexusReconApp(App):
    """Top-level Textual application."""

    CSS_PATH = "app.tcss"
    TITLE = "NexusRecon — Agentic OSINT Orchestration"
    # Textual 8.x ships its own command palette bound to Ctrl+P. We
    # disable it so the NexusRecon palette (which has tool-aware
    # ranking + theme-matched styling) gets the binding instead.
    ENABLE_COMMAND_PALETTE = False
    # Display version pulled from the package __version__ so banner /
    # subtitle / pyproject can never drift apart.
    from nexusrecon import __version__ as _pkg_version
    SUB_TITLE = f"v{_pkg_version}"

    BINDINGS = [
        ("ctrl+q", "quit", "Quit"),
        # Global help overlay — every screen inherits this binding.
        ("question_mark", "show_help", "Help"),
        # Command palette — the flagship discoverability surface.
        ("ctrl+p", "show_palette", "Palette"),
        ("colon", "show_palette", "Palette"),
    ]

    # Path to the per-session log file (set by ``run_tui`` before
    # ``app.run()`` so screens like ``RunnerScreen`` can tail it for
    # the live Detail panel). ``None`` means "no session log
    # configured" — screens that depend on it should handle that.
    session_log_path: Path | None = None

    #: Singleton :class:`CommandPalette` shared across the app's
    #: lifetime. Built lazily on first access so test harnesses
    #: that instantiate the app without running can still mount
    #: screens.
    _palette: CommandPalette | None = None

    def on_mount(self) -> None:
        # Register NexusRecon's themes so :class:`Theme` colour
        # variables resolve in app.tcss. The active theme picks up
        # from the ``NEXUSRECON_TUI_THEME`` env var; unknown values
        # fall back to the default rather than crashing on launch.
        #
        # TUI-8: ``all_themes()`` merges any user-contributed themes
        # from ``~/.nexusrecon/themes/*.toml`` on top of the shipped
        # ones. A broken user theme file is logged + skipped — never
        # blocks launch.
        themes = all_themes()
        # Build a name → theme list so resolve_theme_name sees the
        # user contributions too.
        from nexusrecon.tui.themes import THEMES as _shipped_themes
        _shipped_themes.update(themes)
        for theme in themes.values():
            try:
                self.register_theme(theme)
            except Exception:
                # register_theme is idempotent in current Textual but
                # we never want a theme registration error to keep the
                # TUI from launching.
                pass
        self.theme = resolve_theme_name(os.environ.get("NEXUSRECON_TUI_THEME"))

        # Build the palette with the sources we ship in TUI-2. Each
        # source receives a callable wired into this app so the
        # palette can navigate without owning a reference to it.
        self._palette = CommandPalette()
        self._palette.register(NavigationSource(navigate=self._palette_navigate))
        self._palette.register(ToolsSource(jump_to_tools_screen=self._jump_to_tools))
        self._palette.register(ReportsSource(open_path=self._open_path))

        # TUI-3: launch into the new Dashboard (was WelcomeScreen).
        # The persistent status bar + sidebar live here. The
        # WelcomeScreen file remains as a backwards-compat shim
        # for any code that still imports it directly.
        from nexusrecon.tui.screens.dashboard import DashboardScreen
        self.push_screen(DashboardScreen())

    # ── Palette wiring ──────────────────────────────────────────────

    def get_command_palette(self) -> CommandPalette:
        """Public accessor — screens / tests get the live palette
        instance, building one if mount hasn't run yet (test
        harness path)."""
        if self._palette is None:
            self._palette = CommandPalette()
            self._palette.register(NavigationSource(navigate=self._palette_navigate))
            self._palette.register(ToolsSource(jump_to_tools_screen=self._jump_to_tools))
            self._palette.register(ReportsSource(open_path=self._open_path))
        return self._palette

    def _palette_navigate(self, destination: str) -> None:
        """Top-level navigation executor for :class:`NavigationSource`.

        Each canonical destination ID maps to a screen push. The
        palette dismisses itself BEFORE invoking this callable, so
        the new screen lands on the stack below where the palette
        used to be.
        """
        try:
            if destination == "dashboard":
                # Pop everything back to the dashboard ── the default
                # position. If the dashboard isn't on the stack, push
                # a fresh one.
                from nexusrecon.tui.screens.dashboard import DashboardScreen
                if not any(
                    isinstance(s, DashboardScreen) for s in self.screen_stack
                ):
                    self.push_screen(DashboardScreen())
                else:
                    while self.screen_stack and not isinstance(
                        self.screen_stack[-1], DashboardScreen,
                    ):
                        self.pop_screen()
            elif destination == "new_campaign":
                from nexusrecon.tui.screens.wizard import WizardScreen
                self.push_screen(WizardScreen())
            elif destination == "campaigns":
                from nexusrecon.tui.screens.campaigns import CampaignsScreen
                self.push_screen(CampaignsScreen(resume_mode=False))
            elif destination == "tools":
                self._jump_to_tools(None)
            elif destination == "config":
                from nexusrecon.tui.screens.config import ConfigScreen
                self.push_screen(ConfigScreen())
            elif destination == "help":
                from nexusrecon.tui.screens.help import HelpModal
                self.push_screen(HelpModal())
        except Exception:
            pass

    def _jump_to_tools(self, tool_name: str | None) -> None:
        """Open the new tools browser. ``tool_name`` is the
        selected match's tool name; the screen will focus that
        tool when the deep-link wiring lands in a follow-up
        (currently the screen lands on its default selection)."""
        try:
            from nexusrecon.tui.screens.tools import ToolsScreen
            self.push_screen(ToolsScreen())
        except Exception:
            pass

    def _open_path(self, path: str) -> None:
        """OS-level open of a report file. Same dispatch used by
        the results screen."""
        try:
            from nexusrecon.tui.screens.results import _open_path
            _open_path(path)
        except Exception:
            # Defensive fallback ── if the results-screen helper
            # changes, this still tries the system opener.
            import subprocess
            import sys
            try:
                if sys.platform == "darwin":
                    subprocess.Popen(["open", path])
                elif sys.platform.startswith("linux"):
                    subprocess.Popen(["xdg-open", path])
                elif sys.platform == "win32":
                    subprocess.Popen(["start", "", path], shell=True)
            except Exception:
                pass

    # ── Global actions ──────────────────────────────────────────────

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

    async def action_show_palette(self) -> None:
        """Open the command palette (``Ctrl+P`` / ``:`` from any
        screen). No-op when the palette is already on top so a
        second Ctrl+P doesn't stack."""
        from nexusrecon.tui.screens.command_palette import (
            CommandPaletteScreen,
        )
        try:
            top = self.screen_stack[-1] if self.screen_stack else None
            if isinstance(top, CommandPaletteScreen):
                return
        except Exception:
            pass
        await self.push_screen(CommandPaletteScreen(self.get_command_palette()))


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


def _session_lock_path() -> Path:
    """Path to the per-launch session lock file.

    TUI-8 crash-recovery: written on launch, deleted on CLEAN
    exit (no exception, no kill -9). On the next launch the
    dashboard reads this; if it exists, the previous session
    didn't shut down cleanly and a banner offers to inspect the
    orphaned log. Process kills (SIGKILL, OS crash, power loss)
    skip the deletion path entirely, so the lock survives —
    exactly the case we want to surface to the operator.
    """
    return Path.home() / ".nexusrecon" / ".tui_session_lock"


def _write_session_lock(log_path: Path) -> None:
    """Drop the per-launch lock file with the current PID + log
    pointer + start timestamp. Best-effort; failures here must
    NOT block launch."""
    import json
    import os
    try:
        path = _session_lock_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps({
                "started": datetime.utcnow().isoformat() + "Z",
                "pid": os.getpid(),
                "log_path": str(log_path),
            }),
            encoding="utf-8",
        )
    except Exception:
        pass


def _clear_session_lock() -> None:
    """Remove the lock file. Called only on CLEAN exit."""
    try:
        _session_lock_path().unlink(missing_ok=True)
    except Exception:
        pass


def run_tui() -> None:
    """Public entry — launch the TUI if we have a TTY, fall back otherwise.

    Before handing the terminal to Textual we reroute structlog and the
    stdlib ``logging`` module to a per-session file under
    ``~/.nexusrecon/logs/tui-<ts>.log``. We do NOT redirect file
    descriptor 2 itself: Textual's terminal driver writes some of its
    rendering output to fd 2, so any blanket redirect of that fd
    blanks the screen. See ``_route_logs_to_file`` for the surgical
    approach used instead.

    TUI-8: writes a session lock at launch + deletes it on CLEAN
    exit. If the previous session crashed (uncaught exception or
    process kill), the lock survives and the dashboard's
    crash-recovery banner picks it up.
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

    _write_session_lock(log_path)
    saved = _route_logs_to_file(log_file)
    log_file.write(
        f"---- NexusRecon TUI session start "
        f"{datetime.utcnow().isoformat()}Z ----\n"
    )
    log_file.flush()

    clean_exit = False
    try:
        app = NexusReconApp()
        app.session_log_path = log_path
        app.run()
        # No exception → this was a clean exit. Mark explicitly
        # so finally only clears the lock on the happy path.
        clean_exit = True
    finally:
        _restore_logs(saved)
        try:
            log_file.flush()
            log_file.close()
        except Exception:
            pass
        if clean_exit:
            _clear_session_lock()
        sys.stderr.write(
            f"[info] NexusRecon TUI exited — diagnostic log: {log_path}\n"
        )
        sys.stderr.flush()


if __name__ == "__main__":
    run_tui()

"""Post-campaign results screen."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from textual.app import ComposeResult
from textual.containers import VerticalScroll
from textual.screen import Screen
from textual.widgets import Footer, Header, Static

from nexusrecon.tui.widgets import StatusBar


def _open_path(path: str) -> Exception | None:
    """Open `path` with the user's editor / system handler. Returns the exception on failure."""
    try:
        if sys.platform == "darwin":
            subprocess.Popen(["open", path])
        elif sys.platform.startswith("linux"):
            subprocess.Popen(["xdg-open", path])
        elif os.name == "nt":
            os.startfile(path)  # type: ignore[attr-defined]
        else:
            editor = os.environ.get("EDITOR", "")
            if editor:
                subprocess.Popen([editor, path])
            else:
                return RuntimeError("no opener available for this platform")
        return None
    except Exception as exc:
        return exc


class ResultsScreen(Screen):
    """Summary + report shortcuts after a campaign completes."""

    BINDINGS = [
        # TUI-5: in-TUI markdown report browser. Press `b` for the
        # rich three-pane preview; the per-letter shortcuts below
        # remain for muscle memory + power users.
        ("b", "browse_reports", "Browse"),
        ("m", "open_master", "Master Report"),
        ("t", "open_threads", "Top Threads"),
        ("e", "open_summary", "Exec Summary"),
        ("p", "open_phishing", "Phishing"),
        ("c", "open_creds", "Credentials"),
        ("a", "open_dir", "All Reports"),
        ("escape", "back", "Back"),
        ("ctrl+q", "quit_app", "Quit"),
    ]

    def __init__(self, campaign_dir: str, state: dict[str, Any] | None = None) -> None:
        super().__init__()
        self.campaign_dir = Path(campaign_dir)
        self.reports_dir = self.campaign_dir / "reports"
        self.state = state or {}

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        yield StatusBar()
        yield Static(id="results-summary")
        yield Static("[bold]Top 3 threats[/bold]", classes="wizard-label")
        yield VerticalScroll(Static(id="results-threads"), id="results-threads-wrap")
        yield Static("[bold]Reports[/bold]", classes="wizard-label")
        yield VerticalScroll(Static(id="results-reports"), id="results-reports-wrap")
        yield Footer()

    async def on_mount(self) -> None:
        self._render_summary()
        self._render_threads()
        self._render_reports()

    def _render_summary(self) -> None:
        s = self.state
        findings = len(s.get("findings", []))
        ranked = len(s.get("ranked_threads", []))
        cost = float(s.get("llm_cost_usd", 0.0))
        errors = len(s.get("errors", []))
        completed = len(s.get("completed_phases", []))
        summary = (
            f"  [bold #00ff9c]✓[/bold #00ff9c]  Campaign complete · "
            f"{completed} phases · {findings} findings · {ranked} ranked\n"
            f"  [bold #00ff9c]✓[/bold #00ff9c]  ${cost:.2f} LLM spend · "
            f"{errors} error(s) · audit chain: VALID\n"
            f"  Output: [dim]{self.campaign_dir}[/dim]"
        )
        try:
            self.query_one("#results-summary", Static).update(summary)
        except Exception:
            pass

    def _render_threads(self) -> None:
        threads = self.state.get("ranked_threads", [])[:3]
        lines = []
        if not threads:
            lines.append("  [dim](no ranked threads — phase 8 may not have completed)[/dim]")
        else:
            for i, t in enumerate(threads, 1):
                sev = str(t.get("severity", "info")).upper()
                title = t.get("title", "Untitled")
                score = float(t.get("score", 0.0)) * 100
                lines.append(
                    f"  {i}. [{sev:<8}] {title}  ([dim]score {score:.0f}%[/dim])"
                )
        try:
            self.query_one("#results-threads", Static).update("\n".join(lines))
        except Exception:
            pass

    def _render_reports(self) -> None:
        rd = self.reports_dir
        entries = [
            ("m", "master_report.md",      "📋  Master Report"),
            ("t", "top_threads.md",        "🎯  Top Threads"),
            ("e", "executive_summary.md",  "📊  Executive Summary"),
            ("p", "phishing_package.md",   "🎣  Phishing Package"),
            ("c", "harvested_credentials.md", "🔑  Harvested Credentials"),
        ]
        lines = []
        for key, fname, label in entries:
            p = rd / fname
            status = "" if p.exists() else "  [dim](not generated)[/dim]"
            lines.append(f"  [bold]{key}[/bold]  {label}{status}")
        lines.append("  [bold]a[/bold]  📁  All Reports (open directory)")
        try:
            self.query_one("#results-reports", Static).update("\n".join(lines))
        except Exception:
            pass

    # ── Actions ────────────────────────────────────────────────────────────

    def _open(self, fname: str) -> None:
        path = self.reports_dir / fname
        if not path.exists():
            self.app.bell()
            return
        _open_path(str(path))

    def action_open_master(self) -> None:
        self._open("master_report.md")

    def action_open_threads(self) -> None:
        self._open("top_threads.md")

    def action_open_summary(self) -> None:
        self._open("executive_summary.md")

    def action_open_phishing(self) -> None:
        self._open("phishing_package.md")

    def action_open_creds(self) -> None:
        self._open("harvested_credentials.md")

    def action_open_dir(self) -> None:
        if self.reports_dir.exists():
            _open_path(str(self.reports_dir))

    async def action_browse_reports(self) -> None:
        """Open the TUI-5 in-TUI Markdown report browser."""
        try:
            from nexusrecon.tui.screens.reports_browser import (
                ReportsBrowserScreen,
            )
            await self.app.push_screen(
                ReportsBrowserScreen(str(self.campaign_dir)),
            )
        except Exception:
            pass

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_quit_app(self) -> None:
        self.app.exit()

"""Live campaign progress screen."""
from __future__ import annotations

import asyncio
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import Any, Deque, Dict

from rich.markup import escape as _rich_escape
from textual import work
from textual.app import ComposeResult
from textual.containers import Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import Footer, Header, ProgressBar, Static


_TOTAL_PHASES = 10  # phase1..phase8 + phase7_5 + phase9


class RunnerScreen(Screen):
    """Runs a campaign and displays live progress + recent activity."""

    BINDINGS = [
        ("q", "abort", "Abort"),
        ("p", "pause", "Pause"),
        ("r", "go_results", "Reports"),
        ("escape", "back", "Back"),
        ("ctrl+q", "quit_app", "Quit"),
    ]

    def __init__(
        self,
        scope_path: str,
        mode: str = "light",
        dispatch_mode: str = "lite",
        validate_creds: bool = False,
        generate_phishing: bool = False,
    ) -> None:
        super().__init__()
        self.scope_path = scope_path
        self.mode = mode
        self.dispatch_mode = dispatch_mode
        self.validate_creds = validate_creds
        self.generate_phishing = generate_phishing
        self.campaign_id: str = ""
        self.campaign_dir: str = ""
        self._activity: Deque[str] = deque(maxlen=12)
        self._phase_done = 0
        self._state: Dict[str, Any] = {}
        self._complete = False
        self._aborted = False

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        yield Static("[bold #00ff9c]Initializing campaign…[/bold #00ff9c]", id="phase-label")
        yield ProgressBar(total=_TOTAL_PHASES, show_eta=False, id="phase-bar")
        yield Static(id="runner-stats")
        yield Static("[bold]Recent activity[/bold]", classes="wizard-label")
        # activity-log is fed by user/tool output that can contain anything
        # (Pydantic ValidationError reprs include `[type=enum, input_value=...]`,
        # tool errors can include URLs with brackets, etc). Disable Rich markup
        # parsing entirely so log lines can never crash the screen.
        yield VerticalScroll(Static(id="activity-log", markup=False), id="runner-activity")
        yield Footer()

    async def on_mount(self) -> None:
        self._update_stats()
        self._run_campaign_worker()

    @work(exclusive=True)
    async def _run_campaign_worker(self) -> None:
        """Run the campaign on the same event loop."""
        try:
            await self._run()
        except Exception as exc:
            # Exception strings can contain Rich-markup-poisoning characters
            # (e.g. Pydantic ValidationError's `[type=enum, input_value='...']`
            # annotation parses as a malformed markup tag and crashes the
            # screen renderer). Escape before splicing into a markup template.
            safe = _rich_escape(str(exc))
            self._log(f"FATAL: {safe}")
            self._complete = True
            self._update_label(f"[bold #ff5555]Campaign failed: {safe}[/bold #ff5555]")

    async def _run(self) -> None:
        from nexusrecon.core.campaign import CampaignManager
        from nexusrecon.core.config import get_config
        from nexusrecon.core.scope import ScopeModel, ScopeGuard
        from nexusrecon.core.campaign_runner import run_campaign
        from nexusrecon.tools.registry import get_registry
        from nexusrecon.reports.engine import ReportEngine
        from nexusrecon.models.campaign import CampaignMode

        scope_model = ScopeModel.from_yaml(self.scope_path)
        campaign = CampaignManager(
            scope=scope_model,
            mode=CampaignMode(self.mode),
        )
        campaign.setup()
        self.campaign_id = campaign.campaign_id
        self.campaign_dir = str(campaign.campaign_dir)
        self._update_label(
            f"[bold #00ff9c]Phase 0/{_TOTAL_PHASES} — preparing[/bold #00ff9c]"
            f"  ·  Campaign [dim]{self.campaign_id}[/dim]"
        )

        scope_guard = ScopeGuard(scope_model)
        get_registry().set_campaign_context(scope_guard, campaign.cache, campaign.audit_log)

        # Preserve a copy of the scope file inside the campaign for audit
        try:
            campaign_scope_dst = Path(self.campaign_dir) / "scope.yaml"
            campaign_scope_dst.write_text(
                Path(self.scope_path).read_text(encoding="utf-8"),
                encoding="utf-8",
            )
        except Exception:
            pass

        state: Dict[str, Any] = {
            "campaign_id": campaign.campaign_id,
            "engagement_id": scope_model.engagement.engagement_id,
            "scope_hash": scope_model.scope_hash or "",
            "seeds": list(scope_model.scope.in_scope.domains),
            "completed_phases": [],
            "current_phase": "init",
            "findings": [],
            "subdomain_intel": {},
            "email_intel": {"emails": {}},
            "cloud_intel": {},
            "code_intel": {},
            "infra_intel": {},
            "domain_intel": {},
            "vuln_intel": {},
            "pretext_intel": {},
            "entity_graph": {},
            "hypotheses": [],
            "confirmed_leads": [],
            "validate_credentials": self.validate_creds,
            "generate_phishing_drafts": self.generate_phishing,
            "dispatch_mode": self.dispatch_mode,
            "llm_cost_usd": 0.0,
            "max_llm_cost_usd": getattr(scope_model.constraints, "max_llm_cost_usd", 10.0),
            "tool_cost_usd": 0.0,
            "step_count": 0,
            "errors": [],
            "agent_messages": [],
            "report_paths": {},
        }
        self._state = state

        def on_event(evt: Dict[str, Any]) -> None:
            self._handle_event(evt)

        state = await run_campaign(state, campaign, scope_model, on_event=on_event)
        self._state = state

        self._log("Generating reports…")
        self._update_label(
            f"[bold #00ff9c]Generating reports[/bold #00ff9c]  ·  "
            f"Campaign [dim]{self.campaign_id}[/dim]"
        )
        engine = ReportEngine(
            campaign_id=campaign.campaign_id,
            engagement_id=scope_model.engagement.engagement_id,
            scope_hash=scope_model.scope_hash or "",
            output_dir=campaign.report_dir,
        )
        report_paths = engine.generate_all(state)
        state["report_paths"] = report_paths

        try:
            campaign.finalize()
        except Exception:
            pass

        self._complete = True
        self._update_label(
            f"[bold #00ff9c]Campaign complete ✓[/bold #00ff9c]  ·  "
            f"press [bold]r[/bold] to view reports, [bold]Esc[/bold] for menu"
        )
        self._update_stats()

    # ── Event → UI ─────────────────────────────────────────────────────────

    def _handle_event(self, evt: Dict[str, Any]) -> None:
        etype = evt.get("type", "")
        ts = evt.get("timestamp", "")[11:19] if evt.get("timestamp") else \
            datetime.utcnow().strftime("%H:%M:%S")
        name = evt.get("name") or evt.get("phase") or ""
        if etype == "phase_start":
            # _log() targets a markup=False Static, so name is safe there;
            # _update_label() targets a markup=True widget, so we escape.
            self._log(f"{ts}  ▶  {name}")
            self._update_label(
                f"[bold #00ff9c]Phase {min(self._phase_done + 1, _TOTAL_PHASES)}/"
                f"{_TOTAL_PHASES} — {_rich_escape(name)}[/bold #00ff9c]"
                f"  ·  Campaign [dim]{_rich_escape(self.campaign_id)}[/dim]"
            )
        elif etype == "phase_end":
            self._phase_done += 1
            self._log(
                f"{ts}  ✓  {name}  ({evt.get('findings_count', 0)} findings, "
                f"${evt.get('cost_usd', 0.0):.2f})"
            )
            try:
                self.query_one("#phase-bar", ProgressBar).advance(1)
            except Exception:
                pass
            self._update_stats()
        elif etype == "phase_skipped":
            self._phase_done += 1
            self._log(f"{ts}  ⏭  Skipped {name} ({evt.get('reason')})")
            try:
                self.query_one("#phase-bar", ProgressBar).advance(1)
            except Exception:
                pass
        elif etype == "dispatch_decision":
            self._log(
                f"{ts}  ↻  Dispatcher fired after {evt.get('phase')} "
                f"— {evt.get('dispatched', 0)} follow-up tools"
            )
        elif etype == "campaign_error":
            self._log(f"{ts}  ⚠  {evt.get('phase')}/{evt.get('subsystem')}: {evt.get('error')}")
        elif etype == "campaign_complete":
            self._log(
                f"{ts}  ★  All phases done — "
                f"{evt.get('total_findings', 0)} findings, "
                f"${evt.get('total_cost_usd', 0.0):.2f} spent"
            )

    def _log(self, line: str) -> None:
        self._activity.append(line)
        try:
            widget = self.query_one("#activity-log", Static)
            widget.update("\n".join(self._activity))
        except Exception:
            pass

    def _update_label(self, text: str) -> None:
        try:
            self.query_one("#phase-label", Static).update(text)
        except Exception:
            pass

    def _update_stats(self) -> None:
        s = self._state or {}
        findings = len(s.get("findings", []))
        subs = len(s.get("subdomain_intel", {}))
        emails = len(s.get("email_intel", {}).get("emails", {}))
        cloud = len(s.get("cloud_intel", {}))
        ranked = len(s.get("ranked_threads", []))
        cost = float(s.get("llm_cost_usd", 0.0))
        budget = float(s.get("max_llm_cost_usd", 0.0)) or 1.0
        stats = (
            f"  [bold]Findings:[/bold] {findings:<6}"
            f"[bold]Ranked threats:[/bold] {ranked or 'pending'}\n"
            f"  [bold]Subdomains:[/bold] {subs:<6}"
            f"[bold]Emails:[/bold] {emails}\n"
            f"  [bold]Cloud sources:[/bold] {cloud:<4}"
            f"[bold]LLM cost:[/bold] ${cost:.2f} / ${budget:.2f}"
        )
        try:
            self.query_one("#runner-stats", Static).update(stats)
        except Exception:
            pass

    # ── Actions ────────────────────────────────────────────────────────────

    async def action_abort(self) -> None:
        if self._complete:
            self.app.exit()
            return
        # No clean abort path (yet) — log and stay
        self._log("Abort requested — press Ctrl-Q to force quit, or wait for completion.")

    async def action_pause(self) -> None:
        self._log("Pause not implemented in v1.")

    async def action_go_results(self) -> None:
        if not self._complete:
            self._log("Campaign still running — wait for completion before opening reports.")
            return
        from nexusrecon.tui.screens.results import ResultsScreen
        await self.app.push_screen(ResultsScreen(
            campaign_dir=self.campaign_dir,
            state=self._state,
        ))

    async def action_back(self) -> None:
        if self._complete:
            self.app.pop_screen()

    def action_quit_app(self) -> None:
        self.app.exit()

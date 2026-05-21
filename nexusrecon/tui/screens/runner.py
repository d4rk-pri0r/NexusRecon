"""Live campaign progress screen.

Four stacked regions, matching the visual language of the welcome /
wizard screens:

  1. **runner-header** — bordered panel whose border-title shows the
     campaign id. Body has a center-aligned phase label, a dim subtitle
     line, and a full-width :class:`ChunkyBar` progress widget.
  2. **runner-stats** — bordered panel, two-column grid of live counters
     (findings, subdomains, emails, cloud sources, ranked threats,
     LLM cost vs budget, phase, elapsed time). Refreshed on a 1 Hz
     interval so elapsed time / cost tick smoothly between phase
     boundaries.
  3. **runner-activity-wrap** — bordered scroll region for the
     high-level event timeline (phase starts / ends / dispatch
     decisions). Marker characters only — operator-friendly.
  4. **runner-detail-wrap** — bordered scroll region that tails the
     per-session structlog log file at
     ``self.app.session_log_path``. This is where the fine-grained
     stuff lives: ``log.info("Dynamic dispatcher executing count=5")``,
     ``log.info("Phase 2: Identity and cloud recon")``, agent
     attribution-gating reports, individual tool failures. Newer
     operators can ignore it; advanced users see exactly what the
     framework is doing in real time.

The previous layout sat a tiny phase indicator in the top-left, used
Textual's default thin ``ProgressBar`` (easy to miss), and only updated
stats on phase boundaries (so the "Elapsed" counter would freeze for
30–60s at a time). This layout fills the viewport with bordered panels
that match the rest of the TUI, gives the phase indicator and progress
bar enough visual weight to read from across the room, and ticks live
data once a second so the operator feels the campaign is alive.
"""
from __future__ import annotations

import asyncio
import time
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import Any

from rich.markup import escape as _rich_escape
from textual import work
from textual.app import ComposeResult
from textual.containers import Container, VerticalScroll
from textual.reactive import reactive
from textual.screen import Screen
from textual.widgets import Footer, Header, Static

_TOTAL_PHASES = 10  # phase1..phase8 + phase7_5 + phase9


# ── Custom widgets ─────────────────────────────────────────────────────────


class ChunkyBar(Static):
    """A wide, visually loud progress bar.

    Renders as a horizontal wall of ``█`` blocks — filled portion in the
    accent green, unfilled portion in dim navy — with a bold percentage
    suffix. Fills the full width of its container, so the operator gets
    a bar the width of the whole header panel instead of Textual's
    default thin micro-bar tucked into the top-left.

    Listens to ``progress`` (reactive int) and ``total`` (passed at
    construction). Both can be updated from outside; the widget
    re-renders on the next event loop tick.
    """

    DEFAULT_CSS = """
    ChunkyBar {
        width: 100%;
        height: 1;
        content-align: center middle;
    }
    """

    progress: reactive[int] = reactive(0)

    def __init__(self, total: int = 10, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.total = max(1, total)

    def watch_progress(self, _old: int, _new: int) -> None:
        self._render_bar()

    def on_resize(self) -> None:
        self._render_bar()

    def on_mount(self) -> None:
        self._render_bar()

    def _render_bar(self) -> None:
        # Leave 8 cells for the trailing " 100%" + a single space.
        bar_cells = max(1, self.size.width - 8)
        pct = max(0.0, min(1.0, self.progress / self.total))
        filled = int(round(bar_cells * pct))
        empty = bar_cells - filled
        # Two contrasting colours so the bar reads as "fill vs track"
        # at a glance: bright green for filled, subtle navy for empty.
        filled_block = ("█" * filled) if filled else ""
        empty_block = ("█" * empty) if empty else ""
        pct_text = f"{int(pct * 100):3d}%"
        self.update(
            f"[bold #00ff9c]{filled_block}[/bold #00ff9c]"
            f"[#1a2030]{empty_block}[/#1a2030] "
            f"[bold #00ff9c]{pct_text}[/bold #00ff9c]"
        )


class _LogTailer:
    """File-position-tracking tail reader for the session log file.

    Each call to :meth:`read_new` returns whatever was appended to the
    log since the last call. Returns an empty list if the file doesn't
    exist yet (e.g. log path is None or file hasn't been created)."""

    def __init__(self, path: Path | None) -> None:
        self.path = path
        self._pos = 0

    def read_new(self) -> list[str]:
        if not self.path:
            return []
        try:
            with open(self.path, encoding="utf-8", errors="replace") as f:
                f.seek(self._pos)
                data = f.read()
                self._pos = f.tell()
        except FileNotFoundError:
            return []
        except Exception:
            return []
        return [line for line in data.splitlines() if line.strip()]


# ── Runner screen ──────────────────────────────────────────────────────────


class RunnerScreen(Screen):
    """Runs a campaign and displays live progress + recent activity."""

    # Footer-displayed bindings. We deliberately do NOT include a
    # ``Pause`` binding here even though older versions of this screen
    # advertised one — the underlying campaign runner has no cooperative
    # checkpointing to pause at, so the binding existed only to print
    # "Pause not implemented in v1" into the activity feed. Better to
    # not advertise a feature than to advertise one that lies.
    BINDINGS = [
        ("q", "abort", "Abort"),
        ("r", "go_results", "Reports"),
        ("d", "toggle_detail", "Detail"),
        ("escape", "back", "Back"),
        ("ctrl+q", "quit_app", "Quit"),
    ]

    # Window during which a second press of Q (or Esc, while running)
    # confirms an abort. Short enough that the operator must intend the
    # second press; long enough that they can read the warning toast.
    ABORT_CONFIRM_SECONDS = 3.0

    # How often to refresh stats (elapsed time, cost gauge, etc.). 1 Hz
    # is fast enough that the operator feels things tick but slow enough
    # to be invisible cost.
    STATS_INTERVAL = 1.0

    # How often to poll the structlog session log for new lines. Slightly
    # faster than the stats refresh so detail messages feel responsive.
    DETAIL_INTERVAL = 0.7

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
        self._activity: deque[str] = deque(maxlen=200)
        self._detail_lines: deque[str] = deque(maxlen=500)
        self._phase_done = 0
        self._state: dict[str, Any] = {}
        self._complete = False
        self._aborted = False
        self._started_at: float = time.monotonic()
        self._log_tailer: _LogTailer | None = None
        self._detail_visible: bool = True
        # Reference to the running campaign worker so ``action_abort``
        # can actually cancel the in-flight asyncio task. Populated in
        # ``on_mount`` when the worker is kicked off.
        self._worker: Any = None
        # Two-press abort confirmation flag. First press sets this and
        # shows a toast; second press within ABORT_CONFIRM_SECONDS does
        # the real abort. The flag auto-clears on a timer so a stray
        # keypress doesn't leave the screen primed indefinitely.
        self._abort_pending: bool = False

    # ── Layout ─────────────────────────────────────────────────────────────

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)

        # 1) Top header panel — campaign id in the border title, big phase
        #    indicator + full-width chunky progress bar in the body.
        with Container(id="runner-header") as header:
            header.border_title = "Campaign"
            yield Static(
                "[bold #00ff9c]Initializing campaign…[/bold #00ff9c]",
                id="runner-phase-label",
            )
            yield Static(
                "[dim]Loading framework, validating scope, "
                "preparing workspace…[/dim]",
                id="runner-phase-sub",
            )
            yield ChunkyBar(total=_TOTAL_PHASES, id="runner-progress")

        # 2) Live stats panel.
        with Container(id="runner-stats") as stats:
            stats.border_title = "Live stats"
            yield Static("", id="runner-stats-body")

        # 3) Activity log — high-level event stream.
        with Container(id="runner-activity-wrap") as wrap:
            wrap.border_title = "Activity  ·  high-level events"
            yield VerticalScroll(
                Static("", id="activity-log", markup=False),
                id="runner-activity",
            )

        # 4) Detail panel — tails the structlog session log.
        with Container(id="runner-detail-wrap") as detail:
            detail.border_title = (
                "Detail  ·  structlog stream (press [d] to toggle)"
            )
            yield VerticalScroll(
                Static("", id="detail-log", markup=False),
                id="runner-detail",
            )

        yield Footer()

    async def on_mount(self) -> None:
        # Paint the placeholder layout immediately so the operator sees
        # the new screen the moment they press "Save & Run". The campaign
        # worker boots in the background while they read the layout.
        self._update_stats()
        self._log(
            f"{datetime.utcnow().strftime('%H:%M:%S')}  •  "
            f"Preparing campaign workspace…"
        )

        # Tail the session log file so the Detail panel shows the
        # fine-grained structlog stream — phase entries, dispatcher
        # decisions, attribution-gating reports, individual tool errors.
        log_path = getattr(self.app, "session_log_path", None)
        if log_path is not None:
            self._log_tailer = _LogTailer(log_path)
            self._detail("─" * 60)
            self._detail(f"Tailing session log: {log_path}")
            self._detail("─" * 60)
            self.set_interval(self.DETAIL_INTERVAL, self._tail_detail)
        else:
            self._detail(
                "(no session log path on app — Detail panel will stay empty)"
            )

        # Refresh stats once a second — keeps "Elapsed", "LLM cost", and
        # any reactive counters ticking smoothly even between phase
        # boundaries (which fire every 30+ seconds).
        self.set_interval(self.STATS_INTERVAL, self._update_stats)

        # Now kick off the worker that actually runs the campaign.
        # Keep the worker reference so ``action_abort`` can cancel it.
        self._worker = self._run_campaign_worker()

    # ── Worker ─────────────────────────────────────────────────────────────

    @work(exclusive=True)
    async def _run_campaign_worker(self) -> None:
        """Run the campaign on the same event loop.

        Three terminal states:
        - **Success**: ``_run`` returns normally → screen marks the
          campaign complete and offers the reports.
        - **Cancelled**: operator pressed ``q`` (confirmed) →
          ``asyncio.CancelledError`` raised at an await point, caught
          here, partial state is on disk (the runner saves after every
          phase) and the operator can resume later.
        - **Failed**: any other exception → escaped and surfaced in the
          header so the operator can see what broke instead of just
          seeing the spinner stop.
        """
        try:
            await self._run()
        except asyncio.CancelledError:
            # Operator-initiated abort. campaign_runner saves state
            # after every phase, so anything completed before the
            # cancel point is preserved on disk for ``nexusrecon
            # resume``.
            self._aborted = True
            self._complete = True
            self._update_label(
                "[bold #ffa500]Campaign aborted by operator[/bold #ffa500]",
                sub=(
                    f"[dim]Partial state saved. Resume from the menu "
                    f"with:[/dim]  [bold]nexusrecon resume "
                    f"{_rich_escape(self.campaign_id or '<id>')}[/bold]"
                ),
            )
            self._log(
                f"{datetime.utcnow().strftime('%H:%M:%S')}  ⨯  "
                f"Campaign aborted — press Esc to return to menu."
            )
            self.notify(
                "Campaign aborted. Partial state saved for resume.",
                severity="warning",
                timeout=5,
            )
            return  # Do not re-raise — let the worker terminate cleanly.
        except Exception as exc:
            # Exception strings can contain Rich-markup-poisoning characters
            # (e.g. Pydantic ValidationError's `[type=enum, input_value='...']`
            # annotation parses as a malformed markup tag and crashes the
            # screen renderer). Escape before splicing into a markup template.
            safe = _rich_escape(str(exc))
            self._log(f"FATAL: {safe}")
            self._complete = True
            self._update_label(
                "[bold #ff5555]Campaign failed[/bold #ff5555]",
                sub=f"[#ff5555]{safe}[/#ff5555]",
            )

    async def _run(self) -> None:
        # These imports are warmed up at welcome-screen mount (see
        # ``welcome.py::_warm_imports``) so they should be near-instant
        # cache hits by the time the operator clicks Save & Run. On a
        # totally cold path (no welcome screen visit, e.g. tests) they
        # still work — they just take 30+s.
        from nexusrecon.core.campaign import CampaignManager
        from nexusrecon.core.campaign_runner import run_campaign
        from nexusrecon.core.scope import ScopeGuard, ScopeModel
        from nexusrecon.models.campaign import CampaignMode
        from nexusrecon.reports.engine import ReportEngine
        from nexusrecon.tools.registry import get_registry

        scope_model = ScopeModel.from_yaml(self.scope_path)
        campaign = CampaignManager(
            scope=scope_model,
            mode=CampaignMode(self.mode),
        )
        campaign.setup()
        self.campaign_id = campaign.campaign_id
        self.campaign_dir = str(campaign.campaign_dir)
        try:
            self.query_one("#runner-header", Container).border_title = (
                f"Campaign  {self.campaign_id}"
            )
        except Exception:
            pass
        self._update_label(
            "[bold #00ff9c]Preparing[/bold #00ff9c]",
            sub=(
                f"[dim]Mode: {self.mode}  ·  Dispatch: {self.dispatch_mode}  "
                f"·  Tier cap: {scope_model.constraints.max_tier}[/dim]"
            ),
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

        state: dict[str, Any] = {
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

        def on_event(evt: dict[str, Any]) -> None:
            self._handle_event(evt)

        state = await run_campaign(state, campaign, scope_model, on_event=on_event)
        self._state = state

        self._log("Generating reports…")
        self._update_label(
            "[bold #00ff9c]Generating reports[/bold #00ff9c]",
            sub="[dim]Synthesising master report, top threads, deliverables…[/dim]",
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
        try:
            bar = self.query_one("#runner-progress", ChunkyBar)
            bar.progress = _TOTAL_PHASES
        except Exception:
            pass
        self._update_label(
            "[bold #00ff9c]Campaign complete  ✓[/bold #00ff9c]",
            sub=(
                "[dim]Press [/dim][bold]r[/bold][dim] to view reports, "
                "[/dim][bold]Esc[/bold][dim] to return to menu.[/dim]"
            ),
        )
        self._update_stats()

    # ── Event → UI ─────────────────────────────────────────────────────────

    def _handle_event(self, evt: dict[str, Any]) -> None:
        etype = evt.get("type", "")
        ts = evt.get("timestamp", "")[11:19] if evt.get("timestamp") else \
            datetime.utcnow().strftime("%H:%M:%S")
        name = evt.get("name") or evt.get("phase") or ""
        if etype == "phase_start":
            self._log(f"{ts}  ▶  {name}")
            self._update_label(
                (
                    f"[bold #00ff9c]Phase "
                    f"{min(self._phase_done + 1, _TOTAL_PHASES)} / "
                    f"{_TOTAL_PHASES}  —  {_rich_escape(name)}"
                    f"[/bold #00ff9c]"
                ),
                sub=(
                    f"[dim]Mode: {self.mode}  ·  Dispatch: "
                    f"{self.dispatch_mode}[/dim]"
                ),
            )
        elif etype == "phase_end":
            self._phase_done += 1
            self._log(
                f"{ts}  ✓  {name}  ({evt.get('findings_count', 0)} findings, "
                f"${evt.get('cost_usd', 0.0):.2f})"
            )
            try:
                self.query_one("#runner-progress", ChunkyBar).progress = self._phase_done
            except Exception:
                pass
            self._update_stats()
        elif etype == "phase_skipped":
            self._phase_done += 1
            self._log(f"{ts}  ⏭  Skipped {name} ({evt.get('reason')})")
            try:
                self.query_one("#runner-progress", ChunkyBar).progress = self._phase_done
            except Exception:
                pass
        elif etype == "dispatch_decision":
            self._log(
                f"{ts}  ↻  Dispatcher fired after {evt.get('phase')} "
                f"— {evt.get('dispatched', 0)} follow-up tools"
            )
        elif etype == "campaign_error":
            self._log(
                f"{ts}  ⚠  {evt.get('phase')}/{evt.get('subsystem')}: "
                f"{evt.get('error')}"
            )
        elif etype == "campaign_complete":
            self._log(
                f"{ts}  ★  All phases done — "
                f"{evt.get('total_findings', 0)} findings, "
                f"${evt.get('total_cost_usd', 0.0):.2f} spent"
            )

    # ── Output helpers ─────────────────────────────────────────────────────

    def _log(self, line: str) -> None:
        """Append a line to the high-level Activity feed."""
        self._activity.append(line)
        try:
            widget = self.query_one("#activity-log", Static)
            widget.update("\n".join(self._activity))
            self.query_one("#runner-activity", VerticalScroll).scroll_end(
                animate=False
            )
        except Exception:
            pass

    def _detail(self, line: str) -> None:
        """Append a line to the low-level Detail feed (markup=False)."""
        self._detail_lines.append(line)
        try:
            widget = self.query_one("#detail-log", Static)
            widget.update("\n".join(self._detail_lines))
            self.query_one("#runner-detail", VerticalScroll).scroll_end(
                animate=False
            )
        except Exception:
            pass

    def _tail_detail(self) -> None:
        """Periodic timer callback — drains new structlog lines into the
        Detail panel. Called every ``DETAIL_INTERVAL`` seconds."""
        if not self._log_tailer:
            return
        new_lines = self._log_tailer.read_new()
        if not new_lines:
            return
        for line in new_lines:
            self._detail_lines.append(line)
        try:
            widget = self.query_one("#detail-log", Static)
            widget.update("\n".join(self._detail_lines))
            self.query_one("#runner-detail", VerticalScroll).scroll_end(
                animate=False
            )
        except Exception:
            pass

    def _update_label(self, text: str, sub: str | None = None) -> None:
        """Update the big phase indicator (top of screen)."""
        try:
            self.query_one("#runner-phase-label", Static).update(text)
        except Exception:
            pass
        if sub is not None:
            try:
                self.query_one("#runner-phase-sub", Static).update(sub)
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
        elapsed = int(time.monotonic() - self._started_at)
        mins, secs = divmod(elapsed, 60)

        col_a = [
            ("Findings",        f"{findings}"),
            ("Subdomains",      f"{subs}"),
            ("Emails",          f"{emails}"),
            ("Cloud sources",   f"{cloud}"),
        ]
        col_b = [
            ("Phase",           f"{self._phase_done} / {_TOTAL_PHASES}"),
            ("Ranked threats",  f"{ranked or '—'}"),
            ("LLM cost",        f"${cost:.2f} / ${budget:.2f}"),
            ("Elapsed",         f"{mins:d}m {secs:02d}s"),
        ]

        lines = []
        for (la, va), (lb, vb) in zip(col_a, col_b):
            lines.append(
                f"  [bold #00ff9c]{la:<14}[/bold #00ff9c] {va:<14}  "
                f"[bold #00ff9c]{lb:<16}[/bold #00ff9c] {vb}"
            )
        try:
            self.query_one("#runner-stats-body", Static).update("\n".join(lines))
        except Exception:
            pass

    # ── Actions ────────────────────────────────────────────────────────────

    async def action_abort(self) -> None:
        """``q`` — abort the running campaign with a two-press confirm.

        Once a campaign has finished (or aborted), this acts as
        "return to menu" so the binding stays meaningful end-to-end.

        While running: first press primes the abort and shows a warning
        toast; a second press within ``ABORT_CONFIRM_SECONDS`` cancels
        the worker. The flag self-clears on a timer if the operator
        doesn't follow through, so a stray Q press can't leave the
        screen primed indefinitely.
        """
        if self._complete:
            # Whether we finished cleanly, aborted, or failed — Q now
            # means "I'm done with this screen". Pop back to the menu.
            self.app.pop_screen()
            return

        if not self._abort_pending:
            self._abort_pending = True
            self.notify(
                "Press Q (or Esc) again within 3s to abort. "
                "Partial state will be saved for resume.",
                title="Abort campaign?",
                severity="warning",
                timeout=self.ABORT_CONFIRM_SECONDS,
            )
            self.set_timer(
                self.ABORT_CONFIRM_SECONDS, self._clear_abort_pending
            )
            return

        # Second press inside the confirm window — actually abort.
        self._abort_pending = False
        self._log(
            f"{datetime.utcnow().strftime('%H:%M:%S')}  ⨯  "
            f"Aborting…"
        )
        if self._worker is not None:
            try:
                self._worker.cancel()
            except Exception:
                pass
        # The worker's CancelledError branch will update the header
        # label, show the resume hint, and flip _complete=True.

    def _clear_abort_pending(self) -> None:
        """Timer callback — resets the abort-confirmation flag if the
        operator didn't press the key a second time. Called by
        ``set_timer`` in ``action_abort``."""
        self._abort_pending = False

    async def action_go_results(self) -> None:
        """``r`` — open the reports screen if the campaign is done,
        otherwise tell the operator (via a visible toast, not a log
        line that scrolls away) that reports aren't ready yet."""
        if not self._complete:
            self.notify(
                "Reports are generated after the final phase. "
                "Wait for the campaign to complete (or press Q to "
                "abort with partial output).",
                title="Reports not ready",
                severity="information",
                timeout=4,
            )
            return
        from nexusrecon.tui.screens.results import ResultsScreen
        await self.app.push_screen(ResultsScreen(
            campaign_dir=self.campaign_dir,
            state=self._state,
        ))

    async def action_back(self) -> None:
        """``esc`` — same semantics as Q. While running, prompts for
        abort confirmation; once complete, pops back to the menu.
        Unified so the operator doesn't have to remember which key
        does what in which state."""
        await self.action_abort()

    def action_quit_app(self) -> None:
        """``ctrl+q`` — force-quit the whole TUI. No confirmation
        because Ctrl-Q is the documented panic-exit shortcut; if you
        want a gentle abort, use Q."""
        self.app.exit()

    def action_toggle_detail(self) -> None:
        """``d`` — show/hide the Detail panel. Operators who only care
        about the high-level Activity feed can press ``d`` to collapse
        the structlog stream and let Activity expand to fill the
        bottom half of the screen."""
        try:
            detail = self.query_one("#runner-detail-wrap", Container)
            self._detail_visible = not self._detail_visible
            detail.display = self._detail_visible
            self.notify(
                "Detail panel "
                + ("shown" if self._detail_visible else "hidden"),
                timeout=2,
            )
        except Exception:
            pass

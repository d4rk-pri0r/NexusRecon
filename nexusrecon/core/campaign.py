"""
Campaign lifecycle management — creates, tracks, and manages campaigns.

Handles: campaign directory setup, ID generation, ROE banner display,
scope hash embedding, report directory organization, and diff/resume.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import structlog
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from nexusrecon.core.audit import AuditLog
from nexusrecon.core.cache import Cache
from nexusrecon.core.config import NexusConfig, get_config
from nexusrecon.core.cost_tracker import CostTracker
from nexusrecon.core.entity_graph import EntityGraph
from nexusrecon.models.campaign import CampaignMode, CampaignState
from nexusrecon.models.scope import ScopeModel

log = structlog.get_logger(__name__)
console = Console()

ROE_BANNER = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                        NEXUSRECON — RULES OF ENGAGEMENT                    ║
║                                                                              ║
║  This tool is authorized for use ONLY against assets explicitly listed     ║
║  in the signed scope file.  All activity is logged and audit-chained.      ║
║                                                                              ║
║  Unauthorized use is a criminal offense.  See DISCLAIMER.md.               ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""


class CampaignManager:
    """
    Manages the full lifecycle of a NexusRecon campaign.

    Creates campaign directories, initializes audit log, cache, entity graph,
    and cost tracker.  Handles state persistence and resume logic.
    """

    def __init__(
        self,
        scope: ScopeModel,
        mode: CampaignMode = CampaignMode.MEDIUM,
        config: Optional[NexusConfig] = None,
        campaign_id: Optional[str] = None,
    ) -> None:
        self.scope = scope
        self.mode = mode
        self.config = config or get_config()

        # Campaign ID: new or resume
        self.campaign_id = campaign_id or self._generate_id()
        self.is_resume = campaign_id is not None

        # Directory structure
        self.output_dir = Path(self.config.output_dir)
        self.campaign_dir = (
            self.output_dir
            / scope.engagement.client.replace(" ", "_").lower()
            / scope.engagement.engagement_id
            / self.campaign_id
        )
        self.report_dir = self.campaign_dir / "reports"
        self.artifacts_dir = self.campaign_dir / "artifacts"
        self.logs_dir = self.campaign_dir / "logs"

        # Core components (initialized in setup())
        self.audit_log: Optional[AuditLog] = None
        self.cache: Optional[Cache] = None
        self.entity_graph: Optional[EntityGraph] = None
        self.cost_tracker: Optional[CostTracker] = None
        self.state: Optional[CampaignState] = None
        # Live execution dict — set by save_state() after each phase so that
        # _save_state() serialises real phase output rather than the empty skeleton.
        self._live_dict: Optional[Dict[str, Any]] = None

    def _generate_id(self) -> str:
        ts = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
        uid = str(uuid.uuid4())[:8]
        return f"nr-{ts}-{uid}"

    # ── Setup ─────────────────────────────────────────────────────────────────

    def setup(self) -> "CampaignManager":
        """Initialize all campaign infrastructure. Must be called before use."""
        self._create_directories()
        self._display_roe_banner()
        self._init_components()
        self._write_scope_metadata()

        if self.is_resume:
            self._load_state()
        else:
            self._init_state()

        return self

    def _create_directories(self) -> None:
        for d in [self.campaign_dir, self.report_dir, self.artifacts_dir, self.logs_dir]:
            d.mkdir(parents=True, exist_ok=True)

    def _display_roe_banner(self) -> None:
        """Display ROE banner and log it to the audit trail."""
        console.print(ROE_BANNER, style="bold yellow")
        e = self.scope.engagement
        summary = Text()
        summary.append("Client:       ", style="bold")
        summary.append(f"{e.client}\n")
        summary.append("Engagement:   ", style="bold")
        summary.append(f"{e.engagement_id}\n")
        summary.append("Authorized:   ", style="bold")
        summary.append(f"{e.authorized_by} ({e.authorization_date})\n")
        summary.append("Period:       ", style="bold")
        summary.append(f"{e.start_date} → {e.end_date}\n")
        summary.append("Max Tier:     ", style="bold")
        summary.append(f"{self.scope.constraints.max_tier}\n")
        summary.append("Stealth:      ", style="bold")
        summary.append(f"{self.scope.constraints.stealth_profile}\n")
        summary.append("Scope Hash:   ", style="bold")
        summary.append(f"{self.scope.scope_hash}\n")
        summary.append("Campaign ID:  ", style="bold")
        summary.append(self.campaign_id)

        console.print(Panel(summary, title="[bold green]Engagement Context[/]", border_style="green"))

    def _init_components(self) -> None:
        db_path = self.campaign_dir / "nexusrecon.db"

        self.audit_log = AuditLog(
            log_path=self.logs_dir / "audit.jsonl",
            campaign_id=self.campaign_id,
            scope_hash=self.scope.scope_hash or "",
        )
        self.cache = Cache(db_path=db_path)
        self.entity_graph = EntityGraph(
            campaign_id=self.campaign_id,
            engagement_id=self.scope.engagement.engagement_id,
        )
        self.cost_tracker = CostTracker(
            campaign_id=self.campaign_id,
            max_llm_cost_usd=self.scope.constraints.max_llm_cost_usd,
        )

    def _write_scope_metadata(self) -> None:
        """Write scope metadata JSON for legal defensibility."""
        meta = {
            "campaign_id": self.campaign_id,
            "scope_hash": self.scope.scope_hash,
            "scope_file_path": self.scope.scope_file_path,
            "engagement": self.scope.engagement.model_dump(),
            "constraints": self.scope.constraints.model_dump(),
            "created_at": datetime.utcnow().isoformat(),
        }
        meta_path = self.campaign_dir / "scope_metadata.json"
        meta_path.write_text(json.dumps(meta, indent=2, default=str), encoding="utf-8")

    def _init_state(self) -> None:
        """Initialize a fresh campaign state."""
        self.state = CampaignState(
            campaign_id=self.campaign_id,
            engagement_id=self.scope.engagement.engagement_id,
            mode=self.mode,
            scope_hash=self.scope.scope_hash or "",
        )
        self._save_state()

    def _load_state(self) -> None:
        """Load existing campaign state for resume."""
        state_path = self.campaign_dir / "state.json"
        if state_path.exists():
            data = json.loads(state_path.read_text(encoding="utf-8"))
            self.state = CampaignState.model_validate(data)
            log.info(
                "Resumed campaign state",
                campaign_id=self.campaign_id,
                completed_phases=self.state.completed_phases,
                findings=len(self.state.findings),
            )
            console.print(
                f"[bold green]Resumed campaign {self.campaign_id}[/] — "
                f"continuing from phase: [cyan]{self.state.current_phase}[/]"
            )
        else:
            log.warning("No state file found for resume — starting fresh")
            self._init_state()

    def _save_state(self) -> None:
        """Persist campaign state to JSON.

        Prefers ``_live_dict`` (the execution state dict updated by phase nodes)
        over the pydantic ``CampaignState`` skeleton.  Falls back to the pydantic
        model for the very first checkpoint written during ``_init_state()``
        (before any phase has run and ``_live_dict`` is still ``None``).
        """
        state_path = self.campaign_dir / "state.json"
        if self._live_dict is not None:
            state_path.write_text(
                json.dumps(self._live_dict, indent=2, default=str),
                encoding="utf-8",
            )
        elif self.state is not None:
            state_path.write_text(
                self.state.model_dump_json(indent=2),
                encoding="utf-8",
            )

    def save_state(self, state_dict: Dict[str, Any]) -> None:
        """Persist the live execution state dict to disk.

        Called by the CLI loop after each phase so that ``state.json`` always
        reflects the current execution state rather than the empty pydantic
        skeleton.  Also invoked by ``finalize()`` at campaign end.
        """
        self._live_dict = state_dict
        self._save_state()

    # ── Phase lifecycle ───────────────────────────────────────────────────────

    def begin_phase(self, phase_name: str, agent_name: str) -> None:
        """Mark a phase as started."""
        if self.audit_log:
            self.audit_log.log_phase_start(phase_name, agent_name)
        if self.state:
            self.state.current_phase = phase_name
            self.state.touch()
            self._save_state()

    def end_phase(
        self,
        phase_name: str,
        findings_count: int,
        entities_count: int,
    ) -> None:
        """Mark a phase as completed and checkpoint state."""
        cost_usd = self.cost_tracker.total_llm_cost_usd if self.cost_tracker else 0.0
        if self.audit_log:
            self.audit_log.log_phase_end(phase_name, findings_count, entities_count, cost_usd)
        if self.state:
            self.state.mark_phase_complete(phase_name)
            self._save_state()

    # ── Report path management ────────────────────────────────────────────────

    def report_path(self, filename: str) -> Path:
        """Return the full path for a report file."""
        return self.report_dir / filename

    def artifact_path(self, filename: str) -> Path:
        """Return the full path for an artifact file."""
        return self.artifacts_dir / filename

    # ── Diff against last run ─────────────────────────────────────────────────

    @classmethod
    def diff_campaigns(cls, old_campaign_dir: str | Path, new_campaign_dir: str | Path) -> Dict[str, Any]:
        """
        Compute diff between two campaign states.
        Returns new findings, new entities, and changed entities.
        """
        old_path = Path(old_campaign_dir) / "state.json"
        new_path = Path(new_campaign_dir) / "state.json"

        if not old_path.exists() or not new_path.exists():
            return {"error": "One or both state files not found"}

        old_state = json.loads(old_path.read_text())
        new_state = json.loads(new_path.read_text())

        old_finding_ids = {f.get("finding_id") for f in old_state.get("findings", [])}
        new_findings = [
            f for f in new_state.get("findings", [])
            if f.get("finding_id") not in old_finding_ids
        ]

        return {
            "old_campaign": old_state.get("campaign_id"),
            "new_campaign": new_state.get("campaign_id"),
            "new_findings": new_findings,
            "new_finding_count": len(new_findings),
            "old_finding_count": len(old_state.get("findings", [])),
            "new_total_finding_count": len(new_state.get("findings", [])),
        }

    def finalize(self) -> Dict[str, Any]:
        """Finalize campaign: save state, verify audit chain, return summary."""
        self._save_state()

        chain_ok = self.audit_log.verify_chain() if self.audit_log else True
        cost_summary = self.cost_tracker.summary() if self.cost_tracker else {}
        graph_stats = self.entity_graph.stats() if self.entity_graph else {}

        # Prefer live execution dict for counts; fall back to pydantic model skeleton.
        findings_count = (
            len(self._live_dict.get("findings", []))
            if self._live_dict is not None
            else (len(self.state.findings) if self.state else 0)
        )
        report_paths_for_log: Dict[str, Any] = (
            self._live_dict.get("report_paths", {})
            if self._live_dict is not None
            else (self.state.report_paths if self.state else {})
        )

        if self.audit_log:
            self.audit_log.log_campaign_end(
                findings_total=findings_count,
                report_paths=report_paths_for_log,
            )

        return {
            "campaign_id": self.campaign_id,
            "campaign_dir": str(self.campaign_dir),
            "audit_chain_ok": chain_ok,
            "cost": cost_summary,
            "graph": graph_stats,
            "findings": findings_count,
        }

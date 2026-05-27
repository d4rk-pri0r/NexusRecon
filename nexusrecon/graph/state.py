"""
LangGraph campaign state — TypedDict for the workflow graph.

This is the shared state object that flows through every node in the LangGraph.
It accumulates intelligence, tracks phase progression, and enforces budgets.
"""

from __future__ import annotations

from typing import Any

from typing_extensions import TypedDict


class CampaignGraphState(TypedDict, total=False):
    """
    Mutable state flowing through the LangGraph workflow.

    Each phase node reads and writes to this state.  The final reporter
    node uses this state to generate all deliverables.
    """

    # ── Identity ──────────────────────────────────────────────────────
    campaign_id: str
    engagement_id: str
    scope_hash: str
    seeds: list[str]  # initial targets

    # ── Phase tracking ────────────────────────────────────────────────
    current_phase: str
    completed_phases: list[str]
    phase_results: dict[str, Any]  # {phase_name: {status, findings, ...}}

    # ── Intelligence (accumulates across phases) ──────────────────────
    # Entity graph snapshot (serialized dict)
    entity_graph: dict[str, Any]
    # All findings collected so far
    findings: list[dict[str, Any]]
    # Domain intelligence
    domain_intel: dict[str, Any]
    subdomain_intel: dict[str, Any]
    # Identity intelligence
    email_intel: dict[str, Any]
    identity_intel: dict[str, Any]
    # Cloud intelligence
    cloud_intel: dict[str, Any]
    # Code intelligence
    code_intel: dict[str, Any]
    # Infra intelligence
    infra_intel: dict[str, Any]
    # Vuln intelligence
    vuln_intel: dict[str, Any]
    # Pretext intelligence
    pretext_intel: dict[str, Any]
    # Relationship graph — human-to-human edges populated by Phase E
    # (E1 added the slot; E2-E8 tools populate it via the
    # ``RelationshipGraph.add_edge`` API; E11 commits it to state).
    relationship_graph: dict[str, Any]
    # Pretext scoring output — ranked PretextCandidate dicts produced
    # by Phase 7.7 (E11) from the relationship graph + recent activity.
    pretext_scores: list[dict[str, Any]]
    # Per-target spear-phishing dossiers (E11 deliverable). Always
    # written when Phase 7.7 runs; the per-target ``draft`` field is
    # populated only when ``generate_phishing_drafts`` is True.
    spear_phishing_intelligence: dict[str, Any]
    # Dark-web / paste / ransomwatch intel (Move 1)
    dark_intel: dict[str, Any]
    # Breach/infostealer intel — populated by dynamic dispatch (breach category tools)
    breach_intel: dict[str, Any]
    # Mobile app intel — populated by dynamic dispatch (mobile category tools)
    mobile_intel: dict[str, Any]
    # Social/SOCMINT intel — populated by dynamic dispatch (social category tools)
    social_intel: dict[str, Any]
    # Harvested credentials (Move 2)
    harvested_credentials: list[dict[str, Any]]
    # Dynamic dispatch log (Move 4)
    dynamic_dispatch_log: list[dict[str, Any]]

    # ── Correlation ───────────────────────────────────────────────────
    hypotheses: list[str]
    confirmed_leads: list[str]
    open_questions: list[str]

    # ── Budget ────────────────────────────────────────────────────────
    llm_cost_usd: float
    tool_cost_usd: float
    step_count: int

    # ── Errors / notes ────────────────────────────────────────────────
    errors: list[str]
    agent_messages: list[dict[str, Any]]

    # ── Feature flags ─────────────────────────────────────────────────
    validate_credentials: bool
    generate_phishing_drafts: bool
    dispatch_mode: str  # "lite" | "full" | "off"
    # Optional narrowing of which identities Phase 7.7 scores pretexts
    # for. None / absent = all identities (default). Comma-separated
    # via the --pretext-targets CLI flag, parsed into a list.
    pretext_targets: list[str]
    # When True the report engine emits an Obsidian-flavored parallel
    # of ``master_report.md`` ── YAML frontmatter, [[wikilink]] cross-
    # references, callout-style severity blockquotes. Drop the
    # campaign directory into an Obsidian vault to read.
    generate_obsidian: bool

    # ── Report paths (set at end) ────────────────────────────────────
    report_paths: dict[str, str]

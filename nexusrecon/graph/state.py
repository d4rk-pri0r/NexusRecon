"""
LangGraph campaign state — TypedDict for the workflow graph.

This is the shared state object that flows through every node in the LangGraph.
It accumulates intelligence, tracks phase progression, and enforces budgets.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
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
    seeds: List[str]  # initial targets

    # ── Phase tracking ────────────────────────────────────────────────
    current_phase: str
    completed_phases: List[str]
    phase_results: Dict[str, Any]  # {phase_name: {status, findings, ...}}

    # ── Intelligence (accumulates across phases) ──────────────────────
    # Entity graph snapshot (serialized dict)
    entity_graph: Dict[str, Any]
    # All findings collected so far
    findings: List[Dict[str, Any]]
    # Domain intelligence
    domain_intel: Dict[str, Any]
    subdomain_intel: Dict[str, Any]
    # Identity intelligence
    email_intel: Dict[str, Any]
    identity_intel: Dict[str, Any]
    # Cloud intelligence
    cloud_intel: Dict[str, Any]
    # Code intelligence
    code_intel: Dict[str, Any]
    # Infra intelligence
    infra_intel: Dict[str, Any]
    # Vuln intelligence
    vuln_intel: Dict[str, Any]
    # Pretext intelligence
    pretext_intel: Dict[str, Any]
    # Dark-web / paste / ransomwatch intel (Move 1)
    dark_intel: Dict[str, Any]
    # Breach/infostealer intel — populated by dynamic dispatch (breach category tools)
    breach_intel: Dict[str, Any]
    # Mobile app intel — populated by dynamic dispatch (mobile category tools)
    mobile_intel: Dict[str, Any]
    # Social/SOCMINT intel — populated by dynamic dispatch (social category tools)
    social_intel: Dict[str, Any]
    # Harvested credentials (Move 2)
    harvested_credentials: List[Dict[str, Any]]
    # Dynamic dispatch log (Move 4)
    dynamic_dispatch_log: List[Dict[str, Any]]

    # ── Correlation ───────────────────────────────────────────────────
    hypotheses: List[str]
    confirmed_leads: List[str]
    open_questions: List[str]

    # ── Budget ────────────────────────────────────────────────────────
    llm_cost_usd: float
    tool_cost_usd: float
    step_count: int

    # ── Errors / notes ────────────────────────────────────────────────
    errors: List[str]
    agent_messages: List[Dict[str, Any]]

    # ── Feature flags ─────────────────────────────────────────────────
    validate_credentials: bool
    generate_phishing_drafts: bool
    dispatch_mode: str  # "lite" | "full" | "off"

    # ── Report paths (set at end) ────────────────────────────────────
    report_paths: Dict[str, str]

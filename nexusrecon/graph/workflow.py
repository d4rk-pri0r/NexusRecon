"""
LangGraph workflow builder — constructs the campaign execution graph.

Builds a StateGraph with phase nodes, a reflection node between phases,
and SQLite checkpointing for resume capability.
"""

from __future__ import annotations

from typing import Any, Dict, List

from langgraph.graph import END, StateGraph

from nexusrecon.graph.nodes import (
    phase1_passive_footprinting,
    phase2_identity_cloud,
    phase2_5_personal_identity_pivot,
    phase3_code_leakage,
    phase4_correlation,
    phase5_light_active,
    phase6_active,
    phase7_vuln_pretext,
    phase7_5_harvest,
    phase8_attack_surface,
    phase9_reporting,
    reflection_node,
)
from nexusrecon.graph.state import CampaignGraphState
from nexusrecon.models.campaign import CampaignMode

PHASE_ORDER: List[str] = [
    "phase1", "phase2", "phase2_5", "phase3", "phase4",
    "phase5", "phase6", "phase7", "phase7_5", "phase8", "phase9",
]

# Minimum tier required to run each phase (F-009)
PHASE_TIERS: Dict[str, int] = {
    "phase1": 0, "phase2": 0, "phase2_5": 0, "phase3": 0, "phase4": 0,
    "phase5": 2, "phase6": 3, "phase7": 0, "phase7_5": 0, "phase8": 0, "phase9": 0,
}

# Maximum tier allowed per campaign mode (F-009)
MODE_TIER_LIMITS: Dict[CampaignMode, int] = {
    CampaignMode.LIGHT: 0,
    CampaignMode.MEDIUM: 2,
    CampaignMode.DEEP: 3,
    CampaignMode.MONITOR: 0,
}

PHASE_NODES = {
    "phase1": phase1_passive_footprinting,
    "phase2": phase2_identity_cloud,
    "phase2_5": phase2_5_personal_identity_pivot,
    "phase3": phase3_code_leakage,
    "phase4": phase4_correlation,
    "phase5": phase5_light_active,
    "phase6": phase6_active,
    "phase7": phase7_vuln_pretext,
    "phase7_5": phase7_5_harvest,
    "phase8": phase8_attack_surface,
    "phase9": phase9_reporting,
}


def build_campaign_workflow(
    db_path: str = ":memory:",
    mode: CampaignMode = CampaignMode.MEDIUM,
) -> StateGraph:
    """
    Build the LangGraph StateGraph for a NexusRecon campaign.

    Args:
        db_path: SQLite path for checkpointing. Use ":memory:" for ephemeral.
        mode: Campaign mode — controls which phases are included (F-009).
    """
    tier_limit = MODE_TIER_LIMITS.get(mode, 3)
    active_phases = [p for p in PHASE_ORDER if PHASE_TIERS.get(p, 0) <= tier_limit]

    workflow = StateGraph(CampaignGraphState)

    # Add only the phase nodes allowed by this mode (F-009)
    for phase in active_phases:
        workflow.add_node(phase, PHASE_NODES[phase])
    workflow.add_node("reflect", reflection_node)

    workflow.set_entry_point(active_phases[0])

    # Routing map covers only active phases
    phase_map = {p: p for p in active_phases}
    phase_map["__end__"] = END

    # Each phase (except the last) transitions to the reflection node
    for phase in active_phases[:-1]:
        workflow.add_edge(phase, "reflect")

    # Reflection routes to the next incomplete active phase
    def _route_next(state: CampaignGraphState) -> str:
        completed = set(state.get("completed_phases", []))
        for p in active_phases:
            if p not in completed:
                return p
        return "__end__"

    workflow.add_conditional_edges("reflect", _route_next, phase_map)
    workflow.add_edge(active_phases[-1], END)

    return workflow


async def run_workflow(
    state: Dict[str, Any],
    db_path: str = ":memory:",
    mode: CampaignMode = CampaignMode.MEDIUM,
) -> Dict[str, Any]:
    """
    Convenience: compile and run the campaign workflow with the given initial state.
    Returns the final state after all phases complete (or error).
    """
    workflow = build_campaign_workflow(db_path=db_path, mode=mode)

    # F-005: add SqliteSaver checkpointer so LangGraph can persist and resume state
    try:
        from langgraph.checkpoint.sqlite import SqliteSaver
        checkpointer = SqliteSaver.from_conn_string(db_path)
        app = workflow.compile(checkpointer=checkpointer)
    except Exception:
        app = workflow.compile()

    current = dict(state)

    async for event in app.astream(current):
        for node_name, node_state in event.items():
            if isinstance(node_state, dict):
                current.update(node_state)

    return current

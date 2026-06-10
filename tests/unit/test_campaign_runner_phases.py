"""Regression guard for the default campaign phase list.

``phase2_5`` (personal-identity pivot + credential punch list) and
``phase7_7`` (relationship graph + pretext scoring) are tier-0 passive
phases that produce two marquee deliverables: ``credential_exposure_paths.md``
and ``spear_phishing_intelligence.md``. They were previously reachable only
via the ``--use-graph`` LangGraph path (``graph/workflow.py``) and absent from
``core/campaign_runner.py``'s hardcoded phase list, so a default
``nexusrecon run`` rendered both deliverables empty. These tests pin them onto
the default path and in the correct order so the wiring cannot silently
regress again.
"""
from __future__ import annotations

from typing import Any

import nexusrecon.graph.nodes as nodes
from nexusrecon.core import campaign_runner


class _FakeCampaign:
    audit_log = None
    cost_tracker = None
    campaign_dir = None

    def __init__(self) -> None:
        # (phase_id, findings_count, entities_count) per end_phase call.
        self.end_phase_calls: list[tuple[str, int, int]] = []

    def begin_phase(self, *a: Any, **k: Any) -> None:  # noqa: D401
        pass

    def end_phase(self, phase_name: str, findings_count: int, entities_count: int,
                  *a: Any, **k: Any) -> None:
        self.end_phase_calls.append((phase_name, findings_count, entities_count))

    def save_state(self, *a: Any, **k: Any) -> None:
        pass


class _FakeScope:
    def tier_value(self) -> int:
        # Tier 5 so nothing is skipped for being above the ceiling; this isolates
        # the test to "is the phase in the list" rather than tier gating.
        return 5


_PHASE_ATTR_TO_ID = {
    "phase1_passive_footprinting": "phase1",
    "phase2_identity_cloud": "phase2",
    "phase2_5_personal_identity_pivot": "phase2_5",
    "phase3_code_leakage": "phase3",
    "phase4_correlation": "phase4",
    "phase5_light_active": "phase5",
    "phase6_active": "phase6",
    "phase7_vuln_pretext": "phase7",
    "phase7_5_harvest": "phase7_5",
    "phase7_7_pretext_intelligence": "phase7_7",
    "phase8_attack_surface": "phase8",
    "phase9_reporting": "phase9",
}


async def _run_with_recorders(
    monkeypatch, graph_nodes_at: dict[str, int] | None = None
) -> tuple[list[str], _FakeCampaign]:
    """Run the default campaign with every phase function stubbed by a recorder.

    ``graph_nodes_at`` optionally maps a phase_id to a node count; that phase's
    recorder writes ``state["entity_graph"]`` with that many nodes, mimicking
    phase4/phase8 persisting the built EntityGraph.
    """
    order: list[str] = []
    graph_nodes_at = graph_nodes_at or {}

    def _recorder(phase_id: str):
        async def _fn(state: dict[str, Any]) -> dict[str, Any]:
            order.append(phase_id)
            n = graph_nodes_at.get(phase_id)
            if n is not None:
                state["entity_graph"] = {"nodes": [{"id": i} for i in range(n)]}
            return state

        return _fn

    for attr, pid in _PHASE_ATTR_TO_ID.items():
        monkeypatch.setattr(nodes, attr, _recorder(pid))

    async def _noop_reflection(state: dict[str, Any]) -> dict[str, Any]:
        return state

    monkeypatch.setattr(nodes, "reflection_node", _noop_reflection)
    monkeypatch.setattr(
        nodes, "set_executor_cost_tracker", lambda *a, **k: None, raising=False
    )

    campaign = _FakeCampaign()
    await campaign_runner.run_campaign(
        {"campaign_id": "test"}, campaign, _FakeScope(), on_event=None
    )
    return order, campaign


def test_tier_floor_registers_crown_jewel_phases() -> None:
    assert campaign_runner._PHASE_TIER_FLOOR.get("phase2_5") == 0
    assert campaign_runner._PHASE_TIER_FLOOR.get("phase7_7") == 0


async def test_default_runner_executes_phase2_5_and_phase7_7(monkeypatch) -> None:
    order, _ = await _run_with_recorders(monkeypatch)
    assert "phase2_5" in order, "phase2_5 missing from the default campaign runner"
    assert "phase7_7" in order, "phase7_7 missing from the default campaign runner"


async def test_crown_jewel_phases_run_in_correct_slots(monkeypatch) -> None:
    order, _ = await _run_with_recorders(monkeypatch)
    # phase2_5 runs immediately after corp identity is confirmed (phase2).
    assert order.index("phase2_5") == order.index("phase2") + 1
    # phase7_7 runs immediately after credential harvest (phase7_5) so its
    # pretext quality feeds attack-surface scoring (phase8).
    assert order.index("phase7_7") == order.index("phase7_5") + 1
    assert order.index("phase7_7") < order.index("phase8")


async def test_end_phase_receives_real_entity_count_not_hardcoded_zero(
    monkeypatch,
) -> None:
    """Regression guard for the run-health false alarm. campaign_runner used to
    pass a hardcoded entities_count=0 to end_phase, so run_health.entities_total
    was always 0 and the "entity extraction may be broken" caveat fired on every
    healthy run. The runner must read the real node count from
    state["entity_graph"]["nodes"] (persisted by phase4/phase8)."""
    # phase4 persists a 12-node graph; phase8 grows it to 20.
    order, campaign = await _run_with_recorders(
        monkeypatch, graph_nodes_at={"phase4": 12, "phase8": 20}
    )
    counts = {pid: ents for (pid, _findings, ents) in campaign.end_phase_calls}

    # Phases before phase4 honestly report 0 (no graph built yet).
    assert counts["phase2"] == 0
    # Once the graph exists, the real node count flows through, not 0.
    assert counts["phase4"] == 12
    assert counts["phase8"] == 20
    # run_health takes the max across phases, so the final summary is non-zero.
    assert max(counts.values()) == 20

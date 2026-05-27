"""Tests for Phase 2 PR D: adversarial self-check + strategic
feedback channel.

PR D ships two related pieces:

  - :class:`AdversarialSelfCheck` — periodic "red team the
    graph" pass. Heuristic-driven (no LLM), runs in O(n+e),
    safe to invoke at every phase boundary. Produces
    :class:`WeakLink` findings across four kinds:
    single-source high-confidence, citation cycles,
    disconnected high-confidence islands, source monocultures.
  - :func:`compute_verification_health` — point-in-time
    snapshot of the campaign's confidence health. Feeds the
    strategic layer: the planner reads
    ``state["verification_health"]`` when authoring a
    Strategy + the prompt biases toward verification tools
    when coverage is low.

Coverage
- Each weak-link kind fires under the right conditions and
  stays silent otherwise.
- Severity grading.
- ``state["weak_links"]`` is replaced each run (current
  health, not compounding).
- ``compute_verification_health`` returns sensible numbers
  on an empty graph + populated graph.
- Health is written to ``state["verification_health"]``.
- The planner prompt includes the health block when state
  carries one + does NOT include it otherwise.
"""
from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from nexusrecon.core.entity_graph import EntityGraph
from nexusrecon.models.entities import (
    CloudAssetEntity,
    DomainEntity,
    HypothesisEntity,
    LeadEntity,
    RelationshipType,
    SubdomainEntity,
)
from nexusrecon.verification import (
    AdversarialSelfCheck,
    VerificationHealth,
    WeakLink,
    compute_verification_health,
)


@pytest.fixture
def graph() -> EntityGraph:
    return EntityGraph(campaign_id="cmp-test", engagement_id="eng-test")


# ──────────────────────────────────────────────────────────────────────
# Adversarial heuristics
# ──────────────────────────────────────────────────────────────────────


class TestSingleSourceHighConfidence:
    def test_fires_when_high_conf_single_class(self, graph: EntityGraph):
        # Three sources, all passive_dns → 1 independence class.
        graph.add_subdomain(
            "api.acme.com", "acme.com", "subfinder",
            confidence=0.95,
        )
        graph.add_subdomain(
            "api.acme.com", "acme.com", "amass_passive",
        )
        graph.add_subdomain(
            "api.acme.com", "acme.com", "dnsdumpster",
        )
        # Override confidence to remain high (merge takes max
        # so multiple high-conf adds keep it high).

        check = AdversarialSelfCheck()
        weak_links = check._find_single_source_high_conf(graph)
        assert len(weak_links) == 1
        assert weak_links[0].kind == "single_source_high_confidence"
        assert weak_links[0].severity == "high"  # confidence >= 0.95
        assert (
            weak_links[0].metadata["independence_classes"]
            == ["passive_dns"]
        )

    def test_no_fire_when_multi_class(self, graph: EntityGraph):
        graph.add_subdomain(
            "api.acme.com", "acme.com", "subfinder",
            confidence=0.95,
        )
        graph.add_subdomain(
            "api.acme.com", "acme.com", "crtsh",
        )
        check = AdversarialSelfCheck()
        weak_links = check._find_single_source_high_conf(graph)
        assert weak_links == []

    def test_no_fire_for_low_confidence(self, graph: EntityGraph):
        graph.add_subdomain(
            "api.acme.com", "acme.com", "subfinder",
            confidence=0.4,
        )
        check = AdversarialSelfCheck()
        weak_links = check._find_single_source_high_conf(graph)
        assert weak_links == []


class TestCitationCycle:
    def test_two_node_cycle_detected(self, graph: EntityGraph):
        lead_a = graph.add_entity(LeadEntity(
            value="lead-a", description="d",
            sources=["correlation"], confidence=0.8,
        ))
        lead_b = graph.add_entity(LeadEntity(
            value="lead-b", description="d",
            sources=["correlation"], confidence=0.8,
        ))
        graph.relate(
            lead_a, lead_b,
            rel_type=RelationshipType.CITES,
            confidence=0.9, source_tool="correlation",
        )
        graph.relate(
            lead_b, lead_a,
            rel_type=RelationshipType.CITES,
            confidence=0.9, source_tool="correlation",
        )
        check = AdversarialSelfCheck()
        weak_links = check._find_citation_cycles(graph)
        assert len(weak_links) == 1
        assert weak_links[0].kind == "citation_cycle"
        assert weak_links[0].severity == "high"
        assert set(weak_links[0].entity_ids) == {lead_a, lead_b}

    def test_no_cycle_when_unidirectional(self, graph: EntityGraph):
        lead_a = graph.add_entity(LeadEntity(
            value="lead-a", description="d",
            sources=["correlation"], confidence=0.8,
        ))
        lead_b = graph.add_entity(LeadEntity(
            value="lead-b", description="d",
            sources=["correlation"], confidence=0.8,
        ))
        graph.relate(
            lead_a, lead_b,
            rel_type=RelationshipType.CITES,
            confidence=0.9, source_tool="correlation",
        )
        check = AdversarialSelfCheck()
        assert check._find_citation_cycles(graph) == []


class TestDisconnectedIsland:
    def test_high_conf_orphan_flagged(self, graph: EntityGraph):
        graph.add_subdomain(
            "api.acme.com", "acme.com", "subfinder",
            confidence=0.9,
        )
        # Subdomain entity is added but has no edges (we
        # don't call relate above).
        check = AdversarialSelfCheck()
        weak_links = check._find_disconnected_islands(graph)
        assert len(weak_links) == 1
        assert weak_links[0].kind == "disconnected_island"
        assert weak_links[0].severity == "low"

    def test_scope_seed_not_flagged(self, graph: EntityGraph):
        """Scope-sourced seeds are expected to be isolated at
        the start — don't flag them as orphans."""
        graph.add_domain("acme.com", source="scope", confidence=0.95)
        check = AdversarialSelfCheck()
        weak_links = check._find_disconnected_islands(graph)
        assert weak_links == []

    def test_connected_entity_not_flagged(self, graph: EntityGraph):
        domain_id = graph.add_domain("acme.com", source="scope", confidence=0.95)
        sub_id = graph.add_subdomain(
            "api.acme.com", "acme.com", "subfinder",
            confidence=0.9,
        )
        graph.relate(
            domain_id, sub_id,
            rel_type=RelationshipType.HAS_SUBDOMAIN,
            confidence=0.9, source_tool="subfinder",
        )
        check = AdversarialSelfCheck()
        weak_links = check._find_disconnected_islands(graph)
        assert weak_links == []


class TestSourceMonoculture:
    def test_cluster_at_threshold_flagged(self, graph: EntityGraph):
        # 4 subdomains all sourced solely from subfinder.
        for i in range(4):
            graph.add_subdomain(
                f"s{i}.acme.com", "acme.com", "subfinder",
                confidence=0.8,
            )
        check = AdversarialSelfCheck(monoculture_cluster_size=4)
        weak_links = check._find_source_monocultures(graph)
        assert len(weak_links) == 1
        assert weak_links[0].kind == "source_monoculture"
        assert weak_links[0].metadata["source"] == "subfinder"
        assert weak_links[0].metadata["cluster_size"] == 4

    def test_under_threshold_not_flagged(self, graph: EntityGraph):
        for i in range(3):
            graph.add_subdomain(
                f"s{i}.acme.com", "acme.com", "subfinder",
                confidence=0.8,
            )
        check = AdversarialSelfCheck(monoculture_cluster_size=4)
        assert check._find_source_monocultures(graph) == []

    def test_multi_source_entities_dont_count(self, graph: EntityGraph):
        # Each entity has two sources — not monoculture.
        for i in range(10):
            graph.add_subdomain(
                f"s{i}.acme.com", "acme.com", "subfinder",
                confidence=0.8,
            )
            graph.add_subdomain(
                f"s{i}.acme.com", "acme.com", "crtsh",
            )
        check = AdversarialSelfCheck(monoculture_cluster_size=4)
        assert check._find_source_monocultures(graph) == []

    def test_scope_cluster_skipped(self, graph: EntityGraph):
        for i in range(10):
            graph.add_domain(f"target-{i}.com", source="scope")
        check = AdversarialSelfCheck(monoculture_cluster_size=4)
        assert check._find_source_monocultures(graph) == []


# ──────────────────────────────────────────────────────────────────────
# Run + state writes
# ──────────────────────────────────────────────────────────────────────


class TestRun:
    def test_run_aggregates_all_kinds(self, graph: EntityGraph):
        # Build a graph that triggers each kind.
        # (1) single_source_high_conf
        graph.add_subdomain(
            "api.acme.com", "acme.com", "subfinder",
            confidence=0.95,
        )
        # (2) citation cycle
        a = graph.add_entity(LeadEntity(
            value="lead-a", description="d",
            sources=["correlation"], confidence=0.7,
        ))
        b = graph.add_entity(LeadEntity(
            value="lead-b", description="d",
            sources=["correlation"], confidence=0.7,
        ))
        graph.relate(a, b, rel_type=RelationshipType.CITES,
                    confidence=0.9, source_tool="correlation")
        graph.relate(b, a, rel_type=RelationshipType.CITES,
                    confidence=0.9, source_tool="correlation")
        # (3) source monoculture (4 + cluster)
        for i in range(4):
            graph.add_subdomain(
                f"mono-{i}.acme.com", "acme.com", "subfinder",
                confidence=0.6,
            )

        state: dict[str, Any] = {}
        report = AdversarialSelfCheck(
            monoculture_cluster_size=4,
        ).run(graph, state)

        kinds = {w.kind for w in report.weak_links}
        assert "single_source_high_confidence" in kinds
        assert "citation_cycle" in kinds
        assert "source_monoculture" in kinds

        # state["weak_links"] mirrors the report.
        assert len(state["weak_links"]) == len(report.weak_links)

    def test_run_replaces_previous_weak_links(self, graph: EntityGraph):
        state: dict[str, Any] = {"weak_links": [
            {"kind": "stale_finding"},
        ]}
        # Empty graph → empty report.
        AdversarialSelfCheck().run(graph, state)
        assert state["weak_links"] == []  # stale entry gone

    def test_audit_log_written_when_bound(self, graph: EntityGraph):
        audit = MagicMock()
        graph.add_subdomain(
            "api.acme.com", "acme.com", "subfinder",
            confidence=0.95,
        )
        AdversarialSelfCheck().run(graph, {}, audit_log=audit)
        audit.log_agent_action.assert_called_once()
        kw = audit.log_agent_action.call_args.kwargs
        assert kw["agent"] == "verifier:adversarial_self_check"
        assert kw["action"] == "adversarial_report"


# ──────────────────────────────────────────────────────────────────────
# Verification health
# ──────────────────────────────────────────────────────────────────────


class TestVerificationHealth:
    def test_empty_graph(self, graph: EntityGraph):
        state: dict[str, Any] = {}
        h = compute_verification_health(graph, state)
        assert h.entity_count == 0
        assert h.corroboration_coverage == 0.0
        assert h.avg_confidence == 0.0
        assert state["verification_health"]["entity_count"] == 0

    def test_populated_graph_metrics(self, graph: EntityGraph):
        # Two entities: one corroborated (passive_dns + cert)
        # at 0.85, one single-source at 0.3.
        graph.add_subdomain(
            "api.acme.com", "acme.com", "subfinder",
            confidence=0.85,
        )
        graph.add_subdomain(
            "api.acme.com", "acme.com", "crtsh",
        )
        graph.add_subdomain(
            "weak.acme.com", "acme.com", "subfinder",
            confidence=0.3,
        )

        h = compute_verification_health(graph)
        assert h.entity_count == 2
        assert h.corroborated_entity_count == 1
        assert h.corroboration_coverage == pytest.approx(0.5)
        assert h.low_confidence_entity_count == 1  # the 0.3 one

    def test_contradictions_counted(self, graph: EntityGraph):
        graph.add_subdomain(
            "api.acme.com", "acme.com", "subfinder",
            confidence=0.85,
        )
        state = {
            "contradictions": [
                {"status": "pending"}, {"status": "pending"},
                {"status": "resolved"},
            ],
        }
        h = compute_verification_health(graph, state)
        assert h.open_contradiction_count == 2
        assert h.contradiction_density == pytest.approx(200.0)  # 2/1 * 100

    def test_weak_links_counted(self, graph: EntityGraph):
        graph.add_subdomain(
            "api.acme.com", "acme.com", "subfinder",
            confidence=0.85,
        )
        state = {
            "weak_links": [
                {"kind": "x", "severity": "high"},
                {"kind": "y", "severity": "high"},
                {"kind": "z", "severity": "low"},
            ],
        }
        h = compute_verification_health(graph, state)
        assert h.weak_link_counts == {"low": 1, "medium": 0, "high": 2}


# ──────────────────────────────────────────────────────────────────────
# Strategic feedback (planner integration)
# ──────────────────────────────────────────────────────────────────────


class TestPlannerHealthIntegration:
    """``_build_planner_prompt`` should include the verification
    health block when one is available + omit it otherwise."""

    def test_prompt_carries_health_when_present(self):
        from nexusrecon.strategy.planner import _build_planner_prompt

        health = {
            "entity_count": 100,
            "corroboration_coverage": 0.3,
            "avg_confidence": 0.55,
            "open_contradiction_count": 5,
            "weak_link_counts": {"low": 2, "medium": 3, "high": 1},
        }
        prompt = _build_planner_prompt(
            scope_summary="acme.com",
            seeds=["acme.com"],
            mode="medium",
            dispatch_policy_name="lite",
            max_llm_cost_usd=10.0,
            verification_health=health,
        )
        assert "Verification Health" in prompt
        assert "30.0%" in prompt or "30.00%" in prompt
        assert "Open contradictions: 5" in prompt
        assert "biased" in prompt.lower() or "bias" in prompt.lower()

    def test_prompt_omits_health_when_absent(self):
        from nexusrecon.strategy.planner import _build_planner_prompt

        prompt = _build_planner_prompt(
            scope_summary="acme.com",
            seeds=["acme.com"],
            mode="medium",
            dispatch_policy_name="lite",
            max_llm_cost_usd=10.0,
        )
        assert "Verification Health" not in prompt

    @pytest.mark.asyncio
    async def test_plan_campaign_reads_health_from_state(
        self,
    ):
        """``plan_campaign`` should pull
        ``state["verification_health"]`` into the prompt
        when the operator passes state."""
        from nexusrecon.strategy.planner import plan_campaign
        from unittest.mock import MagicMock

        class _Spy:
            name = "spy"
            captured_prompt = ""

            async def run_agent(
                self, agent_name, task_data, task_prompt, state=None,
            ):
                self.captured_prompt = task_prompt
                return {"output": '{"name": "x"}'}

        spy = _Spy()
        state = {
            "verification_health": {
                "entity_count": 50,
                "corroboration_coverage": 0.2,
                "avg_confidence": 0.45,
                "open_contradiction_count": 3,
                "weak_link_counts": {"low": 0, "medium": 1, "high": 2},
            },
        }
        await plan_campaign(
            scope_summary="acme.com", seeds=["acme.com"],
            mode="medium", executor=spy, state=state,
        )
        assert "Verification Health" in spy.captured_prompt
        assert "20.0%" in spy.captured_prompt

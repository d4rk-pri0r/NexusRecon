"""Tests for Phase 2 PR C: confidence propagation.

PR C ships :class:`ConfidencePropagator` — a verifier that
listens for ``confidence_changed`` events (now emitted by the
new :meth:`EntityGraph.set_confidence`) and cascades
downgrades to predecessors along propagating relationship
types (``CITES``, ``BELONGS_TO``, ``PART_OF``, ``HOSTED_ON``,
``REGISTERED_BY``, ``BLOCKS``).

Coverage
- ``set_confidence`` emits ``confidence_changed`` with the
  correct payload.
- Propagator skips upgrades (one-way ratchet).
- Propagator skips events with ``source="propagation"``
  (cycle protection).
- BFS depth is capped at ``max_depth``.
- Decay attenuates impact per hop.
- Floor caps the downward cascade.
- Non-propagating rel types (``RESOLVES_TO``) don't propagate.
- Visited set prevents re-visiting nodes in cyclic graphs.
- End-to-end: contradiction → propagation lifts the cascade
  into downstream Lead/Hypothesis entities that CITE the
  contradicted node.
"""
from __future__ import annotations

from typing import Any

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
    ConfidencePropagator,
    ContradictionDetector,
    PropagationVerdict,
    VerificationOrchestrator,
)


@pytest.fixture
def graph() -> EntityGraph:
    return EntityGraph(campaign_id="cmp-test", engagement_id="eng-test")


# ──────────────────────────────────────────────────────────────────────
# set_confidence emission
# ──────────────────────────────────────────────────────────────────────


class TestSetConfidenceEvent:
    def test_emits_confidence_changed(self, graph: EntityGraph):
        eid = graph.add_domain("acme.com", source="scope", confidence=0.9)
        events: list[dict[str, Any]] = []
        graph.register_mutation_listener(events.append)

        ok = graph.set_confidence(
            eid, 0.5, reason="test", source="manual",
        )
        assert ok is True
        cc = [e for e in events if e["kind"] == "confidence_changed"]
        assert len(cc) == 1
        e = cc[0]
        assert e["entity_id"] == eid
        assert e["old_confidence"] == pytest.approx(0.9)
        assert e["new_confidence"] == pytest.approx(0.5)
        assert e["delta"] == pytest.approx(-0.4)
        assert e["reason"] == "test"
        assert e["source"] == "manual"

    def test_set_to_same_value_is_noop(self, graph: EntityGraph):
        eid = graph.add_domain("acme.com", source="scope", confidence=0.9)
        events: list[dict[str, Any]] = []
        graph.register_mutation_listener(events.append)
        ok = graph.set_confidence(eid, 0.9)
        assert ok is False
        assert not any(e["kind"] == "confidence_changed" for e in events)

    def test_unknown_entity_returns_false(self, graph: EntityGraph):
        assert graph.set_confidence("ghost", 0.5) is False


# ──────────────────────────────────────────────────────────────────────
# Propagator: skip rules
# ──────────────────────────────────────────────────────────────────────


class TestPropagatorSkipRules:
    def test_upgrades_not_propagated(self, graph: EntityGraph):
        prop = ConfidencePropagator()
        verdict = prop.verify({
            "kind": "confidence_changed",
            "entity_id": "x",
            "old_confidence": 0.5,
            "new_confidence": 0.8,
            "delta": 0.3,
            "source": "corroboration",
        }, graph)
        assert verdict is None

    def test_own_writes_not_propagated(self, graph: EntityGraph):
        prop = ConfidencePropagator()
        verdict = prop.verify({
            "kind": "confidence_changed",
            "entity_id": "x",
            "old_confidence": 0.8,
            "new_confidence": 0.4,
            "delta": -0.4,
            "source": "propagation",  # already propagating
        }, graph)
        assert verdict is None

    def test_non_confidence_events_ignored(self, graph: EntityGraph):
        prop = ConfidencePropagator()
        assert prop.verify({"kind": "entity_added"}, graph) is None
        assert prop.verify({"kind": "relationship_added"}, graph) is None

    def test_zero_old_confidence_skipped(self, graph: EntityGraph):
        """Can't compute a percentage downgrade from a zero
        baseline — short-circuit cleanly."""
        prop = ConfidencePropagator()
        verdict = prop.verify({
            "kind": "confidence_changed",
            "entity_id": "x",
            "old_confidence": 0.0,
            "new_confidence": 0.0,
            "delta": 0.0,
            "source": "contradiction",
        }, graph)
        assert verdict is None


# ──────────────────────────────────────────────────────────────────────
# Propagator: BFS
# ──────────────────────────────────────────────────────────────────────


class TestPropagatorBFS:
    def test_single_hop_propagation(self, graph: EntityGraph):
        # Cloud asset (downgraded) cited by a lead.
        asset_id = graph.add_cloud_asset(
            "acme-bucket", provider="aws",
            service="s3", source="cloud_enum",
            confidence=0.9,
        )
        lead_id = graph.add_entity(LeadEntity(
            value="exposed-bucket-lead",
            description="Public S3 bucket detected",
            sources=["correlation"],
            confidence=0.85,
        ))
        graph.relate(
            lead_id, asset_id,
            rel_type=RelationshipType.CITES,
            confidence=0.95, source_tool="correlation",
        )

        prop = ConfidencePropagator()
        verdict = prop.verify({
            "kind": "confidence_changed",
            "entity_id": asset_id,
            "old_confidence": 0.9,
            "new_confidence": 0.45,   # halved
            "delta": -0.45,
            "source": "contradiction",
        }, graph)

        assert verdict is not None
        assert len(verdict.steps) == 1
        step = verdict.steps[0]
        assert step.entity_id == lead_id
        assert step.depth == 1
        assert step.rel_type == "cites"
        # Halved upstream (50%) * decay 0.5^1 = 25% impact
        # 0.85 * (1 - 0.25) = 0.6375
        assert step.confidence_after == pytest.approx(0.6375, abs=1e-3)
        # Written back to the graph.
        assert graph.graph.nodes[lead_id]["confidence"] == pytest.approx(
            0.6375, abs=1e-3,
        )

    def test_decay_attenuates_at_depth(self, graph: EntityGraph):
        # Chain: hypothesis -- cites --> lead -- cites --> asset
        asset_id = graph.add_cloud_asset(
            "acme-bucket", provider="aws", service="s3",
            source="cloud_enum", confidence=0.9,
        )
        lead_id = graph.add_entity(LeadEntity(
            value="lead", description="d",
            sources=["correlation"], confidence=0.8,
        ))
        hyp_id = graph.add_entity(HypothesisEntity(
            value="hyp", statement="h",
            sources=["correlation"], confidence=0.8,
        ))
        graph.relate(
            lead_id, asset_id,
            rel_type=RelationshipType.CITES,
            confidence=0.95, source_tool="correlation",
        )
        graph.relate(
            hyp_id, lead_id,
            rel_type=RelationshipType.CITES,
            confidence=0.9, source_tool="correlation",
        )

        prop = ConfidencePropagator()
        verdict = prop.verify({
            "kind": "confidence_changed",
            "entity_id": asset_id,
            "old_confidence": 0.9,
            "new_confidence": 0.45,
            "delta": -0.45,
            "source": "contradiction",
        }, graph)

        assert verdict is not None
        assert len(verdict.steps) == 2
        # Depth-1 step beats the depth-2 step's downgrade
        # magnitude.
        depths = sorted({s.depth for s in verdict.steps})
        assert depths == [1, 2]
        d1 = [s for s in verdict.steps if s.depth == 1][0]
        d2 = [s for s in verdict.steps if s.depth == 2][0]
        delta1 = abs(d1.confidence_after - d1.confidence_before)
        delta2 = abs(d2.confidence_after - d2.confidence_before)
        assert delta1 > delta2

    def test_max_depth_cap(self, graph: EntityGraph):
        # Linear chain of 5 entities; propagate from the leaf.
        ids = []
        for i in range(5):
            e = LeadEntity(
                value=f"lead-{i}", description="d",
                sources=["correlation"], confidence=0.8,
            )
            ids.append(graph.add_entity(e))
        # Chain: 0 -> 1 -> 2 -> 3 -> 4 (each CITES the next)
        for i in range(4):
            graph.relate(
                ids[i], ids[i + 1],
                rel_type=RelationshipType.CITES,
                confidence=0.95, source_tool="correlation",
            )

        prop = ConfidencePropagator(max_depth=2)
        verdict = prop.verify({
            "kind": "confidence_changed",
            "entity_id": ids[4],
            "old_confidence": 0.8,
            "new_confidence": 0.4,
            "delta": -0.4,
            "source": "contradiction",
        }, graph)
        assert verdict is not None
        # Reaches ids[3] (depth 1) and ids[2] (depth 2). At
        # max_depth=2 we stop expanding past depth 2.
        depths = {s.depth for s in verdict.steps}
        assert max(depths) <= 2

    def test_floor_respected(self, graph: EntityGraph):
        lead_id = graph.add_entity(LeadEntity(
            value="lead", description="d",
            sources=["correlation"], confidence=0.06,
        ))
        asset_id = graph.add_cloud_asset(
            "acme-bucket", provider="aws", service="s3",
            source="cloud_enum", confidence=0.9,
        )
        graph.relate(
            lead_id, asset_id,
            rel_type=RelationshipType.CITES,
            confidence=0.95, source_tool="correlation",
        )

        prop = ConfidencePropagator(floor=0.05)
        prop.verify({
            "kind": "confidence_changed",
            "entity_id": asset_id,
            "old_confidence": 0.9,
            "new_confidence": 0.1,  # ~89% downgrade
            "delta": -0.8,
            "source": "contradiction",
        }, graph)
        # 0.06 * (1 - 0.89*0.5) = 0.06 * 0.555 ≈ 0.0333 — but
        # floor caps at 0.05.
        assert graph.graph.nodes[lead_id]["confidence"] >= 0.05

    def test_non_propagating_rel_ignored(self, graph: EntityGraph):
        sub_id = graph.add_subdomain(
            "api.acme.com", "acme.com", "subfinder",
            confidence=0.8,
        )
        ip_id = graph.add_ip("1.1.1.1", source="naabu", confidence=0.9)
        # ``resolves_to`` is multi-valued — NOT in PROPAGATING_REL_TYPES.
        graph.relate(
            sub_id, ip_id, rel_type=RelationshipType.RESOLVES_TO,
            confidence=0.95, source_tool="naabu",
        )

        prop = ConfidencePropagator()
        verdict = prop.verify({
            "kind": "confidence_changed",
            "entity_id": ip_id,
            "old_confidence": 0.9,
            "new_confidence": 0.4,
            "delta": -0.5,
            "source": "contradiction",
        }, graph)
        assert verdict is not None
        assert verdict.steps == []  # no propagation

    def test_visited_set_handles_cycles(self, graph: EntityGraph):
        # Build a 3-cycle of leads. Without visited set this
        # would either loop forever or double-downgrade.
        ids = [
            graph.add_entity(LeadEntity(
                value=f"lead-{i}", description="d",
                sources=["correlation"], confidence=0.8,
            ))
            for i in range(3)
        ]
        for i in range(3):
            graph.relate(
                ids[i], ids[(i + 1) % 3],
                rel_type=RelationshipType.CITES,
                confidence=0.9, source_tool="correlation",
            )

        prop = ConfidencePropagator(max_depth=10)
        verdict = prop.verify({
            "kind": "confidence_changed",
            "entity_id": ids[0],
            "old_confidence": 0.8, "new_confidence": 0.4,
            "delta": -0.4, "source": "contradiction",
        }, graph)
        assert verdict is not None
        # Each non-origin node touched at most once.
        touched = [s.entity_id for s in verdict.steps]
        assert len(touched) == len(set(touched))


# ──────────────────────────────────────────────────────────────────────
# Verdict serialisation
# ──────────────────────────────────────────────────────────────────────


class TestVerdictSerialisation:
    def test_to_dict_shape(self, graph: EntityGraph):
        asset_id = graph.add_cloud_asset(
            "acme-bucket", provider="aws", service="s3",
            source="cloud_enum", confidence=0.9,
        )
        lead_id = graph.add_entity(LeadEntity(
            value="lead", description="d",
            sources=["correlation"], confidence=0.85,
        ))
        graph.relate(
            lead_id, asset_id,
            rel_type=RelationshipType.CITES,
            confidence=0.95, source_tool="correlation",
        )
        prop = ConfidencePropagator()
        verdict = prop.verify({
            "kind": "confidence_changed",
            "entity_id": asset_id,
            "old_confidence": 0.9, "new_confidence": 0.45,
            "delta": -0.45, "source": "contradiction",
        }, graph)
        d = verdict.to_dict()
        for key in ("origin_entity_id", "origin_delta_pct",
                    "steps", "rationale", "skipped"):
            assert key in d
        assert d["steps"]
        assert "depth" in d["steps"][0]


# ──────────────────────────────────────────────────────────────────────
# End-to-end via orchestrator
# ──────────────────────────────────────────────────────────────────────


class TestEndToEnd:
    def test_contradiction_propagates_to_leads(self, graph: EntityGraph):
        """Real flow: a sticky-field contradiction downgrades a
        cloud asset → propagator cascades to a Lead that
        CITES it."""
        state: dict[str, Any] = {}
        det = ContradictionDetector(state=state)
        prop = ConfidencePropagator()
        orch = VerificationOrchestrator(state=state)
        # Order matters: contradiction writes confidence first,
        # propagator listens for the resulting event.
        orch.register(det)
        orch.register(prop)
        orch.attach(graph)

        # Seed: cloud asset (high confidence) + lead that
        # cites it.
        asset_id = graph.add_cloud_asset(
            "acme-bucket", provider="aws", service="s3",
            source="cloud_enum", confidence=0.9,
        )
        lead_id = graph.add_entity(LeadEntity(
            value="exposed-bucket-lead",
            description="Public S3 bucket detected",
            sources=["correlation"], confidence=0.85,
        ))
        graph.relate(
            lead_id, asset_id,
            rel_type=RelationshipType.CITES,
            confidence=0.95, source_tool="correlation",
        )

        lead_before = graph.graph.nodes[lead_id]["confidence"]

        # Trigger sticky-field contradiction: someone reports
        # the bucket as Azure instead of AWS.
        graph.add_cloud_asset(
            "acme-bucket", provider="azure",
            service="s3", source="azure_enum",
            confidence=0.85,
        )

        # Asset is downgraded by the contradiction detector,
        # and the lead is downgraded by the propagator.
        asset_after = graph.graph.nodes[asset_id]["confidence"]
        lead_after = graph.graph.nodes[lead_id]["confidence"]
        assert asset_after < 0.9
        assert lead_after < lead_before

        # Verification log carries verdicts from both verifiers.
        verifiers_fired = {
            e["verifier"] for e in state["verification_log"]
        }
        assert "contradiction" in verifiers_fired
        assert "propagation" in verifiers_fired

    def test_no_recursion_when_propagator_self_writes(
        self, graph: EntityGraph,
    ):
        """The propagator's own ``set_confidence`` calls emit
        ``confidence_changed`` events too. Without the
        ``source="propagation"`` short-circuit those would
        re-enter the propagator and cascade forever."""
        state: dict[str, Any] = {}
        prop = ConfidencePropagator()
        orch = VerificationOrchestrator(state=state)
        orch.register(prop)
        orch.attach(graph)

        asset_id = graph.add_cloud_asset(
            "acme-bucket", provider="aws", service="s3",
            source="cloud_enum", confidence=0.9,
        )
        lead_id = graph.add_entity(LeadEntity(
            value="lead", description="d",
            sources=["correlation"], confidence=0.8,
        ))
        graph.relate(
            lead_id, asset_id,
            rel_type=RelationshipType.CITES,
            confidence=0.95, source_tool="correlation",
        )

        # Manually downgrade the asset → propagator runs +
        # writes the lead → confidence_changed fires again →
        # propagator sees source="propagation" and skips.
        graph.set_confidence(
            asset_id, 0.4,
            reason="test downgrade", source="manual",
        )

        # Only ONE propagator verdict (the initial cascade).
        # No further runs from the propagator's own writes.
        verdicts = [
            e for e in state["verification_log"]
            if e["verifier"] == "propagation"
        ]
        assert len(verdicts) == 1

"""Tests for Phase 2 PR A: verification scaffold + corroboration.

PR A introduces:

  - Mutation-event hooks on :class:`EntityGraph`
    (``register_mutation_listener``).
  - The :class:`VerificationOrchestrator` that fans events out
    to registered verifiers + writes verdicts to
    ``state["verification_log"]`` and the audit log.
  - The :class:`CorroborationEngine` — the first concrete
    verifier — which boosts ``entity.confidence`` when
    distinct *source independence classes* agree on the same
    entity.

Coverage
- Mutation listeners fire on add_entity (added) and on
  add_entity (merged) and on add_relationship, with the
  expected event shape.
- A broken listener doesn't take down the graph.
- ``register_mutation_listener`` + ``clear_mutation_listeners``
  are idempotent.
- Corroboration: distinct source independence classes drive
  the boost; same-class sources are ignored; cap and decay
  behave per formula; verdicts include the rationale string.
- Cap (0.99) is respected — already-saturated entities aren't
  re-boosted.
- Orchestrator: registration order is preserved; verdicts land
  in state + audit log; broken verifiers don't break the
  campaign; attach is idempotent.
- End-to-end: registering the orchestrator with a graph + a
  CorroborationEngine produces real confidence boosts as
  entities are added.
"""
from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from nexusrecon.core.audit import AuditLog
from nexusrecon.core.entity_graph import EntityGraph
from nexusrecon.models.entities import (
    DomainEntity,
    EntityRelationship,
    RelationshipType,
    SubdomainEntity,
)
from nexusrecon.verification import (
    CorroborationEngine,
    CorroborationVerdict,
    SOURCE_INDEPENDENCE_CLASSES,
    VerificationOrchestrator,
)
from nexusrecon.verification.corroboration import (
    CORROBORATION_CAP,
    _compute_boost,
    _distinct_classes,
)


# ──────────────────────────────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────────────────────────────


@pytest.fixture
def graph() -> EntityGraph:
    return EntityGraph(campaign_id="cmp-test", engagement_id="eng-test")


# ──────────────────────────────────────────────────────────────────────
# Mutation hook (EntityGraph)
# ──────────────────────────────────────────────────────────────────────


class TestMutationHooks:
    def test_add_entity_fires_entity_added_event(self, graph: EntityGraph):
        events: list[dict[str, Any]] = []
        graph.register_mutation_listener(events.append)

        graph.add_domain("acme.com", source="scope")

        assert len(events) == 1
        evt = events[0]
        assert evt["kind"] == "entity_added"
        assert evt["entity_type"] == "domain"
        assert evt["value"] == "acme.com"
        assert "entity_id" in evt
        assert evt["sources"] == ["scope"]

    def test_duplicate_add_fires_entity_merged_event(self, graph: EntityGraph):
        # First add: entity_added. Second: entity_merged.
        graph.add_domain("acme.com", source="scope")
        events: list[dict[str, Any]] = []
        graph.register_mutation_listener(events.append)
        graph.add_domain("acme.com", source="subfinder")

        assert len(events) == 1
        assert events[0]["kind"] == "entity_merged"
        assert events[0]["new_sources"] == ["subfinder"]

    def test_add_relationship_fires_relationship_added(self, graph: EntityGraph):
        domain_id = graph.add_domain("acme.com", source="scope")
        sub_id = graph.add_subdomain("api.acme.com", "acme.com", "subfinder")
        events: list[dict[str, Any]] = []
        graph.register_mutation_listener(events.append)

        graph.relate(
            domain_id, sub_id,
            rel_type=RelationshipType.HAS_SUBDOMAIN,
            confidence=0.95, source_tool="subfinder",
        )

        assert any(e["kind"] == "relationship_added" for e in events)
        rel_event = [e for e in events if e["kind"] == "relationship_added"][0]
        assert rel_event["rel_type"] == "has_subdomain"
        assert rel_event["confidence"] == 0.95

    def test_broken_listener_doesnt_break_graph(self, graph: EntityGraph):
        def broken(event):
            raise RuntimeError("listener exploded")
        graph.register_mutation_listener(broken)

        # Graph keeps working despite the broken listener.
        eid = graph.add_domain("acme.com", source="scope")
        assert eid is not None
        assert graph.get_entity(eid) is not None

    def test_clear_mutation_listeners(self, graph: EntityGraph):
        events: list[dict[str, Any]] = []
        graph.register_mutation_listener(events.append)
        graph.clear_mutation_listeners()
        graph.add_domain("acme.com", source="scope")
        assert events == []


# ──────────────────────────────────────────────────────────────────────
# Corroboration helpers
# ──────────────────────────────────────────────────────────────────────


class TestDistinctClasses:
    def test_known_sources_map_to_classes(self):
        classes = _distinct_classes(["subfinder", "crtsh", "naabu"])
        assert set(classes) == {"passive_dns", "certificate", "active_probe"}

    def test_same_class_sources_collapse(self):
        classes = _distinct_classes(["subfinder", "amass_passive", "dnsdumpster"])
        # All three are passive_dns.
        assert classes == ["passive_dns"]

    def test_unknown_sources_bucketed(self):
        classes = _distinct_classes(["zerocool_tool", "random_thing"])
        assert classes == ["unknown"]


class TestComputeBoost:
    def test_no_boost_with_one_class(self):
        assert _compute_boost(
            old=0.5, distinct_class_count=1,
            cap=0.99, decay=0.5,
        ) == 0.5

    def test_two_classes_closes_half_headroom(self):
        # old=0.5, cap=0.99, headroom=0.49, coverage=0.5
        # new = 0.5 + 0.49 * 0.5 = 0.745
        assert _compute_boost(
            old=0.5, distinct_class_count=2,
            cap=0.99, decay=0.5,
        ) == pytest.approx(0.745, abs=1e-3)

    def test_diminishing_returns(self):
        b2 = _compute_boost(old=0.5, distinct_class_count=2,
                            cap=0.99, decay=0.5)
        b3 = _compute_boost(old=0.5, distinct_class_count=3,
                            cap=0.99, decay=0.5)
        b4 = _compute_boost(old=0.5, distinct_class_count=4,
                            cap=0.99, decay=0.5)
        assert b3 - b2 < b2 - 0.5
        assert b4 - b3 < b3 - b2

    def test_never_exceeds_cap(self):
        # 100 classes — should saturate at cap.
        boost = _compute_boost(
            old=0.5, distinct_class_count=100,
            cap=0.99, decay=0.5,
        )
        assert boost < 0.99 + 1e-6
        assert boost > 0.985


# ──────────────────────────────────────────────────────────────────────
# Corroboration engine
# ──────────────────────────────────────────────────────────────────────


class TestCorroborationEngine:
    def test_ignores_non_entity_events(self, graph: EntityGraph):
        engine = CorroborationEngine()
        verdict = engine.verify(
            {"kind": "relationship_added"}, graph,
        )
        assert verdict is None

    def test_no_boost_with_one_class(self, graph: EntityGraph):
        # Add an entity with only passive_dns sources
        e = SubdomainEntity(
            value="api.acme.com",
            parent_domain="acme.com",
            sources=["subfinder", "amass_passive"],
            confidence=0.5,
        )
        eid = graph.add_entity(e)
        engine = CorroborationEngine()
        verdict = engine.verify(
            {"kind": "entity_added", "entity_id": eid}, graph,
        )
        assert verdict is not None
        assert verdict.applied is False
        assert verdict.delta == 0.0
        assert "insufficient" in verdict.rationale.lower()

    def test_boost_applies_with_two_classes(self, graph: EntityGraph):
        e = SubdomainEntity(
            value="api.acme.com",
            parent_domain="acme.com",
            sources=["subfinder", "crtsh"],
            confidence=0.5,
        )
        eid = graph.add_entity(e)
        engine = CorroborationEngine()
        verdict = engine.verify(
            {"kind": "entity_added", "entity_id": eid}, graph,
        )
        assert verdict is not None
        assert verdict.applied is True
        assert verdict.delta > 0
        # Boost written back to the graph.
        assert graph.graph.nodes[eid]["confidence"] == pytest.approx(
            verdict.new_confidence, abs=1e-6,
        )

    def test_saturated_entity_not_re_boosted(self, graph: EntityGraph):
        e = SubdomainEntity(
            value="api.acme.com",
            parent_domain="acme.com",
            sources=["subfinder", "crtsh", "naabu"],
            confidence=0.999,  # already above cap
        )
        eid = graph.add_entity(e)
        engine = CorroborationEngine()
        verdict = engine.verify(
            {"kind": "entity_added", "entity_id": eid}, graph,
        )
        assert verdict is not None
        assert verdict.applied is False
        assert "cap" in verdict.rationale.lower()

    def test_missing_entity_returns_none(self, graph: EntityGraph):
        engine = CorroborationEngine()
        verdict = engine.verify(
            {"kind": "entity_added", "entity_id": "ghost"},
            graph,
        )
        assert verdict is None

    def test_engine_name_surfaces_in_verdict_round_trip(self, graph: EntityGraph):
        e = SubdomainEntity(
            value="api.acme.com",
            parent_domain="acme.com",
            sources=["subfinder", "crtsh"],
            confidence=0.5,
        )
        eid = graph.add_entity(e)
        engine = CorroborationEngine()
        verdict = engine.verify(
            {"kind": "entity_added", "entity_id": eid}, graph,
        )
        d = verdict.to_dict()
        assert "rationale" in d
        assert "independence_classes" in d
        assert set(d["independence_classes"]) == {"passive_dns", "certificate"}


# ──────────────────────────────────────────────────────────────────────
# Orchestrator
# ──────────────────────────────────────────────────────────────────────


class _RecordingVerifier:
    """Test double — records every event it sees."""
    name = "recorder"

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def verify(self, event, graph):
        self.calls.append(event)
        return None  # no verdict produced


class _AlwaysVerdictVerifier:
    name = "always"

    def verify(self, event, graph):
        return CorroborationVerdict(
            entity_id=str(event.get("entity_id") or ""),
            entity_type="x",
            independence_classes=["a", "b"],
            old_confidence=0.5,
            new_confidence=0.7,
            delta=0.2,
            applied=True,
            rationale="test verdict",
        )


class _BrokenVerifier:
    name = "broken"

    def verify(self, event, graph):
        raise RuntimeError("verifier exploded")


class TestOrchestrator:
    def test_register_preserves_order(self):
        orch = VerificationOrchestrator()
        a, b, c = _RecordingVerifier(), _RecordingVerifier(), _RecordingVerifier()
        orch.register(a)
        orch.register(b)
        orch.register(c)
        assert orch.verifiers == [a, b, c]

    def test_clear_drops_verifiers(self):
        orch = VerificationOrchestrator()
        orch.register(_RecordingVerifier())
        orch.clear()
        assert orch.verifiers == []

    def test_attach_idempotent(self, graph: EntityGraph):
        orch = VerificationOrchestrator()
        orch.attach(graph)
        orch.attach(graph)
        # First attach registers one listener; second is a no-op.
        assert len(graph._mutation_listeners) == 1

    def test_on_mutation_fans_out(self, graph: EntityGraph):
        orch = VerificationOrchestrator()
        a = _RecordingVerifier()
        b = _RecordingVerifier()
        orch.register(a)
        orch.register(b)
        orch.attach(graph)

        graph.add_domain("acme.com", source="scope")

        assert len(a.calls) == 1
        assert len(b.calls) == 1
        assert a.calls[0]["kind"] == "entity_added"

    def test_verdicts_land_in_state_log(self, graph: EntityGraph):
        state: dict[str, Any] = {}
        orch = VerificationOrchestrator(state=state)
        orch.register(_AlwaysVerdictVerifier())
        orch.attach(graph)

        graph.add_domain("acme.com", source="scope")

        log_entries = state["verification_log"]
        assert len(log_entries) == 1
        assert log_entries[0]["verifier"] == "always"
        assert log_entries[0]["event_kind"] == "entity_added"
        assert log_entries[0]["rationale"] == "test verdict"

    def test_audit_log_called_when_bound(self, graph: EntityGraph):
        audit = MagicMock()
        orch = VerificationOrchestrator(audit_log=audit)
        orch.register(_AlwaysVerdictVerifier())
        orch.attach(graph)

        graph.add_domain("acme.com", source="scope")

        audit.log_agent_action.assert_called_once()
        kwargs = audit.log_agent_action.call_args.kwargs
        assert kwargs["agent"] == "verifier:always"
        assert kwargs["action"] == "verification_verdict"

    def test_broken_verifier_doesnt_break_dispatch(self, graph: EntityGraph):
        state: dict[str, Any] = {}
        orch = VerificationOrchestrator(state=state)
        orch.register(_BrokenVerifier())
        # Second verifier still runs after broken one.
        good = _AlwaysVerdictVerifier()
        orch.register(good)
        orch.attach(graph)

        graph.add_domain("acme.com", source="scope")

        # Good verifier ran; state has only its verdict.
        assert len(state["verification_log"]) == 1
        assert state["verification_log"][0]["verifier"] == "always"


# ──────────────────────────────────────────────────────────────────────
# End-to-end
# ──────────────────────────────────────────────────────────────────────


class TestEndToEnd:
    def test_corroboration_lifts_confidence_via_mutations(
        self, graph: EntityGraph,
    ):
        """Real flow: orchestrator attached to graph with the
        corroboration engine; subsequent adds from distinct
        independence classes lift confidence over time."""
        state: dict[str, Any] = {}
        orch = VerificationOrchestrator(state=state)
        orch.register(CorroborationEngine())
        orch.attach(graph)

        # NB confidence=0.5 on every add — BaseEntity defaults
        # to 1.0, and ``add_entity``'s merge takes the max of
        # existing vs incoming. Without an explicit low
        # confidence per call, the merge would saturate before
        # corroboration ever kicked in.
        # First add: passive_dns only → no boost.
        eid = graph.add_subdomain(
            "api.acme.com", "acme.com", "subfinder",
            confidence=0.5,
        )
        c1 = graph.graph.nodes[eid]["confidence"]
        assert c1 == pytest.approx(0.5)

        # Second add (same subdomain): certificate class →
        # 2 distinct classes → boost.
        graph.add_subdomain(
            "api.acme.com", "acme.com", "crtsh",
            confidence=0.5,
        )
        c2 = graph.graph.nodes[eid]["confidence"]
        assert c2 > c1

        # Third add: active_probe class → 3 distinct classes →
        # further boost (smaller — diminishing returns).
        graph.add_subdomain(
            "api.acme.com", "acme.com", "naabu",
            confidence=0.5,
        )
        c3 = graph.graph.nodes[eid]["confidence"]
        assert c3 > c2
        assert c3 - c2 < c2 - c1

        # All verdicts recorded.
        log_entries = state["verification_log"]
        assert len(log_entries) == 3  # one per mutation

    def test_audit_log_chain_intact_after_verification(
        self, graph: EntityGraph,
    ):
        """The audit log must verify cleanly after a series of
        verification writes — confirms the new event type
        ``agent_action`` from the verifier doesn't break the
        hash chain."""
        with tempfile.TemporaryDirectory() as tmp:
            audit = AuditLog(
                Path(tmp) / "audit.jsonl",
                campaign_id="cmp-test",
                scope_hash="sha256:abc",
            )
            state: dict[str, Any] = {}
            orch = VerificationOrchestrator(
                state=state, audit_log=audit,
            )
            orch.register(CorroborationEngine())
            orch.attach(graph)

            # Add an entity with multiple-class sources to
            # trigger an applied verdict + audit write.
            e = SubdomainEntity(
                value="api.acme.com",
                parent_domain="acme.com",
                sources=["subfinder", "crtsh"],
                confidence=0.5,
            )
            graph.add_entity(e)
            graph.add_subdomain(
                "api.acme.com", "acme.com", "naabu",
            )

            assert audit.verify_chain() is True

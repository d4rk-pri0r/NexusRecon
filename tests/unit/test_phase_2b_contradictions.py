"""Tests for Phase 2 PR B: contradiction detector + review queue.

PR B layers two new event kinds on top of the basic mutation
hooks PR A introduced:

  - ``sticky_field_conflict`` — fires from ``add_entity``'s
    merge path when a new entity tries to overwrite a populated
    sticky field (e.g. ``cloud_provider="azure"`` vs existing
    ``"aws"``).
  - ``exclusive_rel_conflict`` — fires from ``add_relationship``
    when a new edge of a singular-ownership rel_type
    (``belongs_to``, ``owns``, ``part_of``, ``registered_by``,
    ``hosted_on``) arrives alongside an existing one of the
    same type.

The :class:`ContradictionDetector` consumes those events,
downgrades the affected entity's confidence (bounded by a
floor so a single contradiction can't drive it to zero), and
queues medium+ severity records to ``state["contradictions"]``
for human review.

Coverage
- Sticky-field conflicts fire from the graph + detector
  records them; ``incoming_value`` is silently dropped (merge
  preserves existing-wins semantics, the detector annotates).
- Exclusive-rel conflicts fire + are detected.
- Non-exclusive rel types (``resolves_to``, ``has_tech``) DON'T
  fire conflicts when they shouldn't.
- Severity grading: existing-confidence ladder for sticky,
  max(existing, incoming) for relationships.
- Downgrades respect the floor.
- Medium+ severity contradictions land in the review queue;
  low-severity ones downgrade silently.
- ``resolve_contradiction`` updates status + appends to the
  contradiction log; idempotent on already-resolved records.
- End-to-end: orchestrator + detector + graph mutations
  produce the expected verification + audit trail.
"""
from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

import pytest

from nexusrecon.core.audit import AuditLog
from nexusrecon.core.entity_graph import EntityGraph
from nexusrecon.models.entities import (
    CloudAssetEntity,
    DomainEntity,
    EntityRelationship,
    RelationshipType,
    SubdomainEntity,
)
from nexusrecon.verification import (
    ContradictionDetector,
    ContradictionVerdict,
    VerificationOrchestrator,
    resolve_contradiction,
)
from nexusrecon.verification.contradictions import (
    _grade_rel_severity,
    _grade_sticky_severity,
    _severity_meets,
)


# ──────────────────────────────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────────────────────────────


@pytest.fixture
def graph() -> EntityGraph:
    return EntityGraph(campaign_id="cmp-test", engagement_id="eng-test")


# ──────────────────────────────────────────────────────────────────────
# Graph emits new conflict events
# ──────────────────────────────────────────────────────────────────────


class TestGraphConflictEvents:
    def test_sticky_conflict_fires_on_merge_divergence(self, graph: EntityGraph):
        # Seed: cloud_provider = aws.
        eid = graph.add_cloud_asset(
            "acme-bucket", provider="aws",
            service="s3", source="cloud_enum",
        )
        events: list[dict[str, Any]] = []
        graph.register_mutation_listener(events.append)

        # Merge attempt with provider=azure → conflict.
        graph.add_cloud_asset(
            "acme-bucket", provider="azure",
            service="s3", source="azure_enum",
        )

        kinds = [e["kind"] for e in events]
        assert "entity_merged" in kinds
        assert "sticky_field_conflict" in kinds
        conflict = [e for e in events if e["kind"] == "sticky_field_conflict"][0]
        assert conflict["field"] == "provider"
        assert conflict["existing_value"] == "aws"
        assert conflict["incoming_value"] == "azure"
        # Existing sources captured for the queue.
        assert "cloud_enum" in conflict["existing_sources"]
        assert "azure_enum" in conflict["incoming_sources"]

    def test_no_sticky_conflict_when_field_was_empty(self, graph: EntityGraph):
        """If the existing entity has no value for a sticky
        field, the merge fills it in — not a conflict."""
        eid = graph.add_subdomain("api.acme.com", "acme.com", "subfinder")
        events: list[dict[str, Any]] = []
        graph.register_mutation_listener(events.append)

        graph.add_subdomain("api.acme.com", "acme.com", "crtsh")

        assert not any(e["kind"] == "sticky_field_conflict" for e in events)

    def test_exclusive_rel_conflict_fires(self, graph: EntityGraph):
        # Domain A: owned_by = OrgX.
        domain_id = graph.add_domain("acme.com", source="scope")
        org_x = graph.add_entity(
            DomainEntity(value="orgX-placeholder", sources=["manual"]),
        )
        org_y = graph.add_entity(
            DomainEntity(value="orgY-placeholder", sources=["manual"]),
        )
        # First "owns" edge.
        graph.relate(
            domain_id, org_x,
            rel_type=RelationshipType.OWNS,
            confidence=0.9, source_tool="whois",
        )

        events: list[dict[str, Any]] = []
        graph.register_mutation_listener(events.append)

        # Second "owns" edge to a different target → conflict.
        graph.relate(
            domain_id, org_y,
            rel_type=RelationshipType.OWNS,
            confidence=0.6, source_tool="passive_dns",
        )

        kinds = [e["kind"] for e in events]
        assert "exclusive_rel_conflict" in kinds
        conflict = [e for e in events if e["kind"] == "exclusive_rel_conflict"][0]
        assert conflict["rel_type"] == "owns"
        assert conflict["existing_target"] == org_x
        assert conflict["incoming_target"] == org_y
        assert conflict["existing_confidence"] == pytest.approx(0.9)
        assert conflict["incoming_confidence"] == pytest.approx(0.6)

    def test_resolves_to_is_not_exclusive(self, graph: EntityGraph):
        """RESOLVES_TO is multi-valued (load balancers, multi-
        region) — must NOT fire conflicts."""
        sub_id = graph.add_subdomain("api.acme.com", "acme.com", "subfinder")
        ip1 = graph.add_ip("1.1.1.1", source="naabu")
        ip2 = graph.add_ip("2.2.2.2", source="naabu")
        graph.relate(
            sub_id, ip1, rel_type=RelationshipType.RESOLVES_TO,
            confidence=0.95, source_tool="naabu",
        )

        events: list[dict[str, Any]] = []
        graph.register_mutation_listener(events.append)
        graph.relate(
            sub_id, ip2, rel_type=RelationshipType.RESOLVES_TO,
            confidence=0.95, source_tool="naabu",
        )

        assert not any(
            e["kind"] == "exclusive_rel_conflict" for e in events
        )


# ──────────────────────────────────────────────────────────────────────
# Severity grading
# ──────────────────────────────────────────────────────────────────────


class TestSeverityGrading:
    def test_sticky_grading_ladder(self):
        assert _grade_sticky_severity(
            existing_confidence=0.5, severity_threshold=0.7,
        ) == "low"
        assert _grade_sticky_severity(
            existing_confidence=0.75, severity_threshold=0.7,
        ) == "medium"
        assert _grade_sticky_severity(
            existing_confidence=0.95, severity_threshold=0.7,
        ) == "high"

    def test_rel_grading_uses_peak(self):
        # Both low → low.
        assert _grade_rel_severity(
            existing_confidence=0.4, incoming_confidence=0.3,
            severity_threshold=0.7,
        ) == "low"
        # One high → high (no need for both to be high).
        assert _grade_rel_severity(
            existing_confidence=0.3, incoming_confidence=0.95,
            severity_threshold=0.7,
        ) == "high"

    def test_severity_meets_threshold(self):
        assert _severity_meets("high", "medium") is True
        assert _severity_meets("medium", "medium") is True
        assert _severity_meets("low", "medium") is False


# ──────────────────────────────────────────────────────────────────────
# Detector
# ──────────────────────────────────────────────────────────────────────


class TestContradictionDetector:
    def test_ignores_unrelated_events(self, graph: EntityGraph):
        det = ContradictionDetector()
        assert det.verify({"kind": "entity_added"}, graph) is None
        assert det.verify({"kind": "relationship_added"}, graph) is None

    def test_sticky_conflict_downgrades_confidence(self, graph: EntityGraph):
        eid = graph.add_cloud_asset(
            "acme-bucket", provider="aws",
            service="s3", source="cloud_enum",
            confidence=0.9,
        )
        det = ContradictionDetector(downgrade_factor=0.5)
        verdict = det.verify({
            "kind": "sticky_field_conflict",
            "entity_id": eid,
            "field": "provider",
            "existing_value": "aws",
            "incoming_value": "azure",
            "existing_sources": ["cloud_enum"],
            "incoming_sources": ["azure_enum"],
            "existing_confidence": 0.9,
        }, graph)
        assert verdict is not None
        assert verdict.kind == "sticky_field_conflict"
        assert verdict.severity == "high"  # existing was 0.9
        assert verdict.confidence_after == pytest.approx(0.45, abs=1e-3)
        assert verdict.delta < 0
        # Confidence written back to the graph.
        assert graph.graph.nodes[eid]["confidence"] == pytest.approx(0.45)

    def test_downgrade_respects_floor(self, graph: EntityGraph):
        eid = graph.add_cloud_asset(
            "acme-bucket", provider="aws",
            service="s3", source="cloud_enum",
            confidence=0.05,
        )
        det = ContradictionDetector(downgrade_factor=0.5, floor=0.05)
        det.verify({
            "kind": "sticky_field_conflict",
            "entity_id": eid,
            "field": "provider",
            "existing_value": "aws",
            "incoming_value": "azure",
            "existing_sources": [], "incoming_sources": [],
            "existing_confidence": 0.05,
        }, graph)
        # 0.05 * 0.5 = 0.025 — but floor is 0.05.
        assert graph.graph.nodes[eid]["confidence"] == pytest.approx(0.05)

    def test_medium_severity_queues(self, graph: EntityGraph):
        state: dict[str, Any] = {}
        eid = graph.add_cloud_asset(
            "acme-bucket", provider="aws",
            service="s3", source="cloud_enum",
            confidence=0.8,
        )
        det = ContradictionDetector(state=state, severity_threshold=0.7)
        verdict = det.verify({
            "kind": "sticky_field_conflict",
            "entity_id": eid,
            "field": "provider",
            "existing_value": "aws",
            "incoming_value": "azure",
            "existing_sources": ["cloud_enum"],
            "incoming_sources": ["azure_enum"],
            "existing_confidence": 0.8,
        }, graph)
        assert verdict is not None
        assert verdict.severity == "medium"
        assert verdict.queued is True
        assert len(state["contradictions"]) == 1
        rec = state["contradictions"][0]
        assert rec["status"] == "pending"
        assert rec["existing_claim"] == "aws"
        assert rec["incoming_claim"] == "azure"
        assert rec["severity"] == "medium"

    def test_low_severity_doesnt_queue(self, graph: EntityGraph):
        state: dict[str, Any] = {}
        eid = graph.add_cloud_asset(
            "acme-bucket", provider="aws",
            service="s3", source="cloud_enum",
            confidence=0.4,
        )
        det = ContradictionDetector(state=state, severity_threshold=0.7)
        verdict = det.verify({
            "kind": "sticky_field_conflict",
            "entity_id": eid,
            "field": "provider",
            "existing_value": "aws",
            "incoming_value": "azure",
            "existing_sources": [], "incoming_sources": [],
            "existing_confidence": 0.4,
        }, graph)
        assert verdict.severity == "low"
        assert verdict.queued is False
        assert state.get("contradictions", []) == []

    def test_rel_conflict_detector(self, graph: EntityGraph):
        state: dict[str, Any] = {}
        domain_id = graph.add_domain("acme.com", source="scope", confidence=0.9)
        det = ContradictionDetector(state=state, severity_threshold=0.7)
        verdict = det.verify({
            "kind": "exclusive_rel_conflict",
            "source_id": domain_id,
            "rel_type": "owns",
            "existing_target": "tgt1",
            "existing_confidence": 0.95,
            "existing_source_tool": "whois",
            "incoming_target": "tgt2",
            "incoming_confidence": 0.7,
            "incoming_source_tool": "passive_dns",
        }, graph)
        assert verdict is not None
        assert verdict.kind == "exclusive_rel_conflict"
        assert verdict.severity == "high"  # peak == 0.95
        assert verdict.queued is True
        assert len(state["contradictions"]) == 1

    def test_verdict_serialisation_keeps_shape(self, graph: EntityGraph):
        eid = graph.add_cloud_asset(
            "acme-bucket", provider="aws",
            service="s3", source="cloud_enum", confidence=0.8,
        )
        det = ContradictionDetector()
        verdict = det.verify({
            "kind": "sticky_field_conflict",
            "entity_id": eid,
            "field": "provider",
            "existing_value": "aws",
            "incoming_value": "azure",
            "existing_sources": [], "incoming_sources": [],
            "existing_confidence": 0.8,
        }, graph)
        d = verdict.to_dict()
        for key in (
            "entity_id", "kind", "field_or_rel", "existing_claim",
            "incoming_claim", "severity", "confidence_before",
            "confidence_after", "delta", "queued", "rationale",
            "metadata",
        ):
            assert key in d
        # Claim values stringified for the audit log.
        assert d["existing_claim"] == "aws"
        assert d["incoming_claim"] == "azure"


# ──────────────────────────────────────────────────────────────────────
# Resolution
# ──────────────────────────────────────────────────────────────────────


class TestResolveContradiction:
    def test_resolve_updates_status(self):
        state: dict[str, Any] = {
            "contradictions": [{
                "entity_id": "ent-1", "kind": "sticky_field_conflict",
                "field_or_rel": "provider", "status": "pending",
                "existing_claim": "aws", "incoming_claim": "azure",
                "existing_sources": [], "incoming_sources": [],
                "severity": "high",
            }],
        }
        record = resolve_contradiction(
            state, entity_id="ent-1",
            kind="sticky_field_conflict",
            field_or_rel="provider",
            resolution="existing_wins",
            operator="op-jane",
            notes="confirmed via AWS account number",
        )
        assert record is not None
        assert record["status"] == "resolved"
        assert record["resolution"] == "existing_wins"
        assert record["resolved_by"] == "op-jane"
        assert len(state["contradiction_log"]) == 1

    def test_idempotent_double_resolve(self):
        state: dict[str, Any] = {
            "contradictions": [{
                "entity_id": "ent-1", "kind": "sticky_field_conflict",
                "field_or_rel": "provider", "status": "pending",
                "existing_claim": "aws", "incoming_claim": "azure",
                "existing_sources": [], "incoming_sources": [],
                "severity": "high",
            }],
        }
        resolve_contradiction(
            state, entity_id="ent-1",
            kind="sticky_field_conflict",
            field_or_rel="provider",
            resolution="existing_wins",
            operator="jane",
        )
        # Second call → no matching pending record → None.
        again = resolve_contradiction(
            state, entity_id="ent-1",
            kind="sticky_field_conflict",
            field_or_rel="provider",
            resolution="incoming_wins",
            operator="bob",
        )
        assert again is None
        assert len(state["contradiction_log"]) == 1

    def test_missing_record_returns_none(self):
        state: dict[str, Any] = {"contradictions": []}
        assert resolve_contradiction(
            state, entity_id="ghost", kind="x",
            field_or_rel="y", resolution="existing_wins",
            operator="op",
        ) is None


# ──────────────────────────────────────────────────────────────────────
# End-to-end via orchestrator
# ──────────────────────────────────────────────────────────────────────


class TestEndToEnd:
    def test_orchestrator_dispatches_conflicts_to_detector(
        self, graph: EntityGraph,
    ):
        state: dict[str, Any] = {}
        det = ContradictionDetector(state=state)
        orch = VerificationOrchestrator(state=state)
        orch.register(det)
        orch.attach(graph)

        # Seed an entity with high confidence.
        graph.add_cloud_asset(
            "acme-bucket", provider="aws",
            service="s3", source="cloud_enum", confidence=0.9,
        )
        # Conflict.
        graph.add_cloud_asset(
            "acme-bucket", provider="azure",
            service="s3", source="azure_enum", confidence=0.85,
        )

        # Contradiction queued (high severity).
        assert len(state["contradictions"]) == 1
        # Verification log carries the verdict.
        assert any(
            e["verifier"] == "contradiction"
            for e in state["verification_log"]
        )

    def test_audit_chain_intact_with_contradiction_writes(
        self, graph: EntityGraph,
    ):
        """The new event types ride the same audit-log
        ``log_agent_action`` path as PR A — verify the chain
        still validates."""
        with tempfile.TemporaryDirectory() as tmp:
            audit = AuditLog(
                Path(tmp) / "audit.jsonl",
                campaign_id="cmp-test", scope_hash="sha256:abc",
            )
            state: dict[str, Any] = {}
            orch = VerificationOrchestrator(
                state=state, audit_log=audit,
            )
            orch.register(ContradictionDetector(state=state))
            orch.attach(graph)

            graph.add_cloud_asset(
                "acme-bucket", provider="aws",
                service="s3", source="cloud_enum", confidence=0.9,
            )
            graph.add_cloud_asset(
                "acme-bucket", provider="azure",
                service="s3", source="azure_enum", confidence=0.85,
            )

            assert audit.verify_chain() is True

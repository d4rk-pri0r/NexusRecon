"""Tests for Phase 0.1 PR B: three-graph unification.

Phase D's :class:`IdentityGraph` and Phase E's
:class:`RelationshipGraph` now ingest into the unified
:class:`EntityGraph` as ``PERSON`` nodes + typed edges. The
two source graphs survive as authoring conveniences for the
existing tools; the EntityGraph becomes the substrate agents
+ reports query for cross-cutting questions.

Coverage
- ``merge_identity(identity)`` creates a PersonEntity using
  the identity's content-derived ``identity_id`` as both
  entity_id and value; corp/personal emails become Email
  entities + HAS_ACCOUNT edges; handles become Username
  entities + HAS_ACCOUNT edges (with service preserved);
  real_name/etc. fold to ``metadata["extra_identifiers"]``;
  credential_exposures fold to
  ``metadata["credential_exposures"]``.
- ``merge_identity_graph(identity_graph)`` iterates every
  identity and returns the count.
- ``merge_relationship_graph(rel_graph)`` translates
  interaction_type strings to RelationshipType (KNOWS /
  COLLABORATES_WITH / FOLLOWS / FEDERATED_WITH) with KNOWS as
  the safe-default fallback; carries ``strength`` to the
  edge's confidence; skips edges between missing nodes.
- ``EntityGraph.from_state(state)`` automatically ingests
  ``state["identity_graph"]`` + ``state["relationship_graph"]``
  when present.
- Idempotent under repeat merge — the (PERSON, identity_id)
  dedup keeps a second pass from doubling nodes.
"""
from __future__ import annotations

import pytest

from nexusrecon.core.entity_graph import EntityGraph
from nexusrecon.core.identity_graph import (
    Identifier,
    IdentifierType,
    Identity,
    IdentityGraph,
)
from nexusrecon.core.relationship_graph import (
    RelationshipEdge,
    RelationshipGraph,
)
from nexusrecon.models.entities import EntityType, RelationshipType


# ──────────────────────────────────────────────────────────────────────
# Single identity merge
# ──────────────────────────────────────────────────────────────────────


def _make_identity(
    identity_id: str,
    label: str,
    *,
    corp_email: str | None = None,
    personal_email: str | None = None,
    handles: list[tuple[str, str]] | None = None,
    real_name: str | None = None,
) -> Identity:
    """Builder helper for tests."""
    idr_list: list[Identifier] = []
    if corp_email:
        idr_list.append(Identifier(
            value=corp_email,
            identifier_type=IdentifierType.CORP_EMAIL,
            source="hunter",
            confidence=1.0,
        ))
    if personal_email:
        idr_list.append(Identifier(
            value=personal_email,
            identifier_type=IdentifierType.PERSONAL_EMAIL,
            source="personal_pivot",
            confidence=0.6,
        ))
    for (handle, service) in handles or []:
        idr_list.append(Identifier(
            value=handle,
            identifier_type=IdentifierType.HANDLE,
            service=service,
            source="github_social",
            confidence=0.8,
        ))
    if real_name:
        idr_list.append(Identifier(
            value=real_name,
            identifier_type=IdentifierType.REAL_NAME,
            source="hunter",
            confidence=1.0,
        ))
    return Identity(
        identity_id=identity_id,
        primary_label=label,
        identifiers=idr_list,
    )


class TestMergeIdentity:
    def test_merge_creates_person_entity(self):
        g = EntityGraph(campaign_id="t", engagement_id="e")
        ident = _make_identity(
            "id-alice", "Alice Smith",
            corp_email="alice@acme.com",
        )
        pid = g.merge_identity(ident)
        node = g.get_entity(pid)
        assert node is not None
        assert node["entity_type"] == "person"
        # Person value is the content-derived identity_id so
        # cross-references stay stable across runs.
        assert node["value"] == "id-alice"
        assert node["full_name"] == "Alice Smith"

    def test_merge_uses_identity_id_as_entity_id(self):
        """Stable cross-graph references: the PersonEntity's
        entity_id is the identity_id, not a fresh uuid."""
        g = EntityGraph(campaign_id="t", engagement_id="e")
        ident = _make_identity("id-bob", "Bob Jones")
        pid = g.merge_identity(ident)
        assert pid == "id-bob"

    def test_merge_creates_email_entities(self):
        g = EntityGraph(campaign_id="t", engagement_id="e")
        ident = _make_identity(
            "id-alice", "Alice",
            corp_email="alice@acme.com",
            personal_email="alice.s.84@gmail.com",
        )
        g.merge_identity(ident)
        emails = g.get_entities_by_type(EntityType.EMAIL)
        values = {e["value"] for e in emails}
        assert "alice@acme.com" in values
        assert "alice.s.84@gmail.com" in values

    def test_merge_draws_has_account_edge_to_emails(self):
        g = EntityGraph(campaign_id="t", engagement_id="e")
        ident = _make_identity(
            "id-alice", "Alice", corp_email="alice@acme.com",
        )
        pid = g.merge_identity(ident)
        # Walk the person's outbound edges; one should be
        # HAS_ACCOUNT to the email.
        targets = []
        for _, tgt, data in g.graph.out_edges(pid, data=True):
            if data.get("rel_type") == "has_account":
                node = g.get_entity(tgt)
                if node and node["entity_type"] == "email":
                    targets.append(node["value"])
        assert "alice@acme.com" in targets

    def test_merge_creates_username_entity_for_handle(self):
        g = EntityGraph(campaign_id="t", engagement_id="e")
        ident = _make_identity(
            "id-alice", "Alice",
            handles=[("alice-gh", "GitHub")],
        )
        g.merge_identity(ident)
        usernames = g.get_entities_by_type(EntityType.USERNAME)
        values = {u["value"] for u in usernames}
        assert "alice-gh" in values
        # Service preserved.
        un = next(u for u in usernames if u["value"] == "alice-gh")
        assert "GitHub" in un.get("platforms_found", [])

    def test_real_name_folds_to_extra_identifiers_metadata(self):
        g = EntityGraph(campaign_id="t", engagement_id="e")
        ident = _make_identity(
            "id-alice", "Alice Smith", real_name="Alice Smith",
        )
        pid = g.merge_identity(ident)
        node = g.get_entity(pid)
        extras = node.get("metadata", {}).get("extra_identifiers", [])
        assert any(e.get("type") == "real_name" for e in extras)

    def test_merge_is_idempotent(self):
        """Re-merging the same identity returns the same
        entity_id and doesn't double nodes."""
        g = EntityGraph(campaign_id="t", engagement_id="e")
        ident = _make_identity("id-alice", "Alice")
        pid1 = g.merge_identity(ident)
        pid2 = g.merge_identity(ident)
        assert pid1 == pid2
        persons = g.get_entities_by_type(EntityType.PERSON)
        assert len(persons) == 1


# ──────────────────────────────────────────────────────────────────────
# Full identity-graph merge
# ──────────────────────────────────────────────────────────────────────


class TestMergeIdentityGraph:
    def test_merges_every_identity(self):
        g = EntityGraph(campaign_id="t", engagement_id="e")
        idg = IdentityGraph()
        idg.add_identity(_make_identity("id-1", "Alice"))
        idg.add_identity(_make_identity("id-2", "Bob"))
        count = g.merge_identity_graph(idg)
        assert count == 2
        persons = g.get_entities_by_type(EntityType.PERSON)
        assert len(persons) == 2

    def test_handles_none_input_safely(self):
        g = EntityGraph(campaign_id="t", engagement_id="e")
        assert g.merge_identity_graph(None) == 0


# ──────────────────────────────────────────────────────────────────────
# Relationship-graph merge
# ──────────────────────────────────────────────────────────────────────


class TestMergeRelationshipGraph:
    def _setup(self) -> tuple[EntityGraph, IdentityGraph, RelationshipGraph]:
        g = EntityGraph(campaign_id="t", engagement_id="e")
        idg = IdentityGraph()
        idg.add_identity(_make_identity("id-alice", "Alice"))
        idg.add_identity(_make_identity("id-bob", "Bob"))
        g.merge_identity_graph(idg)

        rg = RelationshipGraph(identity_graph=idg)
        rg.add_edge(
            "id-alice",
            RelationshipEdge(
                target_identity_id="id-bob",
                interaction_type="co_author",
                strength=0.8,
                last_observed=0.0,
                sources=["github_social"],
            ),
        )
        rg.add_edge(
            "id-bob",
            RelationshipEdge(
                target_identity_id="id-alice",
                interaction_type="follows",
                strength=0.5,
                last_observed=0.0,
                sources=["mastodon_social"],
            ),
        )
        return g, idg, rg

    def test_translates_co_author_to_collaborates_with(self):
        g, _, rg = self._setup()
        g.merge_relationship_graph(rg)
        data = g.graph.get_edge_data("id-alice", "id-bob")
        assert data is not None
        assert data["rel_type"] == "collaborates_with"

    def test_translates_follows_to_follows(self):
        g, _, rg = self._setup()
        g.merge_relationship_graph(rg)
        data = g.graph.get_edge_data("id-bob", "id-alice")
        assert data is not None
        assert data["rel_type"] == "follows"

    def test_carries_strength_to_edge_confidence(self):
        g, _, rg = self._setup()
        g.merge_relationship_graph(rg)
        data = g.graph.get_edge_data("id-alice", "id-bob")
        # co_author edge had strength=0.8 → edge confidence 0.8.
        assert data["confidence"] == 0.8

    def test_unknown_interaction_falls_back_to_knows(self):
        g = EntityGraph(campaign_id="t", engagement_id="e")
        idg = IdentityGraph()
        idg.add_identity(_make_identity("id-a", "A"))
        idg.add_identity(_make_identity("id-b", "B"))
        g.merge_identity_graph(idg)
        rg = RelationshipGraph(identity_graph=idg)
        rg.add_edge("id-a", RelationshipEdge(
            target_identity_id="id-b",
            interaction_type="some_future_interaction",
            strength=0.5, last_observed=0.0, sources=["x"],
        ))
        g.merge_relationship_graph(rg)
        data = g.graph.get_edge_data("id-a", "id-b")
        # Fallback is KNOWS so unknown interactions still
        # contribute an edge rather than being dropped.
        assert data["rel_type"] == "knows"

    def test_skips_edges_between_missing_nodes(self):
        """If the relationship-graph references identities that
        weren't merged into the EntityGraph, the edges are
        silently skipped — the audit-tolerance pattern."""
        g = EntityGraph(campaign_id="t", engagement_id="e")
        idg = IdentityGraph()
        idg.add_identity(_make_identity("id-known", "Known"))
        g.merge_identity_graph(idg)
        rg = RelationshipGraph(identity_graph=idg)
        # Edge references an identity we never merged.
        rg.add_edge("id-known", RelationshipEdge(
            target_identity_id="id-missing",
            interaction_type="co_author",
            strength=0.5, last_observed=0.0, sources=["x"],
        ))
        count = g.merge_relationship_graph(rg)
        # Edge skipped: count == 0.
        assert count == 0

    def test_handles_none_input_safely(self):
        g = EntityGraph(campaign_id="t", engagement_id="e")
        assert g.merge_relationship_graph(None) == 0


# ──────────────────────────────────────────────────────────────────────
# from_state ingests both graphs
# ──────────────────────────────────────────────────────────────────────


class TestFromStateUnification:
    def test_from_state_ingests_identity_graph_when_present(self):
        idg = IdentityGraph()
        idg.add_identity(_make_identity(
            "id-alice", "Alice",
            corp_email="alice@acme.com",
        ))
        state = {
            "campaign_id": "t",
            "engagement_id": "e",
            "subdomain_intel": {},
            "email_intel": {"emails": {}},
            "cloud_intel": {},
            "code_intel": {},
            "identity_graph": idg.to_dict(),
        }
        g = EntityGraph.from_state(state)
        # Person node landed.
        persons = g.get_entities_by_type(EntityType.PERSON)
        assert len(persons) == 1
        assert persons[0]["value"] == "id-alice"
        # Email entity landed via the identifier ingest.
        emails = g.get_entities_by_type(EntityType.EMAIL)
        assert any(e["value"] == "alice@acme.com" for e in emails)

    def test_from_state_ingests_relationship_graph_when_present(self):
        idg = IdentityGraph()
        idg.add_identity(_make_identity("id-alice", "Alice"))
        idg.add_identity(_make_identity("id-bob", "Bob"))
        rg = RelationshipGraph(identity_graph=idg)
        rg.add_edge("id-alice", RelationshipEdge(
            target_identity_id="id-bob",
            interaction_type="co_author",
            strength=0.7, last_observed=0.0, sources=["x"],
        ))
        state = {
            "campaign_id": "t",
            "engagement_id": "e",
            "subdomain_intel": {},
            "email_intel": {"emails": {}},
            "cloud_intel": {},
            "code_intel": {},
            "identity_graph": idg.to_dict(),
            "relationship_graph": rg.to_dict(),
        }
        g = EntityGraph.from_state(state)
        # Edge translated to COLLABORATES_WITH.
        data = g.graph.get_edge_data("id-alice", "id-bob")
        assert data is not None
        assert data["rel_type"] == "collaborates_with"

    def test_from_state_tolerates_missing_identity_graph(self):
        """Old-style state with no identity_graph key still
        works — phase4 just gets a graph without people in it."""
        state = {
            "campaign_id": "t",
            "engagement_id": "e",
            "subdomain_intel": {"www.acme.com": {}},
            "email_intel": {"emails": {}},
            "cloud_intel": {},
            "code_intel": {},
        }
        g = EntityGraph.from_state(state)
        # No persons; subdomain still ingested.
        assert g.get_entities_by_type(EntityType.PERSON) == []
        subs = g.get_entities_by_type(EntityType.SUBDOMAIN)
        assert len(subs) == 1

    def test_from_state_tolerates_corrupt_identity_graph(self):
        """A malformed identity_graph dict should NOT crash
        phase4. Tolerance is the audit-log discipline."""
        state = {
            "campaign_id": "t",
            "engagement_id": "e",
            "subdomain_intel": {},
            "email_intel": {"emails": {}},
            "cloud_intel": {},
            "code_intel": {},
            "identity_graph": {
                "identities": "this should be a list, not a string",
            },
        }
        # Must not raise.
        g = EntityGraph.from_state(state)
        # Empty result; not a crash.
        assert g.get_entities_by_type(EntityType.PERSON) == []


# ──────────────────────────────────────────────────────────────────────
# Relationship-type vocabulary
# ──────────────────────────────────────────────────────────────────────


class TestNewRelationshipTypes:
    """Pin the new enum values so a refactor that drops them is
    loud — agents and reports key off these strings."""

    def test_knows_value(self):
        assert RelationshipType.KNOWS == "knows"

    def test_collaborates_with_value(self):
        assert RelationshipType.COLLABORATES_WITH == "collaborates_with"

    def test_follows_value(self):
        assert RelationshipType.FOLLOWS == "follows"

    def test_federated_with_value(self):
        assert RelationshipType.FEDERATED_WITH == "federated_with"

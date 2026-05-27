"""Tests for Phase 0.1 PR A: provenance + path-finding +
phase-aware GraphContext.

Coverage
- ``ProvenanceRecord`` round-trips through Pydantic + the
  ``BaseEntity.add_provenance`` helper mirrors the source
  into the legacy ``sources`` list.
- ``BaseEntity.is_virtual`` defaults False; can be set True
  on inferred nodes.
- ``EntityGraph.find_paths`` honors ``max_length`` +
  ``relationship_types`` + ``min_edge_confidence`` filters.
- ``EntityGraph.get_neighbors_filtered`` honors ``edge_type``
  + ``direction``.
- ``EntityGraph.get_attack_surface_nodes`` filters by type +
  confidence floor.
- ``GraphContext.most_cited_entities`` ranks by inbound
  degree with confidence tie-break.
- ``GraphContext.for_phase`` returns the documented schema +
  scopes to the right entity types per
  ``PHASE_FOCUS_TYPES``.
"""
from __future__ import annotations

import pytest

from nexusrecon.core.entity_graph import EntityGraph
from nexusrecon.core.graph_context import GraphContext
from nexusrecon.models.entities import (
    DomainEntity,
    EmailEntity,
    EntityType,
    ProvenanceRecord,
    RelationshipType,
    SubdomainEntity,
)


# ──────────────────────────────────────────────────────────────────────
# Provenance
# ──────────────────────────────────────────────────────────────────────


class TestProvenanceRecord:
    def test_minimal_record_round_trips(self):
        r = ProvenanceRecord(source="shodan")
        dumped = r.model_dump()
        assert dumped["source"] == "shodan"
        assert dumped["evidence_hash"] is None
        assert dumped["tool_name"] is None
        # ``timestamp`` auto-populated.
        assert dumped["timestamp"] is not None

    def test_full_record_carries_evidence_hash_and_tool(self):
        r = ProvenanceRecord(
            source="shodan",
            evidence_hash="sha256:abc",
            tool_name="ShodanTool",
        )
        assert r.evidence_hash == "sha256:abc"
        assert r.tool_name == "ShodanTool"


class TestBaseEntityProvenance:
    def test_add_provenance_appends_record(self):
        e = DomainEntity(value="acme.com")
        assert e.provenance == []
        e.add_provenance("shodan", evidence_hash="sha256:abc",
                         tool_name="ShodanTool")
        assert len(e.provenance) == 1
        assert e.provenance[0].source == "shodan"
        assert e.provenance[0].evidence_hash == "sha256:abc"

    def test_add_provenance_mirrors_into_legacy_sources(self):
        """The two surfaces must stay in sync so the rest of
        the codebase (which still reads ``sources``) sees the
        update."""
        e = DomainEntity(value="acme.com")
        e.add_provenance("shodan")
        assert "shodan" in e.sources

    def test_add_provenance_does_not_duplicate_sources(self):
        e = DomainEntity(value="acme.com", sources=["shodan"])
        e.add_provenance("shodan", evidence_hash="sha256:b")
        # ``sources`` doesn't double; ``provenance`` adds the record.
        assert e.sources.count("shodan") == 1
        assert len(e.provenance) == 1

    def test_is_virtual_defaults_false(self):
        e = DomainEntity(value="acme.com")
        assert e.is_virtual is False

    def test_is_virtual_can_be_set(self):
        """A possible-persona inferred by the personal-pivot
        tool is virtual; the corp email it was derived from is
        not."""
        e = EmailEntity(
            value="possible@gmail.com",
            local_part="possible", domain="gmail.com",
            is_virtual=True,
        )
        assert e.is_virtual is True


# ──────────────────────────────────────────────────────────────────────
# Path-finding
# ──────────────────────────────────────────────────────────────────────


class TestFindPaths:
    """``find_paths`` is the plan's Phase 0.1 surface for path
    queries. Verify the filter parameters all do something."""

    def _graph_with_chain(self) -> tuple[EntityGraph, list[str]]:
        """Build A → B → C → D where edges are alternating
        ``has_subdomain`` and ``hosts``."""
        g = EntityGraph(campaign_id="t", engagement_id="e")
        a = g.add_domain("acme.com", source="x")
        b = g.add_subdomain("vpn.acme.com", "acme.com", source="x")
        c = g.add_ip("203.0.113.5", source="x")
        d = g.add_cloud_asset("aws/s3:bucket", provider="aws",
                              service="s3", source="x")
        g.relate(a, b, RelationshipType.HAS_SUBDOMAIN, confidence=0.9)
        g.relate(b, c, RelationshipType.HOSTS, confidence=0.7)
        g.relate(c, d, RelationshipType.HAS_SUBDOMAIN, confidence=0.3)
        return g, [a, b, c, d]

    def test_default_finds_shortest_simple_path(self):
        g, ids = self._graph_with_chain()
        a, _, _, d = ids
        paths = g.find_paths(a, d, max_length=5)
        assert len(paths) >= 1
        # Shortest is the 3-hop chain through every node.
        assert paths[0] == ids

    def test_max_length_prunes_long_paths(self):
        g, ids = self._graph_with_chain()
        a, _, _, d = ids
        # max_length=2 → can't reach D from A in 2 hops.
        paths = g.find_paths(a, d, max_length=2)
        assert paths == []

    def test_relationship_filter_excludes_paths(self):
        """When the filter excludes an edge in the only path,
        we should get no paths."""
        g, ids = self._graph_with_chain()
        a, _, _, d = ids
        # Restrict to HOSTS only — the A→B edge is HAS_SUBDOMAIN,
        # so no path can start.
        paths = g.find_paths(
            a, d, max_length=5,
            relationship_types=[RelationshipType.HOSTS],
        )
        assert paths == []

    def test_min_edge_confidence_prunes_low_conf_path(self):
        g, ids = self._graph_with_chain()
        a, _, _, d = ids
        # The C→D edge has confidence 0.3 ── filtering at 0.5
        # should drop the path.
        paths = g.find_paths(a, d, max_length=5,
                             min_edge_confidence=0.5)
        assert paths == []

    def test_missing_source_or_target_returns_empty(self):
        g, _ = self._graph_with_chain()
        paths = g.find_paths("nonexistent", "also-nonexistent")
        assert paths == []


class TestGetNeighborsFiltered:
    def _setup(self) -> tuple[EntityGraph, dict[str, str]]:
        g = EntityGraph(campaign_id="t", engagement_id="e")
        ids = {
            "person": g.add_person("Alice", source="x"),
            "email":  g.add_email("alice@acme.com", source="x"),
            "domain": g.add_domain("acme.com", source="x"),
        }
        g.relate(ids["person"], ids["email"],
                 RelationshipType.HAS_ACCOUNT, confidence=0.9)
        g.relate(ids["email"], ids["domain"],
                 RelationshipType.BELONGS_TO, confidence=0.9)
        return g, ids

    def test_no_filter_returns_all_neighbors(self):
        g, ids = self._setup()
        out = g.get_neighbors_filtered(ids["email"])
        values = {n["value"] for n in out}
        assert "Alice" in values
        assert "acme.com" in values

    def test_direction_out(self):
        g, ids = self._setup()
        out = g.get_neighbors_filtered(ids["email"], direction="out")
        values = {n["value"] for n in out}
        assert values == {"acme.com"}

    def test_direction_in(self):
        g, ids = self._setup()
        out = g.get_neighbors_filtered(ids["email"], direction="in")
        values = {n["value"] for n in out}
        assert values == {"Alice"}

    def test_edge_type_filter(self):
        g, ids = self._setup()
        out = g.get_neighbors_filtered(
            ids["email"], edge_type=RelationshipType.HAS_ACCOUNT,
        )
        # Only the inbound HAS_ACCOUNT edge (from Alice).
        values = {n["value"] for n in out}
        assert values == {"Alice"}


class TestGetAttackSurfaceNodes:
    def test_filters_by_default_attack_types(self):
        g = EntityGraph(campaign_id="t", engagement_id="e")
        # Mix of relevant + irrelevant types.
        g.add_subdomain("vpn.acme.com", "acme.com", "x")
        g.add_cloud_asset("aws/s3:bucket", "aws", "s3", "x")
        g.add_cve("CVE-2021-44228", "x")
        g.add_person("Alice", "x")  # NOT attack-surface
        g.add_hypothesis("hyp", "x")  # NOT attack-surface
        out = g.get_attack_surface_nodes()
        types = {n["entity_type"] for n in out}
        assert "subdomain" in types
        assert "cloud_asset" in types
        assert "cve" in types
        assert "person" not in types
        assert "hypothesis" not in types

    def test_confidence_floor(self):
        g = EntityGraph(campaign_id="t", engagement_id="e")
        g.add_subdomain("high.acme.com", "acme.com", "x",
                        confidence=0.9)
        g.add_subdomain("low.acme.com", "acme.com", "x",
                        confidence=0.3)
        out = g.get_attack_surface_nodes(min_confidence=0.5)
        values = {n["value"] for n in out}
        assert values == {"high.acme.com"}


# ──────────────────────────────────────────────────────────────────────
# GraphContext phase-aware
# ──────────────────────────────────────────────────────────────────────


class TestMostCitedEntities:
    def test_ranks_by_inbound_degree(self):
        g = EntityGraph(campaign_id="t", engagement_id="e")
        popular = g.add_domain("popular.com", "x")
        lonely = g.add_domain("lonely.com", "x")
        # Two hypotheses cite ``popular``; none cite ``lonely``.
        g.add_hypothesis("h1", source="x", cites=[popular])
        g.add_hypothesis("h2", source="x", cites=[popular])
        ctx = GraphContext(g)
        out = ctx.most_cited_entities()
        values = [n["value"] for n in out]
        # popular leads; lonely should NOT appear (in-deg == 0).
        assert values[0] == "popular.com"
        assert "lonely.com" not in values

    def test_entity_type_filter(self):
        g = EntityGraph(campaign_id="t", engagement_id="e")
        # A domain + email both cited; restrict result to email.
        dom = g.add_domain("acme.com", "x")
        em = g.add_email("a@acme.com", source="x")
        g.add_hypothesis("h1", source="x", cites=[dom])
        g.add_hypothesis("h2", source="x", cites=[em])
        ctx = GraphContext(g)
        out = ctx.most_cited_entities(entity_types=["email"])
        assert all(n["entity_type"] == "email" for n in out)
        assert any(n["value"] == "a@acme.com" for n in out)


class TestForPhase:
    """The phase-aware ``for_phase`` subsetter is what keeps the
    prompt budget under control as the graph grows. Each phase
    sees only the entity types relevant to its reasoning."""

    def _build(self) -> GraphContext:
        g = EntityGraph(campaign_id="t", engagement_id="e")
        # Sprinkle a variety of entity types.
        g.add_subdomain("vpn.acme.com", "acme.com", "x")
        g.add_email("alice@acme.com", source="x")
        g.add_person("Alice", "x")
        g.add_cve("CVE-2021-44228", "x")
        g.add_secret("api-key-abc", secret_type="aws-key", source="x")
        g.add_hypothesis("hyp", source="x")
        g.add_lead("lead", source="x")
        g.add_open_question("question", source="x")
        return GraphContext(g)

    def test_for_phase_returns_documented_shape(self):
        ctx = self._build()
        td = ctx.for_phase("phase4_correlation")
        assert "graph_summary" in td
        gs = td["graph_summary"]
        for k in (
            "phase", "total_entities", "total_relationships",
            "by_type", "top_entities", "most_cited",
            "hypotheses", "leads", "open_questions",
        ):
            assert k in gs, f"missing key {k!r}"
        assert gs["phase"] == "phase4_correlation"

    def test_phase4_focuses_on_correlation_types(self):
        ctx = self._build()
        td = ctx.for_phase("phase4_correlation")["graph_summary"]
        # phase4 cares about subdomains, emails, persons,
        # hypotheses, leads — NOT CVEs / secrets (those are
        # phase8's territory).
        top = td["top_entities"]
        assert "subdomain" in top
        assert "email" in top
        assert "person" in top
        # phase4 doesn't include CVE or secret in its focus.
        assert "cve" not in top
        assert "secret" not in top

    def test_phase8_focuses_on_attack_surface_types(self):
        ctx = self._build()
        td = ctx.for_phase("phase8_attack_surface")["graph_summary"]
        top = td["top_entities"]
        # phase8 cares about attack-surface assets.
        assert "subdomain" in top
        assert "secret" in top
        assert "cve" in top
        # phase8 does NOT include hypothesis / person in
        # ``top_entities`` (those are phase4's territory).
        # But hypotheses still appear via the dedicated
        # ``hypotheses`` field below.
        assert "person" not in top
        assert "hypothesis" not in top

    def test_unknown_phase_falls_back_to_default_focus(self):
        ctx = self._build()
        td = ctx.for_phase("phase999_invented")["graph_summary"]
        top = td["top_entities"]
        # Default focus matches the original to_task_data
        # types — covers the broad high-signal set.
        assert "subdomain" in top
        assert "email" in top

    def test_for_phase_carries_most_cited(self):
        g = EntityGraph(campaign_id="t", engagement_id="e")
        dom = g.add_subdomain("vpn.acme.com", "acme.com", "x")
        g.add_hypothesis("h", source="x", cites=[dom])
        td = GraphContext(g).for_phase("phase4_correlation")
        gs = td["graph_summary"]
        assert gs["most_cited"]
        # Highest-cited entry carries the value of the cited
        # subdomain.
        values = [m["value"] for m in gs["most_cited"]]
        assert "vpn.acme.com" in values

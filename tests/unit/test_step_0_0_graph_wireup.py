"""Tests for Step 0.0 of IMPLEMENTATION_PLAN_METASPLOIT_OSINT.md.

The wire-up that surfaces the existing :class:`EntityGraph` into
the LangGraph state and makes it reachable by the correlation +
risk-analyst agents via :class:`GraphContext`.

What this file pins
- New entity types ``HYPOTHESIS`` / ``LEAD`` / ``OPEN_QUESTION``
  and the corresponding Pydantic subclasses round-trip through
  the graph correctly.
- ``EntityGraph.from_state(state)`` produces a populated graph
  from the existing flat-bucket state without losing data.
- The reasoning-artifact lists (``state["hypotheses"]`` /
  ``confirmed_leads`` / ``open_questions``) become first-class
  graph nodes — not just text strings.
- ``GraphContext.to_task_data()`` returns the documented schema
  that agents depend on.
- Old ``state.json`` files (where ``state["entity_graph"]`` was
  the truncated name-list dict) load through the new code path
  without raising.

The end-to-end pilot — does the correlation agent actually
receive the graph summary in its task_data — is covered by the
existing Phase 4 integration tests; we don't duplicate the
LangGraph wiring here.
"""
from __future__ import annotations

from typing import Any

import pytest

from nexusrecon.core.entity_graph import EntityGraph
from nexusrecon.core.graph_context import GraphContext
from nexusrecon.models.entities import (
    EntityType,
    HypothesisEntity,
    LeadEntity,
    OpenQuestionEntity,
    RelationshipType,
)


# ──────────────────────────────────────────────────────────────────────
# Entity type registration
# ──────────────────────────────────────────────────────────────────────


class TestNewEntityTypes:
    """``EntityType.HYPOTHESIS`` / ``LEAD`` / ``OPEN_QUESTION``
    are part of the operator-facing contract from Step 0.0
    forward. Pin them so a refactor that drops one is loud."""

    def test_hypothesis_value(self):
        assert EntityType.HYPOTHESIS == "hypothesis"

    def test_lead_value(self):
        assert EntityType.LEAD == "lead"

    def test_open_question_value(self):
        assert EntityType.OPEN_QUESTION == "open_question"

    def test_cites_relationship_value(self):
        assert RelationshipType.CITES == "cites"

    def test_blocks_relationship_value(self):
        assert RelationshipType.BLOCKS == "blocks"

    def test_hypothesis_pydantic_defaults(self):
        h = HypothesisEntity(value="exec emails imply pretext angle")
        assert h.entity_type == EntityType.HYPOTHESIS
        assert h.status == "open"
        assert h.cites == []
        assert h.generated_by is None

    def test_lead_pydantic_defaults(self):
        ld = LeadEntity(value="public S3 bucket acme-leak")
        assert ld.entity_type == EntityType.LEAD
        assert ld.severity == "medium"
        assert ld.recommended_action is None

    def test_open_question_pydantic_defaults(self):
        q = OpenQuestionEntity(value="no emails found")
        assert q.entity_type == EntityType.OPEN_QUESTION
        assert q.blocks == []
        assert q.suggested_tools == []


# ──────────────────────────────────────────────────────────────────────
# EntityGraph reasoning-artifact builders
# ──────────────────────────────────────────────────────────────────────


class TestEntityGraphReasoningBuilders:
    """The new ``add_hypothesis`` / ``add_lead`` /
    ``add_open_question`` helpers should create the right
    entity type AND draw the CITES / BLOCKS edges back to the
    cited entities."""

    def _graph(self) -> EntityGraph:
        return EntityGraph(campaign_id="test", engagement_id="ENG-1")

    def test_add_hypothesis_creates_hypothesis_node(self):
        g = self._graph()
        hid = g.add_hypothesis(
            "Phase D found 5 personal emails — pretext candidates",
            source="phase4",
            generated_by="correlation",
        )
        node = g.get_entity(hid)
        assert node is not None
        assert node["entity_type"] == "hypothesis"
        assert "pretext" in node["statement"]
        assert node["generated_by"] == "correlation"

    def test_add_hypothesis_draws_cites_edges(self):
        g = self._graph()
        # First put two entities into the graph that we'll cite.
        email_id = g.add_email("ceo@acme.com", source="hunter")
        dom_id = g.add_domain("acme.com", source="whois")
        hid = g.add_hypothesis(
            "CEO email + domain → spear-phish ready",
            source="phase4",
            cites=[email_id, dom_id],
        )
        # CITES edges land FROM the hypothesis TO the cited entities.
        neighbors = list(g.graph.successors(hid))
        assert email_id in neighbors
        assert dom_id in neighbors
        # Edge type is CITES on both.
        for tgt in (email_id, dom_id):
            data = g.graph.get_edge_data(hid, tgt)
            assert data["rel_type"] == "cites"

    def test_add_lead_draws_cites_edges(self):
        g = self._graph()
        bucket_id = g.add_cloud_asset(
            "s3://acme-leak", provider="aws", service="s3", source="bucket_enum",
        )
        lid = g.add_lead(
            "Public S3 bucket acme-leak readable", source="phase4",
            cites=[bucket_id], severity="critical",
        )
        node = g.get_entity(lid)
        assert node["severity"] == "critical"
        # Edge wired.
        assert bucket_id in list(g.graph.successors(lid))

    def test_add_open_question_draws_blocks_edges(self):
        g = self._graph()
        # The downstream lead exists already — the open
        # question blocks it.
        lid = g.add_lead("Federation suggests password spray", source="x")
        qid = g.add_open_question(
            "What are the named SSO providers?",
            source="phase4", blocks=[lid],
            suggested_tools=["azure_tenant_enum"],
        )
        node = g.get_entity(qid)
        assert node["blocks"] == [lid]
        # BLOCKS edge from the question to the blocked lead.
        edge = g.graph.get_edge_data(qid, lid)
        assert edge["rel_type"] == "blocks"

    def test_cites_silently_skips_missing_ids(self):
        """A hypothesis can cite an entity id that hasn't landed
        in the graph yet (race condition during phase ingest).
        The edge is skipped rather than raising — Phase 0.0 is
        about non-fatal wire-up, not strict consistency."""
        g = self._graph()
        hid = g.add_hypothesis(
            "Statement", source="x",
            cites=["bogus-id-not-in-graph"],
        )
        # Node still created.
        assert g.get_entity(hid) is not None
        # No edge drawn (target doesn't exist).
        assert list(g.graph.successors(hid)) == []


# ──────────────────────────────────────────────────────────────────────
# EntityGraph.from_state
# ──────────────────────────────────────────────────────────────────────


class TestEntityGraphFromState:
    """``EntityGraph.from_state(state)`` is the Step 0.0 bridge
    from flat buckets to a real graph. Verify the buckets land
    as the right entity types."""

    def _state(self, **overrides: Any) -> dict[str, Any]:
        base: dict[str, Any] = {
            "campaign_id": "c1",
            "engagement_id": "ENG-1",
            "subdomain_intel": {},
            "email_intel": {"emails": {}},
            "cloud_intel": {},
            "code_intel": {},
            "vuln_intel": {},
            "hypotheses": [],
            "confirmed_leads": [],
            "open_questions": [],
        }
        base.update(overrides)
        return base

    def test_empty_state_produces_empty_graph(self):
        g = EntityGraph.from_state(self._state())
        assert g.graph.number_of_nodes() == 0
        assert g.graph.number_of_edges() == 0

    def test_subdomains_become_subdomain_entities(self):
        state = self._state(subdomain_intel={
            "www.acme.com": {"sources": ["crtsh"]},
            "vpn.acme.com": {"sources": ["amass"]},
        })
        g = EntityGraph.from_state(state)
        subs = g.get_entities_by_type(EntityType.SUBDOMAIN)
        assert {s["value"] for s in subs} == {"www.acme.com", "vpn.acme.com"}

    def test_emails_become_email_entities(self):
        state = self._state(email_intel={
            "emails": {
                "alice@acme.com": {"sources": ["hunter"]},
                "bob@acme.com": {"sources": ["hunter"]},
            },
        })
        g = EntityGraph.from_state(state)
        emails = g.get_entities_by_type(EntityType.EMAIL)
        assert {e["value"] for e in emails} == {
            "alice@acme.com", "bob@acme.com",
        }

    def test_cloud_assets_carry_attribution_confidence(self):
        state = self._state(cloud_intel={
            "aws/s3": {"attribution_confidence": 0.9, "buckets": []},
            "azure/onmicrosoft": {"attribution_confidence": 0.4},
        })
        g = EntityGraph.from_state(state)
        assets = g.get_entities_by_type(EntityType.CLOUD_ASSET)
        by_value = {a["value"]: a for a in assets}
        assert by_value["aws/s3"]["confidence"] == 0.9
        assert by_value["azure/onmicrosoft"]["confidence"] == 0.4

    def test_hypotheses_promoted_to_graph_nodes(self):
        state = self._state(
            hypotheses=["Pretext via LinkedIn likely", "M&A timing aligns"],
        )
        g = EntityGraph.from_state(state)
        hyps = g.get_entities_by_type(EntityType.HYPOTHESIS)
        assert len(hyps) == 2
        assert {h["statement"] for h in hyps} == {
            "Pretext via LinkedIn likely", "M&A timing aligns",
        }

    def test_confirmed_leads_promoted_to_lead_nodes(self):
        state = self._state(
            confirmed_leads=["Public S3 bucket: acme-leak"],
        )
        g = EntityGraph.from_state(state)
        leads = g.get_entities_by_type(EntityType.LEAD)
        assert len(leads) == 1
        assert leads[0]["statement"] == "Public S3 bucket: acme-leak"

    def test_open_questions_promoted_to_open_question_nodes(self):
        state = self._state(
            open_questions=["What IdP is in use?"],
        )
        g = EntityGraph.from_state(state)
        qs = g.get_entities_by_type(EntityType.OPEN_QUESTION)
        assert len(qs) == 1
        assert qs[0]["question"] == "What IdP is in use?"

    def test_cves_from_enriched_cves_become_cve_nodes(self):
        state = self._state(vuln_intel={
            "enriched_cves": {
                "CVE-2021-44228": {"cvss": 10.0},
                "CVE-2024-3094": {"cvss": 10.0},
                "garbage-key": {},  # filtered out
            },
        })
        g = EntityGraph.from_state(state)
        cves = g.get_entities_by_type(EntityType.CVE)
        assert {c["value"] for c in cves} == {
            "CVE-2021-44228", "CVE-2024-3094",
        }

    def test_idempotent_under_repeat_invocation(self):
        """Calling from_state twice on the same state yields the
        same node count — dedup catches the second pass."""
        state = self._state(subdomain_intel={
            "www.acme.com": {"sources": ["crtsh"]},
        }, email_intel={"emails": {"a@acme.com": {}}})
        g1 = EntityGraph.from_state(state)
        n1 = g1.graph.number_of_nodes()
        # Build a SECOND graph from the same state — should
        # match exactly.
        g2 = EntityGraph.from_state(state)
        assert g2.graph.number_of_nodes() == n1


# ──────────────────────────────────────────────────────────────────────
# GraphContext
# ──────────────────────────────────────────────────────────────────────


class TestGraphContext:
    """The summary an agent receives is the contract. Schema
    drift here breaks every agent that consumes it — pin the
    shape."""

    def _populated(self) -> EntityGraph:
        g = EntityGraph(campaign_id="c", engagement_id="e")
        g.add_subdomain("www.acme.com", parent="acme.com", source="crtsh")
        g.add_subdomain("vpn.acme.com", parent="acme.com", source="amass")
        g.add_email("alice@acme.com", source="hunter")
        g.add_email("bob@acme.com", source="hunter")
        g.add_hypothesis(
            "Pretext likely", source="phase4",
            generated_by="correlation",
        )
        g.add_lead("Public bucket exposes data",
                   source="phase4", severity="high")
        g.add_open_question("What IdP is used?", source="phase4")
        return g

    def test_count_by_type(self):
        ctx = GraphContext(self._populated())
        counts = ctx.count_by_type()
        assert counts.get("subdomain") == 2
        assert counts.get("email") == 2
        assert counts.get("hypothesis") == 1
        assert counts.get("lead") == 1
        assert counts.get("open_question") == 1

    def test_top_entities_filters_by_type(self):
        ctx = GraphContext(self._populated())
        emails = ctx.top_entities("email", limit=10)
        assert {e["value"] for e in emails} == {
            "alice@acme.com", "bob@acme.com",
        }

    def test_top_entities_respects_confidence_floor(self):
        g = self._populated()
        # Hypothesis defaults to confidence 0.6 — should filter
        # out when min_confidence > 0.6.
        g.add_hypothesis("low conf", source="x", confidence=0.3)
        ctx = GraphContext(g)
        out = ctx.top_entities(
            "hypothesis", min_confidence=0.5,
        )
        # The 0.3-confidence hypothesis should be filtered.
        assert all(h["confidence"] >= 0.5 for h in out)

    def test_hypotheses_returns_statements(self):
        ctx = GraphContext(self._populated())
        out = ctx.hypotheses()
        assert "Pretext likely" in out

    def test_leads_returns_statements(self):
        ctx = GraphContext(self._populated())
        out = ctx.leads()
        assert "Public bucket exposes data" in out

    def test_open_questions_returns_question_text(self):
        ctx = GraphContext(self._populated())
        out = ctx.open_questions()
        assert "What IdP is used?" in out

    def test_to_task_data_shape(self):
        ctx = GraphContext(self._populated())
        td = ctx.to_task_data()
        assert "graph_summary" in td
        gs = td["graph_summary"]
        for k in (
            "total_entities", "total_relationships",
            "by_type", "top_entities",
            "hypotheses", "leads", "open_questions",
        ):
            assert k in gs, f"missing key {k!r} in graph_summary"
        assert gs["total_entities"] == 7
        # Subdomain section populated; hypothesis NOT in
        # top_entities (only focus_types).
        assert "subdomain" in gs["top_entities"]
        assert "hypothesis" not in gs["top_entities"]

    def test_empty_graph_produces_zero_counts(self):
        g = EntityGraph(campaign_id="c", engagement_id="e")
        td = GraphContext(g).to_task_data()
        gs = td["graph_summary"]
        assert gs["total_entities"] == 0
        assert gs["total_relationships"] == 0
        assert gs["by_type"] == {}
        assert gs["hypotheses"] == []


# ──────────────────────────────────────────────────────────────────────
# Migration: old state.json formats
# ──────────────────────────────────────────────────────────────────────


class TestMigrationFromTruncatedFormat:
    """Pre-Step-0.0 ``state.json`` files held
    ``state["entity_graph"] = {"subdomains": [...], "emails":
    [...]}`` (truncated name lists). New code must tolerate
    these without crashing — the resume path re-runs phase 4,
    which rebuilds the graph from the flat buckets anyway."""

    def test_from_dict_tolerates_truncated_old_format(self):
        """Old-format dict lacks ``nodes`` and ``edges`` keys.
        ``EntityGraph.from_dict`` falls back to an empty graph
        rather than raising."""
        old_format = {
            "subdomains": ["www.acme.com", "vpn.acme.com"],
            "emails": ["alice@acme.com"],
        }
        g = EntityGraph.from_dict(old_format)
        # Empty: the truncated format carried no graph
        # information; the flat-bucket re-ingest is what
        # populates it.
        assert g.graph.number_of_nodes() == 0

    def test_from_state_rebuilds_after_loading_truncated(self):
        """The full migration path: resume a campaign whose
        state.json has the truncated entity_graph + flat
        buckets populated. ``from_state`` rebuilds correctly
        because it reads the flat buckets directly."""
        state = {
            "campaign_id": "c1",
            "engagement_id": "e1",
            "subdomain_intel": {"www.acme.com": {}, "vpn.acme.com": {}},
            "email_intel": {"emails": {"alice@acme.com": {}}},
            # Old truncated entity_graph — should be ignored by
            # from_state (which works off the flat buckets).
            "entity_graph": {
                "subdomains": ["www.acme.com", "vpn.acme.com"],
                "emails": ["alice@acme.com"],
            },
            "hypotheses": ["stale hypothesis from old run"],
            "confirmed_leads": [],
            "open_questions": [],
        }
        g = EntityGraph.from_state(state)
        # All flat-bucket entities present.
        assert len(g.get_entities_by_type(EntityType.SUBDOMAIN)) == 2
        assert len(g.get_entities_by_type(EntityType.EMAIL)) == 1
        # Old hypothesis preserved.
        hyps = g.get_entities_by_type(EntityType.HYPOTHESIS)
        assert len(hyps) == 1
        assert hyps[0]["statement"] == "stale hypothesis from old run"

    def test_new_format_round_trips_through_to_dict_from_dict(self):
        """Step 0.0's new ``state["entity_graph"]`` is a real
        graph dict ── verify it round-trips."""
        original = EntityGraph(campaign_id="c", engagement_id="e")
        original.add_subdomain("www.acme.com", "acme.com", "crtsh")
        original.add_email("alice@acme.com", source="hunter")
        original.add_hypothesis(
            "Pretext likely", source="phase4",
            generated_by="correlation",
        )
        serialized = original.to_dict()
        restored = EntityGraph.from_dict(serialized)
        assert restored.graph.number_of_nodes() == 3
        # Hypothesis survived round-trip with its
        # type-specific fields.
        hyps = restored.get_entities_by_type(EntityType.HYPOTHESIS)
        assert len(hyps) == 1
        assert hyps[0]["statement"] == "Pretext likely"
        assert hyps[0]["generated_by"] == "correlation"

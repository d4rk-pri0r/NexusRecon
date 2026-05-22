"""Tests for nexusrecon.core.pretext_scoring (Phase E9).

Covers:
  - PretextCandidate serialisation round-trip.
  - extract_topic_anchors: corp/personal email contributes domain +
    literal, handle / domain / real_name contribute the value, OTHER
    contributes verbatim, empty values are dropped, case-normalised
    to lower.
  - score_pretext_candidates input handling:
      * empty identity graph → empty list
      * no recent activities → empty list
      * target identity with no edges → empty list
      * target_ids=None scores every identity
      * target_ids=[specific] narrows to those
      * unknown target_id silently skipped
  - Per-target scoring math:
      * single sender + single activity → predictable combined_score
        (geometric mean of three axes)
      * geometric mean: any zero axis → zero combined score
      * dual-relevance boost applies when activity concerns sender too
      * stable ranking — ties break by (target, sender, topic)
      * per-target caps (max_candidates_per_target /
        max_senders_per_target / max_topics_per_target)
      * recency decay: same edge but older `last_observed` → lower
        sender_plausibility; same activity but older `published_at`
        → lower timing_score
  - Audit trail (`sources` field) contains edge sources + activity
    source.
  - Convenience helpers: group_candidates_by_target, summarise_candidates.
"""
from __future__ import annotations

import math
from datetime import UTC, datetime, timedelta

import pytest

from nexusrecon.core.identity_graph import (
    Identifier,
    IdentifierType,
    Identity,
    IdentityGraph,
    RelationshipEdge,
    derive_identity_id,
)
from nexusrecon.core.pretext_scoring import (
    DEFAULT_ACTIVITY_HALF_LIFE_DAYS,
    TOPIC_BASE_PLAUSIBILITY,
    TOPIC_DUAL_RELEVANCE_BOOST,
    PretextCandidate,
    extract_topic_anchors,
    group_candidates_by_target,
    score_pretext_candidates,
    summarise_candidates,
)
from nexusrecon.core.recent_activity import RecentActivity
from nexusrecon.core.relationship_graph import (
    DEFAULT_HALF_LIFE_DAYS,
    RelationshipGraph,
)

# ──────────────────────────────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────────────────────────────


def _iso(year: int, month: int = 1, day: int = 1) -> str:
    return datetime(year, month, day, tzinfo=UTC).isoformat()


NOW_TS = datetime(2024, 7, 1, tzinfo=UTC).timestamp()


def _identity_corp(seed: str, domain: str = "acme.com") -> Identity:
    """Build an identity with a corp email at the given domain."""
    ident = Identifier(
        value=f"{seed}@{domain}",
        identifier_type=IdentifierType.CORP_EMAIL,
        source="test",
        confidence=1.0,
    )
    name = Identifier(
        value=seed.title(),
        identifier_type=IdentifierType.REAL_NAME,
        source="test",
        confidence=0.9,
    )
    return Identity(
        identity_id=derive_identity_id([ident, name]),
        primary_label=seed.title(),
        identifiers=[ident, name],
    )


def _activity(
    *,
    target: str,
    title: str = "Acme Announces New Product",
    source: str = "news_intel",
    published_at: str = _iso(2024, 6, 25),  # ~6 days before NOW_TS
    kind: str = "press_release",
) -> RecentActivity:
    return RecentActivity(
        target=target,
        kind=kind,
        source=source,
        title=title,
        url=f"https://example.com/{title.replace(' ', '-').lower()}",
        summary="snippet",
        published_at=published_at,
        raw={},
    )


def _make_world(
    *,
    targets: list[str],
    senders: list[str],
    edges: list[tuple[str, str, str, float, str]] | None = None,
    activities: list[RecentActivity] | None = None,
    domain: str = "acme.com",
):
    """Build (identity_graph, relationship_graph, activities, id_map).

    ``edges`` is a list of ``(source_seed, target_seed, interaction_type,
    strength, last_observed)`` tuples.
    """
    ig = IdentityGraph()
    id_map: dict[str, str] = {}
    for seed in {*targets, *senders}:
        ident = _identity_corp(seed, domain=domain)
        ig.add_identity(ident)
        id_map[seed] = ident.identity_id
    rg = RelationshipGraph(identity_graph=ig)
    for src_seed, tgt_seed, itype, strength, last_obs in (edges or []):
        rg.add_edge(id_map[src_seed], RelationshipEdge(
            target_identity_id=id_map[tgt_seed],
            interaction_type=itype,
            strength=strength,
            last_observed=last_obs,
            sources=["test_source"],
        ))
    return ig, rg, list(activities or []), id_map


# ──────────────────────────────────────────────────────────────────────
# PretextCandidate
# ──────────────────────────────────────────────────────────────────────


class TestPretextCandidateShape:
    def test_to_dict_keys_and_rounding(self):
        c = PretextCandidate(
            target_identity_id="tid",
            target_label="Target",
            sender_identity_id="sid",
            sender_label="Sender",
            topic="Headline",
            timing_anchor={"title": "Headline"},
            sender_plausibility=0.123456,
            topic_plausibility=0.654321,
            timing_score=0.987654,
            combined_score=0.555555,
            sources=["github_social", "news_intel"],
            rationale="x",
        )
        d = c.to_dict()
        assert d["target_identity_id"] == "tid"
        assert d["sender_identity_id"] == "sid"
        # All numeric scores rounded to 3 dp
        assert d["sender_plausibility"] == 0.123
        assert d["topic_plausibility"] == 0.654
        assert d["timing_score"] == 0.988
        assert d["combined_score"] == 0.556
        assert d["sources"] == ["github_social", "news_intel"]


# ──────────────────────────────────────────────────────────────────────
# extract_topic_anchors
# ──────────────────────────────────────────────────────────────────────


class TestExtractTopicAnchors:
    def test_corp_email_contributes_literal_and_domain(self):
        ident = _identity_corp("alice")
        anchors = extract_topic_anchors(ident)
        assert "alice@acme.com" in anchors
        assert "acme.com" in anchors

    def test_personal_email_contributes_domain_too(self):
        i = Identifier(
            value="bob@personal.example",
            identifier_type=IdentifierType.PERSONAL_EMAIL,
            source="test", confidence=1.0,
        )
        identity = Identity(identity_id="x", identifiers=[i])
        anchors = extract_topic_anchors(identity)
        assert {"bob@personal.example", "personal.example"} <= anchors

    def test_handle_contributes_value(self):
        i = Identifier(
            value="alice-doe",
            identifier_type=IdentifierType.HANDLE,
            service="GitHub",
            source="test", confidence=1.0,
        )
        identity = Identity(identity_id="x", identifiers=[i])
        anchors = extract_topic_anchors(identity)
        assert anchors == {"alice-doe"}

    def test_domain_identifier_contributes_value(self):
        i = Identifier(
            value="example.com",
            identifier_type=IdentifierType.DOMAIN,
            source="test", confidence=1.0,
        )
        identity = Identity(identity_id="x", identifiers=[i])
        assert extract_topic_anchors(identity) == {"example.com"}

    def test_real_name_contributes_value(self):
        i = Identifier(
            value="Alice Doe",
            identifier_type=IdentifierType.REAL_NAME,
            source="test", confidence=1.0,
        )
        identity = Identity(identity_id="x", identifiers=[i])
        # Case-normalised to lower
        assert extract_topic_anchors(identity) == {"alice doe"}

    def test_other_kind_contributes_verbatim(self):
        i = Identifier(
            value="did:plc:abc123",
            identifier_type=IdentifierType.OTHER,
            source="test", confidence=1.0,
        )
        identity = Identity(identity_id="x", identifiers=[i])
        assert extract_topic_anchors(identity) == {"did:plc:abc123"}

    def test_case_insensitive(self):
        i = Identifier(
            value="Alice@ACME.COM",
            identifier_type=IdentifierType.CORP_EMAIL,
            source="test", confidence=1.0,
        )
        identity = Identity(identity_id="x", identifiers=[i])
        anchors = extract_topic_anchors(identity)
        assert "alice@acme.com" in anchors
        assert "acme.com" in anchors

    def test_empty_identifier_dropped(self):
        i = Identifier(
            value="",
            identifier_type=IdentifierType.HANDLE,
            source="test", confidence=1.0,
        )
        identity = Identity(identity_id="x", identifiers=[i])
        assert extract_topic_anchors(identity) == set()


# ──────────────────────────────────────────────────────────────────────
# score_pretext_candidates — input handling
# ──────────────────────────────────────────────────────────────────────


class TestScoreInputHandling:
    def test_empty_graph_returns_empty(self):
        out = score_pretext_candidates(
            identity_graph=IdentityGraph(),
            relationship_graph=RelationshipGraph(),
            recent_activities=[],
            now=NOW_TS,
        )
        assert out == []

    def test_no_activities_returns_empty(self):
        ig, rg, acts, ids = _make_world(
            targets=["alice"], senders=["bob"],
            edges=[("bob", "alice", "co-author", 0.9, _iso(2024, 6, 28))],
            activities=[],
        )
        out = score_pretext_candidates(
            identity_graph=ig, relationship_graph=rg,
            recent_activities=acts, now=NOW_TS,
        )
        assert out == []

    def test_no_edges_returns_empty(self):
        ig, rg, acts, ids = _make_world(
            targets=["alice"], senders=["bob"],
            edges=[],
            activities=[_activity(target="acme.com")],
        )
        out = score_pretext_candidates(
            identity_graph=ig, relationship_graph=rg,
            recent_activities=acts, now=NOW_TS,
        )
        assert out == []

    def test_target_with_no_anchors_skipped(self):
        # An identity with no identifiers at all → no anchors.
        ig = IdentityGraph()
        empty = Identity(identity_id="empty-id", primary_label="Ghost")
        ig.add_identity(empty)
        rg = RelationshipGraph(identity_graph=ig)
        out = score_pretext_candidates(
            identity_graph=ig, relationship_graph=rg,
            recent_activities=[_activity(target="anything")],
            now=NOW_TS,
        )
        assert out == []

    def test_default_target_ids_scores_all(self):
        ig, rg, acts, ids = _make_world(
            targets=["alice", "carol"], senders=["bob"],
            edges=[
                ("bob", "alice", "co-author", 0.9, _iso(2024, 6, 28)),
                ("bob", "carol", "co-author", 0.9, _iso(2024, 6, 28)),
            ],
            activities=[_activity(target="acme.com")],
        )
        out = score_pretext_candidates(
            identity_graph=ig, relationship_graph=rg,
            recent_activities=acts, now=NOW_TS,
        )
        targets_seen = {c.target_identity_id for c in out}
        assert targets_seen == {ids["alice"], ids["carol"]}

    def test_target_ids_narrows_scope(self):
        ig, rg, acts, ids = _make_world(
            targets=["alice", "carol"], senders=["bob"],
            edges=[
                ("bob", "alice", "co-author", 0.9, _iso(2024, 6, 28)),
                ("bob", "carol", "co-author", 0.9, _iso(2024, 6, 28)),
            ],
            activities=[_activity(target="acme.com")],
        )
        out = score_pretext_candidates(
            identity_graph=ig, relationship_graph=rg,
            recent_activities=acts,
            target_ids=[ids["alice"]],
            now=NOW_TS,
        )
        assert {c.target_identity_id for c in out} == {ids["alice"]}

    def test_unknown_target_id_silently_skipped(self):
        ig, rg, acts, ids = _make_world(
            targets=["alice"], senders=["bob"],
            edges=[("bob", "alice", "co-author", 0.9, _iso(2024, 6, 28))],
            activities=[_activity(target="acme.com")],
        )
        out = score_pretext_candidates(
            identity_graph=ig, relationship_graph=rg,
            recent_activities=acts,
            target_ids=["does-not-exist", ids["alice"]],
            now=NOW_TS,
        )
        assert len(out) == 1
        assert out[0].target_identity_id == ids["alice"]


# ──────────────────────────────────────────────────────────────────────
# Scoring math
# ──────────────────────────────────────────────────────────────────────


class TestScoringMath:
    def test_single_candidate_predictable_score(self):
        # Edge: bob → alice, strength 1.0, observed at NOW (no decay)
        # Activity: target=acme.com (matches alice's anchor), published
        # ~6 days before NOW with activity_half_life=90 days.
        ig, rg, acts, ids = _make_world(
            targets=["alice"], senders=["bob"],
            edges=[("bob", "alice", "co-author", 1.0, _iso(2024, 7, 1))],
            activities=[_activity(target="acme.com",
                                   published_at=_iso(2024, 6, 25))],
        )
        out = score_pretext_candidates(
            identity_graph=ig, relationship_graph=rg,
            recent_activities=acts, now=NOW_TS,
        )
        assert len(out) == 1
        c = out[0]
        # Expected:
        #   sender_plausibility = 1.0 (no decay)
        #   timing = 0.5 ** (6 / 90)
        #   topic = TOPIC_BASE_PLAUSIBILITY  (= 0.65) since the activity
        #           target "acme.com" also matches BOB's corp-domain anchor
        #           (both share acme.com), so the dual-relevance boost
        #           is applied → 0.65 * 1.5 = 0.975
        timing_expected = 0.5 ** (6.0 / DEFAULT_ACTIVITY_HALF_LIFE_DAYS)
        topic_expected = min(1.0, TOPIC_BASE_PLAUSIBILITY * TOPIC_DUAL_RELEVANCE_BOOST)
        combined_expected = (1.0 * topic_expected * timing_expected) ** (1.0 / 3.0)
        assert c.sender_plausibility == pytest.approx(1.0, abs=1e-6)
        assert c.timing_score == pytest.approx(timing_expected, abs=1e-6)
        assert c.topic_plausibility == pytest.approx(topic_expected, abs=1e-6)
        assert c.combined_score == pytest.approx(combined_expected, abs=1e-6)

    def test_timing_decay_lowers_score_for_older_activity(self):
        ig, rg, acts_recent, ids = _make_world(
            targets=["alice"], senders=["bob"],
            edges=[("bob", "alice", "co-author", 1.0, _iso(2024, 7, 1))],
            activities=[_activity(target="acme.com",
                                   published_at=_iso(2024, 7, 1))],  # today
        )
        ig2, rg2, acts_old, ids2 = _make_world(
            targets=["alice"], senders=["bob"],
            edges=[("bob", "alice", "co-author", 1.0, _iso(2024, 7, 1))],
            activities=[_activity(target="acme.com",
                                   published_at=_iso(2024, 1, 1))],  # ~180d
        )
        recent = score_pretext_candidates(
            identity_graph=ig, relationship_graph=rg,
            recent_activities=acts_recent, now=NOW_TS,
        )
        old = score_pretext_candidates(
            identity_graph=ig2, relationship_graph=rg2,
            recent_activities=acts_old, now=NOW_TS,
        )
        assert recent[0].combined_score > old[0].combined_score
        assert recent[0].timing_score > old[0].timing_score

    def test_geometric_mean_zero_axis_zeroes_combined(self):
        # Edge strength 0 → sender_plausibility 0 → combined 0
        ig, rg, acts, ids = _make_world(
            targets=["alice"], senders=["bob"],
            edges=[("bob", "alice", "co-author", 0.0, _iso(2024, 7, 1))],
            activities=[_activity(target="acme.com")],
        )
        out = score_pretext_candidates(
            identity_graph=ig, relationship_graph=rg,
            recent_activities=acts, now=NOW_TS,
        )
        # Zero-strength sender doesn't show up in top_correspondents_to
        # at all (that helper drops zero-strength edges). So the result
        # is empty rather than a zero-combined candidate.
        assert out == []

    def test_dual_relevance_boost_when_activity_also_concerns_sender(self):
        # Sender and target share the corp domain → activity targeting
        # that domain "concerns" both → topic gets boosted.
        ig, rg, acts, ids = _make_world(
            targets=["alice"], senders=["bob"],
            edges=[("bob", "alice", "co-author", 0.8, _iso(2024, 7, 1))],
            activities=[_activity(target="acme.com")],  # shared domain
        )
        out = score_pretext_candidates(
            identity_graph=ig, relationship_graph=rg,
            recent_activities=acts, now=NOW_TS,
        )
        assert len(out) == 1
        # Boosted topic = 0.65 * 1.5 = 0.975
        assert out[0].topic_plausibility == pytest.approx(
            min(1.0, TOPIC_BASE_PLAUSIBILITY * TOPIC_DUAL_RELEVANCE_BOOST),
            abs=1e-6,
        )

    def test_base_topic_when_sender_unrelated_to_activity(self):
        # Sender's domain ≠ activity target → no boost.
        ig = IdentityGraph()
        alice = _identity_corp("alice", domain="acme.com")
        bob = _identity_corp("bob", domain="other.com")
        ig.add_identity(alice)
        ig.add_identity(bob)
        rg = RelationshipGraph(identity_graph=ig)
        rg.add_edge(bob.identity_id, RelationshipEdge(
            target_identity_id=alice.identity_id,
            interaction_type="co-author",
            strength=0.8,
            last_observed=_iso(2024, 7, 1),
            sources=["test_source"],
        ))
        out = score_pretext_candidates(
            identity_graph=ig, relationship_graph=rg,
            recent_activities=[_activity(target="acme.com")],
            now=NOW_TS,
        )
        assert len(out) == 1
        # No boost: topic stays at base.
        assert out[0].topic_plausibility == pytest.approx(
            TOPIC_BASE_PLAUSIBILITY, abs=1e-6,
        )


# ──────────────────────────────────────────────────────────────────────
# Ranking + caps
# ──────────────────────────────────────────────────────────────────────


class TestRankingAndCaps:
    def test_ranking_by_combined_descending(self):
        # Three senders, all linked to alice with varying strength.
        ig, rg, acts, ids = _make_world(
            targets=["alice"],
            senders=["strong_sender", "mid_sender", "weak_sender"],
            edges=[
                ("strong_sender", "alice", "co-author", 0.9,
                 _iso(2024, 7, 1)),
                ("mid_sender", "alice", "co-author", 0.5,
                 _iso(2024, 7, 1)),
                ("weak_sender", "alice", "co-author", 0.2,
                 _iso(2024, 7, 1)),
            ],
            activities=[_activity(target="acme.com",
                                   published_at=_iso(2024, 7, 1))],
        )
        out = score_pretext_candidates(
            identity_graph=ig, relationship_graph=rg,
            recent_activities=acts, now=NOW_TS,
        )
        # 3 senders × 1 activity = 3 candidates
        assert len(out) == 3
        scores = [c.combined_score for c in out]
        assert scores == sorted(scores, reverse=True)
        assert out[0].sender_identity_id == ids["strong_sender"]
        assert out[-1].sender_identity_id == ids["weak_sender"]

    def test_max_senders_per_target_caps(self):
        # 5 candidate senders; cap at 2.
        senders = [f"s{i}" for i in range(5)]
        edges = [(s, "alice", "co-author", 0.5 + 0.05 * i, _iso(2024, 7, 1))
                 for i, s in enumerate(senders)]
        ig, rg, acts, ids = _make_world(
            targets=["alice"], senders=senders,
            edges=edges,
            activities=[_activity(target="acme.com")],
        )
        out = score_pretext_candidates(
            identity_graph=ig, relationship_graph=rg,
            recent_activities=acts,
            max_senders_per_target=2,
            now=NOW_TS,
        )
        assert len({c.sender_identity_id for c in out}) == 2

    def test_max_topics_per_target_caps(self):
        # 5 candidate activities; cap at 2.
        activities = [_activity(target="acme.com", title=f"Story {i}",
                                 published_at=_iso(2024, 7, 1))
                      for i in range(5)]
        ig, rg, _, ids = _make_world(
            targets=["alice"], senders=["bob"],
            edges=[("bob", "alice", "co-author", 0.9, _iso(2024, 7, 1))],
        )
        out = score_pretext_candidates(
            identity_graph=ig, relationship_graph=rg,
            recent_activities=activities,
            max_topics_per_target=2,
            now=NOW_TS,
        )
        # 1 sender × 2 topics = 2 candidates
        assert len(out) == 2

    def test_max_candidates_per_target_caps(self):
        # 3 senders × 3 topics = 9 raw candidates → cap to 2.
        senders = ["s0", "s1", "s2"]
        edges = [(s, "alice", "co-author", 0.7, _iso(2024, 7, 1))
                 for s in senders]
        activities = [_activity(target="acme.com", title=f"T{i}",
                                 published_at=_iso(2024, 7, 1))
                      for i in range(3)]
        ig, rg, _, ids = _make_world(
            targets=["alice"], senders=senders,
            edges=edges,
        )
        out = score_pretext_candidates(
            identity_graph=ig, relationship_graph=rg,
            recent_activities=activities,
            max_candidates_per_target=2,
            now=NOW_TS,
        )
        assert len(out) == 2

    def test_stable_tie_break(self):
        # Two senders with IDENTICAL inputs — combined_scores should
        # match; ordering breaks by (target, sender_id, topic) ascending.
        ig, rg, acts, ids = _make_world(
            targets=["alice"], senders=["sa", "sb"],
            edges=[
                ("sa", "alice", "co-author", 0.7, _iso(2024, 7, 1)),
                ("sb", "alice", "co-author", 0.7, _iso(2024, 7, 1)),
            ],
            activities=[_activity(target="acme.com",
                                   published_at=_iso(2024, 7, 1))],
        )
        out = score_pretext_candidates(
            identity_graph=ig, relationship_graph=rg,
            recent_activities=acts, now=NOW_TS,
        )
        # Both candidates have the same combined score.
        assert math.isclose(
            out[0].combined_score, out[1].combined_score, abs_tol=1e-9,
        )
        # The two sender ids are sorted ascending in the output.
        assert out[0].sender_identity_id <= out[1].sender_identity_id


# ──────────────────────────────────────────────────────────────────────
# Audit trail
# ──────────────────────────────────────────────────────────────────────


class TestAuditTrail:
    def test_sources_includes_edge_and_activity_sources(self):
        ig = IdentityGraph()
        alice = _identity_corp("alice")
        bob = _identity_corp("bob")
        ig.add_identity(alice)
        ig.add_identity(bob)
        rg = RelationshipGraph(identity_graph=ig)
        rg.add_edge(bob.identity_id, RelationshipEdge(
            target_identity_id=alice.identity_id,
            interaction_type="co-author",
            strength=0.8,
            last_observed=_iso(2024, 7, 1),
            sources=["github_social", "linkedin_social"],
        ))
        activity = _activity(target="acme.com", source="news_intel")
        out = score_pretext_candidates(
            identity_graph=ig, relationship_graph=rg,
            recent_activities=[activity], now=NOW_TS,
        )
        assert len(out) == 1
        sources = out[0].sources
        # All three sources surface in the audit trail.
        assert "github_social" in sources
        assert "linkedin_social" in sources
        assert "news_intel" in sources

    def test_rationale_mentions_topic_and_sender(self):
        ig, rg, acts, ids = _make_world(
            targets=["alice"], senders=["bob"],
            edges=[("bob", "alice", "co-author", 0.9, _iso(2024, 7, 1))],
            activities=[_activity(target="acme.com",
                                   title="Acme Announces Product",
                                   published_at=_iso(2024, 7, 1))],
        )
        out = score_pretext_candidates(
            identity_graph=ig, relationship_graph=rg,
            recent_activities=acts, now=NOW_TS,
        )
        rationale = out[0].rationale
        assert "Bob" in rationale  # sender label
        assert "Acme Announces Product" in rationale
        assert "co-author" in rationale


# ──────────────────────────────────────────────────────────────────────
# Sender-side recency
# ──────────────────────────────────────────────────────────────────────


class TestSenderRecency:
    def test_older_edge_lowers_sender_plausibility(self):
        # Same setup but the edge is 180 days old (one half-life) vs
        # observed today.
        ig_recent, rg_recent, acts, ids = _make_world(
            targets=["alice"], senders=["bob"],
            edges=[("bob", "alice", "co-author", 0.9, _iso(2024, 7, 1))],
            activities=[_activity(target="acme.com",
                                   published_at=_iso(2024, 7, 1))],
        )
        # 180-day-old edge
        ig_old, rg_old, _, ids2 = _make_world(
            targets=["alice"], senders=["bob"],
            edges=[("bob", "alice", "co-author", 0.9,
                    (datetime(2024, 7, 1, tzinfo=UTC)
                     - timedelta(days=180)).isoformat())],
            activities=[],
        )
        out_recent = score_pretext_candidates(
            identity_graph=ig_recent, relationship_graph=rg_recent,
            recent_activities=acts, now=NOW_TS,
        )
        out_old = score_pretext_candidates(
            identity_graph=ig_old, relationship_graph=rg_old,
            recent_activities=acts, now=NOW_TS,
        )
        assert out_recent[0].sender_plausibility > out_old[0].sender_plausibility


# ──────────────────────────────────────────────────────────────────────
# Convenience helpers
# ──────────────────────────────────────────────────────────────────────


class TestConvenienceHelpers:
    def test_group_candidates_by_target_preserves_order(self):
        c1 = PretextCandidate(
            target_identity_id="t1", target_label="T1",
            sender_identity_id="s1", sender_label="S1",
            topic="x", timing_anchor={},
            sender_plausibility=0.5, topic_plausibility=0.5,
            timing_score=0.5, combined_score=0.5,
        )
        c2 = PretextCandidate(
            target_identity_id="t1", target_label="T1",
            sender_identity_id="s2", sender_label="S2",
            topic="y", timing_anchor={},
            sender_plausibility=0.3, topic_plausibility=0.3,
            timing_score=0.3, combined_score=0.3,
        )
        c3 = PretextCandidate(
            target_identity_id="t2", target_label="T2",
            sender_identity_id="s1", sender_label="S1",
            topic="z", timing_anchor={},
            sender_plausibility=0.7, topic_plausibility=0.7,
            timing_score=0.7, combined_score=0.7,
        )
        groups = group_candidates_by_target([c1, c2, c3])
        assert set(groups.keys()) == {"t1", "t2"}
        assert [c.sender_identity_id for c in groups["t1"]] == ["s1", "s2"]
        assert [c.sender_identity_id for c in groups["t2"]] == ["s1"]

    def test_summarise_candidates_empty(self):
        out = summarise_candidates([])
        assert out == {
            "target_count": 0,
            "candidate_count": 0,
            "score_min": 0.0,
            "score_median": 0.0,
            "score_max": 0.0,
        }

    def test_summarise_candidates_basic(self):
        c1 = PretextCandidate(
            target_identity_id="t1", target_label="T1",
            sender_identity_id="s1", sender_label="S1",
            topic="x", timing_anchor={},
            sender_plausibility=0.0, topic_plausibility=0.0,
            timing_score=0.0, combined_score=0.2,
        )
        c2 = PretextCandidate(
            target_identity_id="t1", target_label="T1",
            sender_identity_id="s2", sender_label="S2",
            topic="y", timing_anchor={},
            sender_plausibility=0.0, topic_plausibility=0.0,
            timing_score=0.0, combined_score=0.5,
        )
        c3 = PretextCandidate(
            target_identity_id="t2", target_label="T2",
            sender_identity_id="s1", sender_label="S1",
            topic="z", timing_anchor={},
            sender_plausibility=0.0, topic_plausibility=0.0,
            timing_score=0.0, combined_score=0.8,
        )
        out = summarise_candidates([c1, c2, c3])
        assert out["candidate_count"] == 3
        assert out["target_count"] == 2
        assert out["score_min"] == 0.2
        assert out["score_max"] == 0.8
        # median of sorted [0.2, 0.5, 0.8] is 0.5
        assert out["score_median"] == 0.5


# ──────────────────────────────────────────────────────────────────────
# Constants sanity
# ──────────────────────────────────────────────────────────────────────


class TestConstants:
    def test_topic_constants_in_range(self):
        assert 0.0 < TOPIC_BASE_PLAUSIBILITY <= 1.0
        assert TOPIC_DUAL_RELEVANCE_BOOST >= 1.0

    def test_default_activity_half_life_tighter_than_edge_half_life(self):
        # Activity timing should be tighter than relationship recency.
        assert DEFAULT_ACTIVITY_HALF_LIFE_DAYS < DEFAULT_HALF_LIFE_DAYS

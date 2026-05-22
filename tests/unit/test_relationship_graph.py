"""Tests for nexusrecon.core.relationship_graph (Phase E1).

Covers:
  - Time helpers (_to_timestamp, _pick_later) including ISO ``Z`` /
    ``+00:00`` suffixes, naive timestamps, epoch numbers, bad input.
  - decay_strength: half-life math at 0 / 1 / 2 half-lives, clock-skew
    safety, None / out-of-range handling, configurable half-life.
  - aggregate_strengths: empty / single / multi-source corroboration,
    cap at 1.0, input clamping.
  - merge_edges: source union order, strength aggregation, later
    timestamp wins, immutability of inputs.
  - RelationshipGraph.add_edge: dedup by (source, target, type),
    multi-interaction same pair, cycles, mirror to / from Identity.
  - Lookup helpers (edges_from / edges_to / edge_between / sources /
    targets / source_of).
  - decayed_strength_to + top_correspondents / top_correspondents_to
    with deterministic ``now=`` overrides.
  - to_dict / from_dict round trip + idempotent resume (no double-
    mirror onto identity.related_to).
  - build_from_identity_graph: dedup of duplicate edges within a
    single related_to list + re-sync back to canonical form.
"""
from __future__ import annotations

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
from nexusrecon.core.relationship_graph import (
    DEFAULT_HALF_LIFE_DAYS,
    INTERACTION_WEIGHTS,
    STRENGTH_CAP,
    RelationshipGraph,
    _pick_later,
    _to_timestamp,
    aggregate_strengths,
    build_from_identity_graph,
    decay_strength,
    merge_edges,
)

# ──────────────────────────────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────────────────────────────


def _make_identity(seed: str) -> Identity:
    """Build an Identity with a deterministic id from a single identifier."""
    ident = Identifier(
        value=f"{seed}@corp.com",
        identifier_type=IdentifierType.CORP_EMAIL,
        source="test",
        confidence=1.0,
    )
    return Identity(
        identity_id=derive_identity_id([ident]),
        primary_label=seed,
        identifiers=[ident],
    )


def _make_graph(*seeds: str) -> tuple[IdentityGraph, dict[str, str]]:
    """Build an IdentityGraph + return {seed: identity_id} map for tests."""
    g = IdentityGraph()
    ids: dict[str, str] = {}
    for seed in seeds:
        identity = _make_identity(seed)
        g.add_identity(identity)
        ids[seed] = identity.identity_id
    return g, ids


def _iso(year: int, month: int = 1, day: int = 1, hour: int = 0) -> str:
    """ISO-8601 with explicit UTC, used by tests for deterministic timestamps."""
    return datetime(year, month, day, hour, tzinfo=UTC).isoformat()


# ──────────────────────────────────────────────────────────────────────
# Time helpers
# ──────────────────────────────────────────────────────────────────────


class TestToTimestamp:
    def test_iso_with_z_suffix(self):
        ts = _to_timestamp("2024-01-01T00:00:00Z")
        assert ts == datetime(2024, 1, 1, tzinfo=UTC).timestamp()

    def test_iso_with_explicit_offset(self):
        ts = _to_timestamp("2024-01-01T00:00:00+00:00")
        assert ts == datetime(2024, 1, 1, tzinfo=UTC).timestamp()

    def test_naive_iso_assumed_utc(self):
        ts = _to_timestamp("2024-01-01T00:00:00")
        assert ts == datetime(2024, 1, 1, tzinfo=UTC).timestamp()

    def test_epoch_int(self):
        assert _to_timestamp(1_700_000_000) == 1_700_000_000.0

    def test_epoch_float(self):
        assert _to_timestamp(1_700_000_000.5) == 1_700_000_000.5

    def test_none_returns_none(self):
        assert _to_timestamp(None) is None

    def test_empty_string_returns_none(self):
        assert _to_timestamp("") is None

    def test_invalid_string_returns_none(self):
        assert _to_timestamp("not-a-date") is None

    def test_non_string_non_number_returns_none(self):
        assert _to_timestamp([]) is None  # type: ignore[arg-type]


class TestPickLater:
    def test_both_none(self):
        assert _pick_later(None, None) is None

    def test_first_none_returns_second(self):
        assert _pick_later(None, "2024-01-01T00:00:00Z") == "2024-01-01T00:00:00Z"

    def test_second_none_returns_first(self):
        assert _pick_later("2024-01-01T00:00:00Z", None) == "2024-01-01T00:00:00Z"

    def test_later_wins(self):
        assert _pick_later(_iso(2023), _iso(2024)) == _iso(2024)
        assert _pick_later(_iso(2024), _iso(2023)) == _iso(2024)

    def test_equal_returns_first_for_stable_ordering(self):
        a = _iso(2024)
        assert _pick_later(a, a) == a

    def test_unparseable_loses_to_parseable(self):
        assert _pick_later("garbage", _iso(2024)) == _iso(2024)
        assert _pick_later(_iso(2024), "garbage") == _iso(2024)


# ──────────────────────────────────────────────────────────────────────
# decay_strength
# ──────────────────────────────────────────────────────────────────────


class TestDecayStrength:
    def test_zero_age_returns_unchanged(self):
        now = datetime(2024, 6, 1, tzinfo=UTC).timestamp()
        result = decay_strength(0.8, _iso(2024, 6, 1), now=now)
        assert result == pytest.approx(0.8)

    def test_one_half_life_halves(self):
        # 180 days before "now"
        now = datetime(2024, 7, 1, tzinfo=UTC).timestamp()
        observed = (
            datetime(2024, 7, 1, tzinfo=UTC) - timedelta(days=180)
        ).isoformat()
        result = decay_strength(0.8, observed, half_life_days=180.0, now=now)
        assert result == pytest.approx(0.4, abs=1e-6)

    def test_two_half_lives_quarters(self):
        now = datetime(2024, 7, 1, tzinfo=UTC).timestamp()
        observed = (
            datetime(2024, 7, 1, tzinfo=UTC) - timedelta(days=360)
        ).isoformat()
        result = decay_strength(0.8, observed, half_life_days=180.0, now=now)
        assert result == pytest.approx(0.2, abs=1e-6)

    def test_configurable_half_life(self):
        now = datetime(2024, 7, 1, tzinfo=UTC).timestamp()
        observed = (
            datetime(2024, 7, 1, tzinfo=UTC) - timedelta(days=30)
        ).isoformat()
        # 30-day half-life: 30 days old → exactly half
        result = decay_strength(1.0, observed, half_life_days=30.0, now=now)
        assert result == pytest.approx(0.5, abs=1e-6)

    def test_future_timestamp_no_amplification(self):
        # Clock skew → observed is in the future. Should NOT amplify.
        now = datetime(2024, 6, 1, tzinfo=UTC).timestamp()
        observed = _iso(2025)
        result = decay_strength(0.5, observed, now=now)
        assert result == 0.5

    def test_none_last_observed_returns_clamped_base(self):
        assert decay_strength(0.7, None) == 0.7
        assert decay_strength(1.5, None) == STRENGTH_CAP
        assert decay_strength(-0.3, None) == 0.0

    def test_zero_or_negative_half_life_returns_clamped(self):
        assert decay_strength(0.6, _iso(2020), half_life_days=0) == 0.6
        assert decay_strength(0.6, _iso(2020), half_life_days=-1) == 0.6

    def test_unparseable_timestamp_returns_clamped(self):
        assert decay_strength(0.6, "not-a-date") == 0.6

    def test_out_of_range_base_strength_clamped(self):
        now = datetime(2024, 7, 1, tzinfo=UTC).timestamp()
        # base > 1.0 clamped to 1.0 then decayed
        observed = (
            datetime(2024, 7, 1, tzinfo=UTC) - timedelta(days=180)
        ).isoformat()
        result = decay_strength(2.0, observed, half_life_days=180.0, now=now)
        assert result == pytest.approx(0.5, abs=1e-6)

        # base < 0 clamped to 0
        assert decay_strength(-0.5, observed, half_life_days=180.0, now=now) == 0.0


# ──────────────────────────────────────────────────────────────────────
# aggregate_strengths
# ──────────────────────────────────────────────────────────────────────


class TestAggregateStrengths:
    def test_empty_is_zero(self):
        assert aggregate_strengths() == 0.0

    def test_single_unchanged(self):
        assert aggregate_strengths(0.4) == pytest.approx(0.4)

    def test_two_half_sources(self):
        # 1 - (1-0.5)*(1-0.5) = 1 - 0.25 = 0.75
        assert aggregate_strengths(0.5, 0.5) == pytest.approx(0.75)

    def test_three_half_sources(self):
        # 1 - 0.5^3 = 0.875
        assert aggregate_strengths(0.5, 0.5, 0.5) == pytest.approx(0.875)

    def test_symmetry(self):
        a = aggregate_strengths(0.3, 0.7, 0.2)
        b = aggregate_strengths(0.7, 0.2, 0.3)
        assert a == pytest.approx(b)

    def test_one_full_strength_caps(self):
        # 1 - 0 * (1 - x) = 1, regardless of other inputs
        assert aggregate_strengths(1.0, 0.4) == STRENGTH_CAP
        assert aggregate_strengths(0.9, 1.0, 0.5) == STRENGTH_CAP

    def test_monotonic_non_decreasing(self):
        # Adding a non-zero strength can never lower the result.
        base = aggregate_strengths(0.3, 0.4)
        plus = aggregate_strengths(0.3, 0.4, 0.2)
        assert plus >= base

    def test_clamps_out_of_range_inputs(self):
        # 1.5 clamped to 1.0 → result 1.0 (since one full source caps).
        assert aggregate_strengths(1.5, 0.4) == STRENGTH_CAP
        # Negative clamped to 0 → other input unchanged.
        assert aggregate_strengths(-0.5, 0.4) == pytest.approx(0.4)


# ──────────────────────────────────────────────────────────────────────
# merge_edges
# ──────────────────────────────────────────────────────────────────────


class TestMergeEdges:
    def _edge(self, **kw):
        defaults = dict(
            target_identity_id="tgt",
            interaction_type="reply",
            strength=0.5,
            last_observed=_iso(2024),
            sources=["github"],
        )
        defaults.update(kw)
        return RelationshipEdge(**defaults)

    def test_strength_aggregated(self):
        a = self._edge(strength=0.5)
        b = self._edge(strength=0.5, sources=["mastodon"])
        merged = merge_edges(a, b)
        assert merged.strength == pytest.approx(0.75)

    def test_sources_unioned_order_preserved(self):
        a = self._edge(sources=["github", "twitter"])
        b = self._edge(sources=["mastodon", "github"])  # github already present
        merged = merge_edges(a, b)
        assert merged.sources == ["github", "twitter", "mastodon"]

    def test_later_timestamp_wins(self):
        a = self._edge(last_observed=_iso(2023))
        b = self._edge(last_observed=_iso(2024))
        assert merge_edges(a, b).last_observed == _iso(2024)
        assert merge_edges(b, a).last_observed == _iso(2024)

    def test_missing_timestamp_loses(self):
        a = self._edge(last_observed=None)
        b = self._edge(last_observed=_iso(2024))
        assert merge_edges(a, b).last_observed == _iso(2024)
        assert merge_edges(b, a).last_observed == _iso(2024)

    def test_both_missing_timestamps(self):
        a = self._edge(last_observed=None)
        b = self._edge(last_observed=None)
        assert merge_edges(a, b).last_observed is None

    def test_inputs_are_not_mutated(self):
        a = self._edge(strength=0.4, sources=["github"])
        b = self._edge(strength=0.6, sources=["mastodon"])
        a_sources_before = list(a.sources)
        b_sources_before = list(b.sources)
        a_strength_before = a.strength
        b_strength_before = b.strength
        _ = merge_edges(a, b)
        assert a.sources == a_sources_before
        assert b.sources == b_sources_before
        assert a.strength == a_strength_before
        assert b.strength == b_strength_before


# ──────────────────────────────────────────────────────────────────────
# RelationshipGraph: mutation + dedup
# ──────────────────────────────────────────────────────────────────────


class TestRelationshipGraphAddEdge:
    def test_new_edge_appended(self):
        rg = RelationshipGraph()
        edge = RelationshipEdge(
            target_identity_id="b",
            interaction_type="reply",
            strength=0.5,
            sources=["github"],
        )
        rg.add_edge("a", edge)
        assert len(rg) == 1
        assert rg.edges() == [edge]
        assert rg.source_of(0) == "a"

    def test_duplicate_triple_merges(self):
        rg = RelationshipGraph()
        rg.add_edge("a", RelationshipEdge(
            target_identity_id="b", interaction_type="reply",
            strength=0.4, sources=["github"],
        ))
        merged = rg.add_edge("a", RelationshipEdge(
            target_identity_id="b", interaction_type="reply",
            strength=0.6, sources=["mastodon"],
        ))
        assert len(rg) == 1
        # 1 - (1-0.4)*(1-0.6) = 0.76
        assert merged.strength == pytest.approx(0.76)
        assert merged.sources == ["github", "mastodon"]

    def test_different_interaction_type_creates_second_edge(self):
        rg = RelationshipGraph()
        rg.add_edge("a", RelationshipEdge(
            target_identity_id="b", interaction_type="reply",
            strength=0.4,
        ))
        rg.add_edge("a", RelationshipEdge(
            target_identity_id="b", interaction_type="follower",
            strength=0.2,
        ))
        assert len(rg) == 2

    def test_cycle_two_separate_edges(self):
        rg = RelationshipGraph()
        rg.add_edge("alice", RelationshipEdge(
            target_identity_id="bob", interaction_type="reply",
            strength=0.5,
        ))
        rg.add_edge("bob", RelationshipEdge(
            target_identity_id="alice", interaction_type="reply",
            strength=0.5,
        ))
        assert len(rg) == 2
        assert len(rg.edges_from("alice")) == 1
        assert len(rg.edges_from("bob")) == 1

    def test_add_edges_for_bulk(self):
        rg = RelationshipGraph()
        rg.add_edges_for("a", [
            RelationshipEdge(target_identity_id="b", interaction_type="reply", strength=0.5),
            RelationshipEdge(target_identity_id="c", interaction_type="reply", strength=0.3),
        ])
        assert len(rg) == 2

    def test_self_loop_allowed(self):
        rg = RelationshipGraph()
        rg.add_edge("a", RelationshipEdge(
            target_identity_id="a", interaction_type="reply", strength=0.1,
        ))
        assert len(rg) == 1


class TestRelationshipGraphMirror:
    def test_mirror_to_identity_when_attached(self):
        ig, ids = _make_graph("alice", "bob")
        rg = RelationshipGraph(identity_graph=ig)
        rg.add_edge(ids["alice"], RelationshipEdge(
            target_identity_id=ids["bob"],
            interaction_type="reply",
            strength=0.5,
            sources=["github"],
        ))
        alice = ig.get(ids["alice"])
        assert len(alice.related_to) == 1
        assert alice.related_to[0].target_identity_id == ids["bob"]

    def test_mirror_updates_on_merge_in_place(self):
        ig, ids = _make_graph("alice", "bob")
        rg = RelationshipGraph(identity_graph=ig)
        rg.add_edge(ids["alice"], RelationshipEdge(
            target_identity_id=ids["bob"],
            interaction_type="reply",
            strength=0.4,
            sources=["github"],
        ))
        rg.add_edge(ids["alice"], RelationshipEdge(
            target_identity_id=ids["bob"],
            interaction_type="reply",
            strength=0.6,
            sources=["mastodon"],
        ))
        alice = ig.get(ids["alice"])
        # Still ONE entry on related_to, not two.
        assert len(alice.related_to) == 1
        assert alice.related_to[0].strength == pytest.approx(0.76)
        assert alice.related_to[0].sources == ["github", "mastodon"]

    def test_no_mirror_when_no_identity_graph(self):
        rg = RelationshipGraph()  # detached
        # Should not raise; index is populated, mirror is just skipped.
        rg.add_edge("a", RelationshipEdge(
            target_identity_id="b", interaction_type="reply", strength=0.5,
        ))
        assert len(rg) == 1

    def test_no_mirror_when_source_unknown(self):
        ig, ids = _make_graph("alice")
        rg = RelationshipGraph(identity_graph=ig)
        # Unknown source: index populated, mirror skipped (no crash).
        rg.add_edge("ghost-id", RelationshipEdge(
            target_identity_id=ids["alice"], interaction_type="reply", strength=0.5,
        ))
        assert len(rg) == 1
        alice = ig.get(ids["alice"])
        assert alice.related_to == []  # alice is the target, not source

    def test_attach_identity_graph_post_construction(self):
        rg = RelationshipGraph()
        ig, ids = _make_graph("alice", "bob")
        rg.attach_identity_graph(ig)
        rg.add_edge(ids["alice"], RelationshipEdge(
            target_identity_id=ids["bob"], interaction_type="reply", strength=0.5,
        ))
        alice = ig.get(ids["alice"])
        assert len(alice.related_to) == 1


# ──────────────────────────────────────────────────────────────────────
# Lookup helpers
# ──────────────────────────────────────────────────────────────────────


class TestLookups:
    def _populate(self):
        rg = RelationshipGraph()
        rg.add_edge("a", RelationshipEdge(target_identity_id="b", interaction_type="reply", strength=0.5))
        rg.add_edge("a", RelationshipEdge(target_identity_id="b", interaction_type="follower", strength=0.2))
        rg.add_edge("a", RelationshipEdge(target_identity_id="c", interaction_type="reply", strength=0.3))
        rg.add_edge("b", RelationshipEdge(target_identity_id="c", interaction_type="reply", strength=0.4))
        return rg

    def test_edges_from(self):
        rg = self._populate()
        a_edges = rg.edges_from("a")
        assert len(a_edges) == 3
        assert {e.target_identity_id for e in a_edges} == {"b", "c"}

    def test_edges_to(self):
        rg = self._populate()
        c_edges = rg.edges_to("c")
        assert len(c_edges) == 2

    def test_edge_between_filters_by_pair(self):
        rg = self._populate()
        between = rg.edge_between("a", "b")
        assert len(between) == 2  # reply + follower
        assert {e.interaction_type for e in between} == {"reply", "follower"}

    def test_edge_between_filters_by_interaction(self):
        rg = self._populate()
        between = rg.edge_between("a", "b", interaction_type="reply")
        assert len(between) == 1
        assert between[0].interaction_type == "reply"

    def test_edge_between_unknown_pair_returns_empty(self):
        rg = self._populate()
        assert rg.edge_between("nope", "nada") == []

    def test_sources_and_targets(self):
        rg = self._populate()
        assert set(rg.sources()) == {"a", "b"}
        assert set(rg.targets()) == {"b", "c"}


# ──────────────────────────────────────────────────────────────────────
# Scoring helpers
# ──────────────────────────────────────────────────────────────────────


class TestDecayedStrengthTo:
    def test_combines_multiple_interactions(self):
        now = datetime(2024, 7, 1, tzinfo=UTC).timestamp()
        rg = RelationshipGraph()
        # Two edges between a→b, both observed today, different types.
        rg.add_edge("a", RelationshipEdge(
            target_identity_id="b", interaction_type="reply",
            strength=0.5, last_observed=_iso(2024, 7, 1),
        ))
        rg.add_edge("a", RelationshipEdge(
            target_identity_id="b", interaction_type="follower",
            strength=0.5, last_observed=_iso(2024, 7, 1),
        ))
        result = rg.decayed_strength_to("a", "b", now=now)
        # No decay (age 0), aggregate two 0.5s → 0.75
        assert result == pytest.approx(0.75)

    def test_applies_decay(self):
        now = datetime(2024, 7, 1, tzinfo=UTC).timestamp()
        observed = (
            datetime(2024, 7, 1, tzinfo=UTC) - timedelta(days=180)
        ).isoformat()
        rg = RelationshipGraph()
        rg.add_edge("a", RelationshipEdge(
            target_identity_id="b", interaction_type="reply",
            strength=0.8, last_observed=observed,
        ))
        result = rg.decayed_strength_to("a", "b", half_life_days=180.0, now=now)
        # Single edge, age = half-life → strength / 2 = 0.4
        assert result == pytest.approx(0.4, abs=1e-6)

    def test_unknown_pair_returns_zero(self):
        rg = RelationshipGraph()
        assert rg.decayed_strength_to("a", "b") == 0.0


class TestTopCorrespondents:
    def test_ranks_by_decayed_strength(self):
        now = datetime(2024, 7, 1, tzinfo=UTC).timestamp()
        rg = RelationshipGraph()
        rg.add_edge("a", RelationshipEdge(
            target_identity_id="b", interaction_type="reply",
            strength=0.8, last_observed=_iso(2024, 7, 1),
        ))
        rg.add_edge("a", RelationshipEdge(
            target_identity_id="c", interaction_type="reply",
            strength=0.6, last_observed=_iso(2024, 7, 1),
        ))
        rg.add_edge("a", RelationshipEdge(
            target_identity_id="d", interaction_type="reply",
            strength=0.4, last_observed=_iso(2024, 7, 1),
        ))
        ranked = rg.top_correspondents("a", now=now)
        assert [t for t, _ in ranked] == ["b", "c", "d"]
        assert ranked[0][1] == pytest.approx(0.8)

    def test_drops_zero_strength(self):
        # An edge with strength 0 and no decay → drops from ranking.
        rg = RelationshipGraph()
        rg.add_edge("a", RelationshipEdge(
            target_identity_id="b", interaction_type="reply", strength=0.0,
        ))
        assert rg.top_correspondents("a") == []

    def test_n_limit(self):
        now = datetime(2024, 7, 1, tzinfo=UTC).timestamp()
        rg = RelationshipGraph()
        for letter in "bcdefg":
            rg.add_edge("a", RelationshipEdge(
                target_identity_id=letter, interaction_type="reply",
                strength=0.5, last_observed=_iso(2024, 7, 1),
            ))
        ranked = rg.top_correspondents("a", n=3, now=now)
        assert len(ranked) == 3

    def test_stable_tie_break_by_id(self):
        now = datetime(2024, 7, 1, tzinfo=UTC).timestamp()
        rg = RelationshipGraph()
        for letter in "cba":  # added in c, b, a order
            rg.add_edge("src", RelationshipEdge(
                target_identity_id=letter, interaction_type="reply",
                strength=0.5, last_observed=_iso(2024, 7, 1),
            ))
        ranked = rg.top_correspondents("src", now=now)
        # All equal strength → sorted by id ascending.
        assert [t for t, _ in ranked] == ["a", "b", "c"]

    def test_unknown_source_returns_empty(self):
        rg = RelationshipGraph()
        assert rg.top_correspondents("nope") == []


class TestTopCorrespondentsTo:
    def test_inbound_ranking(self):
        now = datetime(2024, 7, 1, tzinfo=UTC).timestamp()
        rg = RelationshipGraph()
        # Multiple sources pointing at target "z".
        rg.add_edge("strong", RelationshipEdge(
            target_identity_id="z", interaction_type="reply",
            strength=0.9, last_observed=_iso(2024, 7, 1),
        ))
        rg.add_edge("weak", RelationshipEdge(
            target_identity_id="z", interaction_type="reply",
            strength=0.2, last_observed=_iso(2024, 7, 1),
        ))
        ranked = rg.top_correspondents_to("z", now=now)
        assert [s for s, _ in ranked] == ["strong", "weak"]


# ──────────────────────────────────────────────────────────────────────
# Serialisation
# ──────────────────────────────────────────────────────────────────────


class TestSerialisation:
    def test_to_dict_shape(self):
        rg = RelationshipGraph()
        rg.add_edge("a", RelationshipEdge(
            target_identity_id="b", interaction_type="reply",
            strength=0.5, last_observed=_iso(2024), sources=["github"],
        ))
        data = rg.to_dict()
        assert data["edge_count"] == 1
        assert len(data["edges"]) == 1
        edge_data = data["edges"][0]
        assert edge_data["source_identity_id"] == "a"
        assert edge_data["target_identity_id"] == "b"
        assert edge_data["interaction_type"] == "reply"
        assert edge_data["strength"] == 0.5
        assert edge_data["sources"] == ["github"]
        assert data["by_source"] == {"a": [0]}
        assert data["by_target"] == {"b": [0]}

    def test_round_trip_preserves_edges(self):
        rg = RelationshipGraph()
        rg.add_edge("a", RelationshipEdge(
            target_identity_id="b", interaction_type="reply",
            strength=0.5, sources=["github"],
        ))
        rg.add_edge("a", RelationshipEdge(
            target_identity_id="c", interaction_type="follower",
            strength=0.2, sources=["twitter"],
        ))
        rebuilt = RelationshipGraph.from_dict(rg.to_dict())
        assert len(rebuilt) == 2
        ab = rebuilt.edge_between("a", "b")
        assert len(ab) == 1
        assert ab[0].strength == pytest.approx(0.5)
        assert ab[0].sources == ["github"]
        ac = rebuilt.edge_between("a", "c")
        assert ac[0].interaction_type == "follower"

    def test_from_dict_does_not_mutate_related_to(self):
        # Simulate campaign resume: identity_graph rebuilt first,
        # related_to already populated. from_dict() must NOT append again.
        ig, ids = _make_graph("alice", "bob")
        alice = ig.get(ids["alice"])
        existing_edge = RelationshipEdge(
            target_identity_id=ids["bob"],
            interaction_type="reply", strength=0.5,
        )
        alice.related_to.append(existing_edge)

        # Serialised relationship-graph payload that includes the same edge.
        payload = {
            "edges": [{
                "source_identity_id": ids["alice"],
                "target_identity_id": ids["bob"],
                "interaction_type": "reply",
                "strength": 0.5,
                "last_observed": None,
                "sources": [],
            }],
        }
        _ = RelationshipGraph.from_dict(payload, identity_graph=ig)

        # related_to was untouched ── still exactly one entry.
        assert len(alice.related_to) == 1


# ──────────────────────────────────────────────────────────────────────
# build_from_identity_graph
# ──────────────────────────────────────────────────────────────────────


class TestBuildFromIdentityGraph:
    def test_builds_top_level_index(self):
        ig, ids = _make_graph("alice", "bob")
        alice = ig.get(ids["alice"])
        alice.related_to.append(RelationshipEdge(
            target_identity_id=ids["bob"], interaction_type="reply",
            strength=0.5, sources=["github"],
        ))
        rg = build_from_identity_graph(ig)
        assert len(rg) == 1
        assert rg.edges_from(ids["alice"])[0].target_identity_id == ids["bob"]

    def test_dedups_within_single_related_to(self):
        # Some upstream produced two entries for the same triple ──
        # build should merge them.
        ig, ids = _make_graph("alice", "bob")
        alice = ig.get(ids["alice"])
        alice.related_to.append(RelationshipEdge(
            target_identity_id=ids["bob"], interaction_type="reply",
            strength=0.4, sources=["github"],
        ))
        alice.related_to.append(RelationshipEdge(
            target_identity_id=ids["bob"], interaction_type="reply",
            strength=0.6, sources=["mastodon"],
        ))
        rg = build_from_identity_graph(ig)
        assert len(rg) == 1
        merged = rg.edges_from(ids["alice"])[0]
        assert merged.strength == pytest.approx(0.76)
        assert merged.sources == ["github", "mastodon"]

    def test_resyncs_related_to_after_dedup(self):
        ig, ids = _make_graph("alice", "bob")
        alice = ig.get(ids["alice"])
        # Plant TWO duplicate edges on related_to.
        alice.related_to.append(RelationshipEdge(
            target_identity_id=ids["bob"], interaction_type="reply",
            strength=0.4, sources=["github"],
        ))
        alice.related_to.append(RelationshipEdge(
            target_identity_id=ids["bob"], interaction_type="reply",
            strength=0.6, sources=["mastodon"],
        ))
        build_from_identity_graph(ig)
        # After build, related_to has the single canonical merged entry.
        assert len(alice.related_to) == 1
        assert alice.related_to[0].strength == pytest.approx(0.76)

    def test_empty_identity_graph_produces_empty_relationship_graph(self):
        ig = IdentityGraph()
        rg = build_from_identity_graph(ig)
        assert len(rg) == 0

    def test_cycles_preserved(self):
        ig, ids = _make_graph("alice", "bob")
        ig.get(ids["alice"]).related_to.append(RelationshipEdge(
            target_identity_id=ids["bob"], interaction_type="reply", strength=0.5,
        ))
        ig.get(ids["bob"]).related_to.append(RelationshipEdge(
            target_identity_id=ids["alice"], interaction_type="reply", strength=0.5,
        ))
        rg = build_from_identity_graph(ig)
        assert len(rg) == 2


# ──────────────────────────────────────────────────────────────────────
# Constants sanity
# ──────────────────────────────────────────────────────────────────────


class TestConstants:
    def test_default_half_life_positive(self):
        assert DEFAULT_HALF_LIFE_DAYS > 0

    def test_strength_cap_is_one(self):
        assert STRENGTH_CAP == 1.0

    def test_interaction_weights_in_range(self):
        for k, v in INTERACTION_WEIGHTS.items():
            assert 0.0 <= v <= 1.0, f"{k}={v} out of [0, 1]"

    def test_strong_interactions_outrank_weak(self):
        # Sanity: co-author > follower.
        assert INTERACTION_WEIGHTS["co-author"] > INTERACTION_WEIGHTS["follower"]
        assert INTERACTION_WEIGHTS["co-speaker"] > INTERACTION_WEIGHTS["mention"]

"""Top-level relationship graph for Phase E (human-to-human edges).

Phase D shipped the :class:`~nexusrecon.core.identity_graph.Identity`
model with an empty ``related_to: list[RelationshipEdge]`` field. Phase E
populates those edges from social-graph tools (E2-E8: GitHub social,
Mastodon, Bluesky, LinkedIn, business-partner data, conference
co-speaker links, recent activity). This module owns the *graph-level*
view on top of those per-identity lists.

Dual-storage architecture (locked-in 2026-05-21):

  - Edges live on the **source** identity's ``related_to`` list ── the
    same place Phase D's contract promised. Natural traversal from an
    identity ("who does Jane talk to?") works without consulting any
    other object.
  - Edges are ALSO indexed at the **top level** here, with
    ``by_source`` and ``by_target`` indexes so graph-wide questions
    ("which identities have the most edges pointing AT them?") are
    O(1) for E9 pretext scoring.

The two views stay in sync ── :meth:`RelationshipGraph.add_edge`
updates both. The :func:`build_from_identity_graph` helper builds the
top-level view from existing per-identity data without mutating it
(used by campaign-resume after :meth:`IdentityGraph.from_dict`).

Pure Python. No network, no LLM calls, no file I/O. Scoring math lives
here so it's deterministic and unit-testable.

Recency decay (the headline math):

  Edges carry a base ``strength`` (interaction-type-dependent, set by
  the source tool) and a ``last_observed`` ISO-8601 timestamp. The
  effective strength at scoring time is::

      decayed = strength * 0.5 ** (age_days / half_life_days)

  Default half-life is 180 days ── a co-author signal from 6 months
  ago is half as strong as one from yesterday, and a year-old signal
  is a quarter as strong. The half-life is configurable per call so
  E9 can experiment with different decay profiles without modifying
  this module.

Cross-source aggregation:

  When two tools independently surface the same edge (e.g. GitHub +
  Mastodon both observe Alice replying to Bob) the strengths combine
  via the standard "independent-evidence" formula::

      aggregated = 1 - (1 - strength_a) * (1 - strength_b)

  This is monotonically increasing (more sources → higher strength),
  capped at 1.0, and reduces to ``max(a, b)`` when one source has
  zero strength. The same formula is used by :func:`merge_edges` (at
  ingest time) and by :meth:`RelationshipGraph.decayed_strength_to`
  (at scoring time, combining different interaction types between the
  same pair).
"""
from __future__ import annotations

import time
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from nexusrecon.core.identity_graph import (
    IdentityGraph,
    RelationshipEdge,
)

# ──────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────

#: Default half-life for recency decay (in days). After this many days
#: an interaction's strength contribution is exactly halved. Picked at
#: 180 days because spear-phishing pretexts ("hey, we co-authored that
#: paper last quarter") feel current up to a few months and tired past
#: a year. E9 can override per scoring call.
DEFAULT_HALF_LIFE_DAYS = 180.0

#: Aggregated strength can never exceed this. Kept as a named constant
#: so tests can assert against it and callers can introspect.
STRENGTH_CAP = 1.0

#: Suggested base-strength weights by interaction type. Tools may use
#: these as defaults when constructing :class:`RelationshipEdge` values;
#: they are NOT enforced by this module. The ordering reflects how much
#: each signal contributes to "does this sender feel real to the target":
#: co-authorship and co-speaking are repeated multi-step collaborations
#: (very strong); follower-only is passive (very weak).
INTERACTION_WEIGHTS: dict[str, float] = {
    "co-author": 0.95,
    "co-speaker": 0.95,
    "collaborator": 0.85,
    "colleague": 0.80,
    "recommender": 0.75,
    "endorser": 0.70,
    "reply": 0.55,
    "commenter": 0.50,
    "mention": 0.40,
    "boost": 0.35,
    "repost": 0.35,
    "follower": 0.20,
}


# ──────────────────────────────────────────────────────────────────────
# Time helpers
# ──────────────────────────────────────────────────────────────────────


def _to_timestamp(value: str | float | int | None) -> float | None:
    """Best-effort parse of an ISO-8601 string or epoch number into a
    UTC unix timestamp.

    Returns ``None`` when the value is missing or unparseable ── callers
    treat that as "no recency signal available" rather than crashing on
    a slightly-malformed upstream value.

    ISO-8601 inputs may end in ``Z`` (UTC marker) or carry an explicit
    offset like ``+00:00``; naive timestamps are assumed UTC.
    """
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if not isinstance(value, str) or not value:
        return None
    s = value.strip()
    if s.endswith("Z"):
        # ``datetime.fromisoformat`` only learnt ``Z`` in 3.11; normalise
        # to a literal UTC offset for older runtimes and consistency.
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.timestamp()


def _pick_later(a: str | None, b: str | None) -> str | None:
    """Return the later of two ISO-8601 timestamp strings.

    A missing or unparseable timestamp loses to any parseable one. When
    both are missing, returns ``None``. When both parse to the same
    instant, returns ``a`` (stable tie-break).
    """
    if not a:
        return b
    if not b:
        return a
    ts_a = _to_timestamp(a)
    ts_b = _to_timestamp(b)
    if ts_a is None:
        return b
    if ts_b is None:
        return a
    return a if ts_a >= ts_b else b


# ──────────────────────────────────────────────────────────────────────
# Decay + aggregation primitives
# ──────────────────────────────────────────────────────────────────────


def decay_strength(
    base_strength: float,
    last_observed: str | float | int | None,
    *,
    half_life_days: float = DEFAULT_HALF_LIFE_DAYS,
    now: float | None = None,
) -> float:
    """Apply exponential recency decay to an edge strength.

    Formula::

        decayed = base * 0.5 ** (age_days / half_life_days)

    Args:
        base_strength: Pre-decay strength in ``[0, 1]``. Out-of-range
            values are clamped before decay applies.
        last_observed: ISO-8601 string OR epoch seconds. ``None`` means
            "no recency signal available" ── returns ``base_strength``
            unchanged (clamped).
        half_life_days: Days for the strength to halve. ``<= 0`` is
            treated as "no decay" (returns base_strength clamped).
        now: Override "current time" for reproducible tests. Defaults
            to :func:`time.time`.

    Returns:
        Decayed strength in ``[0, STRENGTH_CAP]``. When
        ``last_observed`` is in the future (clock skew or bad upstream
        data) the function returns the unmodified base strength rather
        than amplifying it.
    """
    clamped = max(0.0, min(STRENGTH_CAP, base_strength))
    if last_observed is None or half_life_days <= 0:
        return clamped

    observed_ts = _to_timestamp(last_observed)
    if observed_ts is None:
        return clamped

    now_ts = now if now is not None else time.time()
    if observed_ts >= now_ts:
        # Future / equal-to-now ── no decay rather than amplification.
        return clamped

    age_days = (now_ts - observed_ts) / 86400.0
    decayed = clamped * (0.5 ** (age_days / half_life_days))
    return max(0.0, min(STRENGTH_CAP, decayed))


def aggregate_strengths(*strengths: float) -> float:
    """Combine independent-evidence strengths via the OR-of-independent
    -events formula::

        aggregated = 1 - prod(1 - s_i)

    Properties:
      - ``aggregate_strengths()`` → ``0.0`` (no evidence).
      - ``aggregate_strengths(s)`` → ``s`` (single source unchanged).
      - Monotonically non-decreasing in each input.
      - Capped at :data:`STRENGTH_CAP`.
      - Symmetric ── order of arguments doesn't matter.

    Each input is clamped to ``[0, 1]`` before combination so an
    upstream tool that emits slightly out-of-band values can't break
    the invariant.
    """
    if not strengths:
        return 0.0
    running = 0.0
    for s in strengths:
        clamped = max(0.0, min(STRENGTH_CAP, s))
        running = 1.0 - (1.0 - running) * (1.0 - clamped)
    return min(STRENGTH_CAP, running)


# ──────────────────────────────────────────────────────────────────────
# Edge merging
# ──────────────────────────────────────────────────────────────────────


def merge_edges(
    existing: RelationshipEdge,
    incoming: RelationshipEdge,
) -> RelationshipEdge:
    """Merge two edges that share the same
    ``(source_identity, target_identity, interaction_type)`` triple.

    Strategy:
      - **strength**: aggregated via :func:`aggregate_strengths`
        (cross-source corroboration raises confidence; capped at 1.0).
      - **sources**: union of both lists, preserving the order of
        ``existing`` first (deterministic for tests).
      - **last_observed**: later timestamp wins; ``None`` loses to any
        value.

    Neither input is mutated ── a fresh :class:`RelationshipEdge` is
    returned. The caller is responsible for any storage updates.

    Pre-condition (not enforced for performance): the inputs must
    actually share a target + interaction_type. The graph uses this
    function only after a dedup-key lookup, so the contract holds in
    practice.
    """
    merged_sources = list(existing.sources)
    for s in incoming.sources:
        if s not in merged_sources:
            merged_sources.append(s)

    aggregated = aggregate_strengths(existing.strength, incoming.strength)
    last = _pick_later(existing.last_observed, incoming.last_observed)

    return RelationshipEdge(
        target_identity_id=existing.target_identity_id,
        interaction_type=existing.interaction_type,
        strength=aggregated,
        last_observed=last,
        sources=merged_sources,
    )


# ──────────────────────────────────────────────────────────────────────
# RelationshipGraph
# ──────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class _EdgeKey:
    """Internal dedup key. Kept as a frozen dataclass (instead of a raw
    tuple) so the field meanings are explicit at the call sites."""

    source: str
    target: str
    interaction_type: str


class RelationshipGraph:
    """Per-campaign graph of relationship edges between identities.

    Built by Phase E tools (E2-E8) on top of the
    :class:`~nexusrecon.core.identity_graph.IdentityGraph` produced by
    Phase 2 / 2.5. Consumed by Phase E9 (:func:`pretext_scoring`) and
    Phase E11 (reports + phase wiring).

    Cycles are permitted ── ``Alice → Bob`` and ``Bob → Alice`` are
    two distinct edges with potentially different interaction
    histories. Self-loops (``Alice → Alice``) are allowed but only
    meaningful for self-referential interactions (e.g. self-replies);
    callers usually filter them out before scoring.

    Edges are stored once in a flat list; the
    ``by_source`` / ``by_target`` indexes hold integer positions for
    O(1) lookup. Dedup is by
    ``(source_identity_id, target_identity_id, interaction_type)`` ──
    re-adding the same triple merges via :func:`merge_edges` rather
    than creating a duplicate.
    """

    def __init__(self, identity_graph: IdentityGraph | None = None) -> None:
        self._identity_graph = identity_graph
        # Parallel arrays: _edges[i] is the i-th edge; _source_of[i] is
        # the identity that owns it. RelationshipEdge intentionally
        # doesn't carry its source identity (it lives in the source's
        # related_to list), so this graph tracks the mapping.
        self._edges: list[RelationshipEdge] = []
        self._source_of: list[str] = []
        self._by_source: dict[str, list[int]] = defaultdict(list)
        self._by_target: dict[str, list[int]] = defaultdict(list)
        self._edge_index: dict[_EdgeKey, int] = {}

    # ── Wiring ──────────────────────────────────────────────────────

    def attach_identity_graph(self, identity_graph: IdentityGraph) -> None:
        """Bind an IdentityGraph after construction. Subsequent
        :meth:`add_edge` calls will mirror onto the matching
        ``Identity.related_to`` list."""
        self._identity_graph = identity_graph

    @property
    def identity_graph(self) -> IdentityGraph | None:
        return self._identity_graph

    # ── Edge mutation ───────────────────────────────────────────────

    def add_edge(
        self,
        source_identity_id: str,
        edge: RelationshipEdge,
    ) -> RelationshipEdge:
        """Add an edge from ``source_identity_id`` to
        ``edge.target_identity_id``.

        If an edge with the same
        ``(source, target, interaction_type)`` already exists, the
        strengths and sources are merged via :func:`merge_edges` and
        the existing entry is updated in place. Otherwise a new entry
        is appended.

        When an :class:`IdentityGraph` is attached and contains the
        source identity, the merged edge is also mirrored onto that
        identity's ``related_to`` list so per-identity traversal stays
        in sync.

        Returns the canonical (post-merge) edge that now lives in the
        graph ── useful for callers that want to read the aggregated
        strength.
        """
        final = self._add_edge_indexed(source_identity_id, edge)
        self._mirror_to_identity(source_identity_id, final)
        return final

    def add_edges_for(
        self,
        source_identity_id: str,
        edges: Iterable[RelationshipEdge],
    ) -> None:
        """Convenience: bulk-add edges from a single source identity."""
        for edge in edges:
            self.add_edge(source_identity_id, edge)

    def _add_edge_indexed(
        self,
        source_identity_id: str,
        edge: RelationshipEdge,
    ) -> RelationshipEdge:
        """Top-level index mutation only ── does NOT touch
        ``Identity.related_to``. Used by :meth:`add_edge` (paired with
        a mirror call) and by :meth:`from_dict` /
        :func:`build_from_identity_graph` (no mirror needed because
        the per-identity data is already in place)."""
        key = _EdgeKey(
            source=source_identity_id,
            target=edge.target_identity_id,
            interaction_type=edge.interaction_type,
        )
        existing_idx = self._edge_index.get(key)
        if existing_idx is not None:
            existing = self._edges[existing_idx]
            merged = merge_edges(existing, edge)
            self._edges[existing_idx] = merged
            return merged

        idx = len(self._edges)
        self._edges.append(edge)
        self._source_of.append(source_identity_id)
        self._edge_index[key] = idx
        self._by_source[source_identity_id].append(idx)
        self._by_target[edge.target_identity_id].append(idx)
        return edge

    def _mirror_to_identity(
        self,
        source_identity_id: str,
        edge: RelationshipEdge,
    ) -> None:
        """Reflect the post-merge edge onto the source identity's
        ``related_to`` list. Silent no-op when no IdentityGraph is
        attached or the source identity is unknown ── the top-level
        index is still authoritative."""
        if self._identity_graph is None:
            return
        identity = self._identity_graph.get(source_identity_id)
        if identity is None:
            return
        for i, existing in enumerate(identity.related_to):
            if (
                existing.target_identity_id == edge.target_identity_id
                and existing.interaction_type == edge.interaction_type
            ):
                identity.related_to[i] = edge
                return
        identity.related_to.append(edge)

    # ── Lookup ──────────────────────────────────────────────────────

    def edges(self) -> list[RelationshipEdge]:
        """Snapshot of all edges in insertion order."""
        return list(self._edges)

    def edges_from(self, source_identity_id: str) -> list[RelationshipEdge]:
        """Edges where this identity is the source."""
        return [self._edges[i] for i in self._by_source.get(source_identity_id, [])]

    def edges_to(self, target_identity_id: str) -> list[RelationshipEdge]:
        """Edges where this identity is the target."""
        return [self._edges[i] for i in self._by_target.get(target_identity_id, [])]

    def edge_between(
        self,
        source_identity_id: str,
        target_identity_id: str,
        interaction_type: str | None = None,
    ) -> list[RelationshipEdge]:
        """All edges from ``source`` to ``target``, optionally filtered
        by interaction type. May return more than one entry when the
        same pair has multiple interaction types (e.g. follower +
        commenter)."""
        out: list[RelationshipEdge] = []
        for idx in self._by_source.get(source_identity_id, []):
            edge = self._edges[idx]
            if edge.target_identity_id != target_identity_id:
                continue
            if interaction_type and edge.interaction_type != interaction_type:
                continue
            out.append(edge)
        return out

    def source_of(self, edge_index: int) -> str:
        """Look up the source identity ID for an edge by its position
        in :meth:`edges`. Useful when iterating the flat edge list and
        needing to recover the source."""
        return self._source_of[edge_index]

    def sources(self) -> list[str]:
        """Distinct source identity IDs that have at least one
        outbound edge."""
        return list(self._by_source.keys())

    def targets(self) -> list[str]:
        """Distinct target identity IDs that have at least one inbound
        edge."""
        return list(self._by_target.keys())

    def __len__(self) -> int:
        return len(self._edges)

    # ── Scoring helpers (deterministic, no network) ─────────────────

    def decayed_strength_to(
        self,
        source_identity_id: str,
        target_identity_id: str,
        *,
        half_life_days: float = DEFAULT_HALF_LIFE_DAYS,
        now: float | None = None,
    ) -> float:
        """Combined, recency-decayed strength of all edges between the
        given pair.

        Each underlying edge is decayed independently via
        :func:`decay_strength`, then combined via
        :func:`aggregate_strengths`. The result is a single ``[0, 1]``
        score E9 can use as the "sender plausibility" axis.
        """
        edges = self.edge_between(source_identity_id, target_identity_id)
        if not edges:
            return 0.0
        decayed = [
            decay_strength(
                e.strength,
                e.last_observed,
                half_life_days=half_life_days,
                now=now,
            )
            for e in edges
        ]
        return aggregate_strengths(*decayed)

    def top_correspondents(
        self,
        source_identity_id: str,
        *,
        n: int = 10,
        half_life_days: float = DEFAULT_HALF_LIFE_DAYS,
        now: float | None = None,
    ) -> list[tuple[str, float]]:
        """Top-N targets the source talks to most, ranked by decayed
        aggregate strength. Zero-strength targets are dropped.

        Returns a list of ``(target_identity_id, decayed_strength)``
        tuples sorted descending by strength. Ties break on target
        identity_id (stable for tests)."""
        targets: dict[str, list[RelationshipEdge]] = defaultdict(list)
        for idx in self._by_source.get(source_identity_id, []):
            edge = self._edges[idx]
            targets[edge.target_identity_id].append(edge)

        ranked: list[tuple[str, float]] = []
        for target_id, edge_list in targets.items():
            decayed = [
                decay_strength(
                    e.strength,
                    e.last_observed,
                    half_life_days=half_life_days,
                    now=now,
                )
                for e in edge_list
            ]
            score = aggregate_strengths(*decayed)
            if score > 0:
                ranked.append((target_id, score))
        ranked.sort(key=lambda t: (-t[1], t[0]))
        return ranked[:n]

    def top_correspondents_to(
        self,
        target_identity_id: str,
        *,
        n: int = 10,
        half_life_days: float = DEFAULT_HALF_LIFE_DAYS,
        now: float | None = None,
    ) -> list[tuple[str, float]]:
        """Top-N sources that talk to ``target`` most, ranked by
        decayed aggregate strength. The inbound counterpart of
        :meth:`top_correspondents`.

        E9 calls this directly when ranking plausible spear-phish
        senders for a given target identity.
        """
        sources: dict[str, list[RelationshipEdge]] = defaultdict(list)
        for idx in self._by_target.get(target_identity_id, []):
            edge = self._edges[idx]
            src = self._source_of[idx]
            sources[src].append(edge)

        ranked: list[tuple[str, float]] = []
        for src_id, edge_list in sources.items():
            decayed = [
                decay_strength(
                    e.strength,
                    e.last_observed,
                    half_life_days=half_life_days,
                    now=now,
                )
                for e in edge_list
            ]
            score = aggregate_strengths(*decayed)
            if score > 0:
                ranked.append((src_id, score))
        ranked.sort(key=lambda t: (-t[1], t[0]))
        return ranked[:n]

    # ── Serialisation ───────────────────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe representation suitable for ``state["relationship_graph"]``.

        Shape::

            {
                "edge_count": int,
                "edges": [
                    {
                        "source_identity_id": str,
                        "target_identity_id": str,
                        "interaction_type": str,
                        "strength": float,
                        "last_observed": str | None,
                        "sources": [str, ...],
                    }, ...
                ],
                "by_source": {identity_id: [edge_index, ...]},
                "by_target": {identity_id: [edge_index, ...]},
            }

        The ``by_source`` / ``by_target`` payloads are included so
        downstream readers (e.g. the report engine) can skip the
        O(N) rebuild ── :meth:`from_dict` ignores them and rebuilds
        from ``edges`` to guarantee invariants hold.
        """
        return {
            "edge_count": len(self._edges),
            "edges": [
                {
                    "source_identity_id": self._source_of[i],
                    **edge.to_dict(),
                }
                for i, edge in enumerate(self._edges)
            ],
            "by_source": {k: list(v) for k, v in self._by_source.items()},
            "by_target": {k: list(v) for k, v in self._by_target.items()},
        }

    @classmethod
    def from_dict(
        cls,
        data: dict[str, Any],
        identity_graph: IdentityGraph | None = None,
    ) -> RelationshipGraph:
        """Rebuild from a :meth:`to_dict` payload.

        Does NOT touch ``identity_graph.related_to`` ── on campaign
        resume, the IdentityGraph is restored from its own
        ``to_dict`` first (which brings back ``related_to`` populated),
        and then this constructor rebuilds the top-level index. Calling
        ``add_edge`` here would double-append onto the already-restored
        per-identity lists.
        """
        graph = cls(identity_graph=identity_graph)
        for entry in data.get("edges", []):
            edge = RelationshipEdge(
                target_identity_id=entry["target_identity_id"],
                interaction_type=entry["interaction_type"],
                strength=float(entry["strength"]),
                last_observed=entry.get("last_observed"),
                sources=list(entry.get("sources", [])),
            )
            graph._add_edge_indexed(entry["source_identity_id"], edge)
        return graph


# ──────────────────────────────────────────────────────────────────────
# Hydration helper
# ──────────────────────────────────────────────────────────────────────


def build_from_identity_graph(
    identity_graph: IdentityGraph,
) -> RelationshipGraph:
    """Build a :class:`RelationshipGraph` from edges already living on
    ``identity.related_to`` lists.

    Use cases:
      - Campaign resume: ``IdentityGraph.from_dict`` restores
        per-identity edges; this helper builds the top-level index
        view without re-mutating the per-identity lists.
      - Tests / fixtures that construct identities with pre-populated
        ``related_to`` lists directly.

    Duplicate edges within a single ``identity.related_to`` (same
    target + interaction_type) are deduplicated during indexing via
    :func:`merge_edges`. After indexing, each identity's
    ``related_to`` list is rewritten with the canonical merged set so
    the two views stay consistent.

    Pure read-then-rewrite on ``related_to``; no network, no LLM.
    """
    graph = RelationshipGraph(identity_graph=identity_graph)
    for identity in identity_graph.all():
        for edge in identity.related_to:
            graph._add_edge_indexed(identity.identity_id, edge)
    # Re-sync each identity.related_to to the canonical (merged) set,
    # so per-identity traversal sees the same edges as the top-level
    # index. Re-uses graph.edges_from rather than walking the index
    # directly so the contract is symmetric with normal usage.
    for identity in identity_graph.all():
        identity.related_to = graph.edges_from(identity.identity_id)
    return graph

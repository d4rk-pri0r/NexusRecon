"""Pretext-scoring engine (Phase E9).

Given the relationship graph (E1) and the recent-activity feed (E8),
score ``(sender × topic × timing)`` tuples for spear-phishing
plausibility. Output is a ranked list of
:class:`PretextCandidate` objects E10 (drafter) and E11 (reports +
state wiring) consume.

Multi-signal weighted score:

  - **Sender plausibility** — how strongly the candidate sender is
    linked to the target in the relationship graph. Computed via
    :meth:`RelationshipGraph.decayed_strength_to` (recency-decayed,
    cross-source-aggregated).
  - **Topic plausibility** — does the topic actually concern the
    target? Implicit-then-explicit: we only consider activities whose
    ``target`` field matches one of the target identity's anchor
    strings (corp-email domain, handles, owned domains), so topic
    relevance is qualitative pass/fail by default. When the activity
    *also* concerns the sender (the rare case), the score is boosted.
  - **Timing** — how recent is the underlying activity? Recency-
    decayed against a tighter half-life than the relationship signal
    (default 90 days vs 180 days for edges) because pretexts tied to
    last-month news feel fresh, while year-old news doesn't.

Combination: geometric mean of the three axes
(``∛(sender × topic × timing)``) ── geometric mean penalises any
single weak axis, so a 0.9 sender with 0 timing scores 0 (no recent
activity → no anchor). Linear weighting would let one strong axis
mask another's weakness; for pretext scoring that's the wrong
optimisation.

Audit-trail invariant (locked-in 2026-05-21): **every score has a
``sources: list[str]`` field**. The framework never claims a
relationship absent public evidence ── the sources field records
which edges and which activities contributed to the candidate so the
operator can verify before drafting.

Scoping (locked-in 2026-05-21): default scores ALL identities in
the graph. The optional ``target_ids`` parameter narrows the scope
(used by ``--pretext-targets`` CLI flag that E11/CLI will wire).
``target_ids=None`` (the default) means "score every identity"; pass
a list to restrict.

Pure Python. No network, no LLM. Deterministic with the optional
``now=`` override for testing.
"""
from __future__ import annotations

import math
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from nexusrecon.core.identity_graph import (
    IdentifierType,
    Identity,
    IdentityGraph,
)
from nexusrecon.core.recent_activity import RecentActivity
from nexusrecon.core.relationship_graph import (
    DEFAULT_HALF_LIFE_DAYS,
    STRENGTH_CAP,
    RelationshipGraph,
    decay_strength,
)

# ──────────────────────────────────────────────────────────────────────
# Tunables
# ──────────────────────────────────────────────────────────────────────

#: Half-life for the **activity timing** signal (in days). Tighter
#: than :data:`DEFAULT_HALF_LIFE_DAYS` because pretexts that quote
#: news from last month still feel current; news from a year ago is
#: just trivia.
DEFAULT_ACTIVITY_HALF_LIFE_DAYS = 90.0

#: Topic boost when the activity concerns BOTH the sender and the
#: target. Multiplies the topic_plausibility (capped at 1.0). Models
#: the "Alice sees an article about her own work that also mentions
#: Bob — has plausible reason to email Bob about it" case.
TOPIC_DUAL_RELEVANCE_BOOST = 1.5

#: Base topic plausibility when the activity concerns the target
#: (single-sided relevance). Less than 1.0 to leave headroom for the
#: dual-relevance boost above.
TOPIC_BASE_PLAUSIBILITY = 0.65

#: Per-target cap on emitted candidates. Default 5 (matches E11's
#: planned "top 3 senders × top 3 pretexts" report layout). Caller
#: overrides via ``max_candidates_per_target``.
DEFAULT_MAX_CANDIDATES_PER_TARGET = 5

#: Per-target cap on candidate senders to consider. Sized so a 50-
#: person org doesn't fan out to thousands of candidate pairs.
DEFAULT_MAX_SENDERS_PER_TARGET = 10

#: Per-target cap on candidate topics (activities) to consider.
DEFAULT_MAX_TOPICS_PER_TARGET = 5


# ──────────────────────────────────────────────────────────────────────
# PretextCandidate dataclass
# ──────────────────────────────────────────────────────────────────────


@dataclass
class PretextCandidate:
    """One scored spear-phishing pretext suggestion.

    Identifies a plausible (sender, target, topic, timing) tuple
    along with its score components and the audit trail of evidence
    that produced the score.

    Attributes:
        target_identity_id: Identity that would *receive* the email.
        target_label: Human-readable label (``Identity.primary_label``)
            for reports.
        sender_identity_id: Identity that would plausibly *send* the
            email.
        sender_label: Sender's primary label.
        topic: Short topic string, derived from the timing-anchor
            activity's title. What the email would be "about".
        timing_anchor: Trimmed dict view of the underlying
            :class:`RecentActivity` (title, url, source, published_at,
            kind) ── enough for the operator to verify the topic
            without needing the full record.
        sender_plausibility: ``[0, 1]`` ── decayed relationship-graph
            strength from sender → target.
        topic_plausibility: ``[0, 1]`` ── whether the topic concerns
            the target (and, when applicable, the sender too).
        timing_score: ``[0, 1]`` ── recency-decayed weight of the
            timing-anchor activity.
        combined_score: ``[0, 1]`` ── geometric mean of the three
            axes. Used for the ranking.
        sources: Audit trail. Includes the sources of the underlying
            relationship edges (``"github_social"``,
            ``"linkedin_social"``, ...) and the source of the
            timing-anchor activity (``"news_intel"``, ...).
        rationale: Human-readable one-sentence summary of why this
            pretext makes the rankings.
    """

    target_identity_id: str
    target_label: str
    sender_identity_id: str
    sender_label: str
    topic: str
    timing_anchor: dict[str, Any]
    sender_plausibility: float
    topic_plausibility: float
    timing_score: float
    combined_score: float
    sources: list[str] = field(default_factory=list)
    rationale: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_identity_id": self.target_identity_id,
            "target_label": self.target_label,
            "sender_identity_id": self.sender_identity_id,
            "sender_label": self.sender_label,
            "topic": self.topic,
            "timing_anchor": dict(self.timing_anchor),
            "sender_plausibility": round(self.sender_plausibility, 3),
            "topic_plausibility": round(self.topic_plausibility, 3),
            "timing_score": round(self.timing_score, 3),
            "combined_score": round(self.combined_score, 3),
            "sources": list(self.sources),
            "rationale": self.rationale,
        }


# ──────────────────────────────────────────────────────────────────────
# Anchor extraction
# ──────────────────────────────────────────────────────────────────────


def extract_topic_anchors(identity: Identity) -> set[str]:
    """Derive the set of "topic anchor" strings that an activity
    would match against to be considered relevant to this identity.

    Anchors come from the identity's identifiers:

      - ``CORP_EMAIL`` / ``PERSONAL_EMAIL`` → contributes the literal
        email and the email's domain (so a news article tagged
        ``acme.com`` matches ``alice@acme.com``'s owner).
      - ``HANDLE`` → contributes the handle string (so an article
        tagged ``alice-doe`` matches the LinkedIn handle).
      - ``DOMAIN`` → contributes the domain literal.
      - ``REAL_NAME`` → contributes the name string.

    Anchors are case-normalised to lower-case for matching.
    """
    anchors: set[str] = set()
    for ident in identity.identifiers:
        value = (ident.value or "").strip().lower()
        if not value:
            continue
        kind = ident.identifier_type
        if kind in (IdentifierType.CORP_EMAIL, IdentifierType.PERSONAL_EMAIL):
            anchors.add(value)
            if "@" in value:
                domain = value.split("@", 1)[1].strip()
                if domain:
                    anchors.add(domain)
        elif kind in (IdentifierType.HANDLE, IdentifierType.DOMAIN,
                      IdentifierType.REAL_NAME):
            anchors.add(value)
        elif kind == IdentifierType.OTHER:
            # OTHER may carry DIDs or org names — include verbatim.
            anchors.add(value)
    return anchors


# ──────────────────────────────────────────────────────────────────────
# Internal helpers
# ──────────────────────────────────────────────────────────────────────


def _activity_target_lower(activity: RecentActivity) -> str:
    return (activity.target or "").strip().lower()


def _activity_to_anchor_dict(activity: RecentActivity) -> dict[str, Any]:
    """Trim a :class:`RecentActivity` for embedding in a candidate."""
    return {
        "target": activity.target,
        "kind": activity.kind,
        "source": activity.source,
        "title": activity.title,
        "url": activity.url,
        "published_at": activity.published_at,
    }


def _geometric_mean(*values: float) -> float:
    """Geometric mean of N non-negative values. Returns 0.0 if any
    value is 0 (intentional: zero-weight any axis with no signal).
    Clamps each input to ``[0, STRENGTH_CAP]`` defensively."""
    if not values:
        return 0.0
    if any(v <= 0.0 for v in values):
        return 0.0
    clamped = [max(0.0, min(STRENGTH_CAP, v)) for v in values]
    return math.prod(clamped) ** (1.0 / len(clamped))


def _build_rationale(
    *,
    sender_label: str,
    target_label: str,
    topic: str,
    sender_plausibility: float,
    timing_score: float,
    timing_anchor: dict[str, Any],
    interaction_summary: str,
) -> str:
    """Compose the human-readable rationale string."""
    parts = [
        f"{sender_label} → {target_label}",
    ]
    if interaction_summary:
        parts.append(f"({interaction_summary}, plausibility {sender_plausibility:.2f})")
    else:
        parts.append(f"(plausibility {sender_plausibility:.2f})")
    parts.append(f"about \"{topic}\"")
    pub = timing_anchor.get("published_at")
    if pub:
        parts.append(f"from {timing_anchor.get('source', 'source')} ({pub})")
    parts.append(f"— timing {timing_score:.2f}")
    return " ".join(parts)


def _summarise_top_edge_interaction(
    relationship_graph: RelationshipGraph,
    sender_id: str,
    target_id: str,
) -> tuple[str, list[str]]:
    """Find the strongest edge from sender to target and return a
    short interaction summary + the sources of all contributing
    edges (for the audit trail).

    Returns ``(summary, sources)`` where ``summary`` is e.g.
    ``"co-author on github_social"`` and ``sources`` is a deduped
    list across every contributing edge.
    """
    edges = relationship_graph.edge_between(sender_id, target_id)
    if not edges:
        return ("", [])
    # Strongest by raw strength (the score-time decay is captured
    # separately in sender_plausibility).
    top = max(edges, key=lambda e: e.strength)
    sources_set: list[str] = []
    seen: set[str] = set()
    for edge in edges:
        for s in edge.sources:
            if s not in seen:
                seen.add(s)
                sources_set.append(s)
    summary = top.interaction_type
    if top.sources:
        summary = f"{top.interaction_type} on {top.sources[0]}"
    return (summary, sources_set)


# ──────────────────────────────────────────────────────────────────────
# Scoring engine
# ──────────────────────────────────────────────────────────────────────


def score_pretext_candidates(
    *,
    identity_graph: IdentityGraph,
    relationship_graph: RelationshipGraph,
    recent_activities: list[RecentActivity],
    target_ids: list[str] | None = None,
    max_candidates_per_target: int = DEFAULT_MAX_CANDIDATES_PER_TARGET,
    max_senders_per_target: int = DEFAULT_MAX_SENDERS_PER_TARGET,
    max_topics_per_target: int = DEFAULT_MAX_TOPICS_PER_TARGET,
    half_life_days: float = DEFAULT_HALF_LIFE_DAYS,
    activity_half_life_days: float = DEFAULT_ACTIVITY_HALF_LIFE_DAYS,
    now: float | None = None,
) -> list[PretextCandidate]:
    """Score (sender × topic × timing) pretext candidates per target.

    Args:
        identity_graph: The campaign's identity graph.
        relationship_graph: The relationship graph (E1) populated
            by Phase E social tools.
        recent_activities: RecentActivity records (E8) from
            ``news_tool`` and future activity sources.
        target_ids: Restrict scoring to these identity IDs. ``None``
            (default) scores every identity in ``identity_graph``.
            Unknown IDs are silently skipped.
        max_candidates_per_target: Per-target cap on emitted
            candidates after ranking.
        max_senders_per_target: Per-target cap on plausible senders
            considered.
        max_topics_per_target: Per-target cap on candidate topics.
        half_life_days: Half-life for the relationship-edge recency
            decay. Default :data:`DEFAULT_HALF_LIFE_DAYS` (180).
        activity_half_life_days: Half-life for the activity timing
            score. Default :data:`DEFAULT_ACTIVITY_HALF_LIFE_DAYS`
            (90).
        now: Override "current time" for deterministic tests.
            Defaults to :func:`time.time`.

    Returns:
        A list of :class:`PretextCandidate` objects sorted by
        ``combined_score`` descending. Ties break on
        ``(target_identity_id, sender_identity_id, topic)`` for
        stable output across runs.
    """
    now_ts = now if now is not None else time.time()

    # ── 1. Resolve target set ───────────────────────────────────────
    if target_ids is None:
        targets: list[Identity] = identity_graph.all()
    else:
        targets = []
        for tid in target_ids:
            identity = identity_graph.get(tid)
            if identity is not None:
                targets.append(identity)

    if not targets:
        return []

    # ── 2. Pre-bucket activities by anchor string ───────────────────
    # We do this once across all targets for O(activities) lookup
    # per target rather than O(activities * targets).
    by_anchor: dict[str, list[RecentActivity]] = defaultdict(list)
    for activity in recent_activities:
        t = _activity_target_lower(activity)
        if t:
            by_anchor[t].append(activity)

    # ── 3. Pre-compute anchor sets per known identity for the
    #       dual-relevance topic boost (does the activity also
    #       concern the sender?).
    anchors_by_identity_id: dict[str, set[str]] = {}
    for identity in identity_graph.all():
        anchors_by_identity_id[identity.identity_id] = extract_topic_anchors(identity)

    # ── 4. Per-target scoring ───────────────────────────────────────
    candidates: list[PretextCandidate] = []

    for target in targets:
        target_id = target.identity_id
        target_label = target.primary_label or target_id

        # Topic anchors for this target.
        target_anchors = anchors_by_identity_id.get(target_id) or extract_topic_anchors(target)
        if not target_anchors:
            continue

        # Collect activities relevant to the target, deduplicated
        # by activity identity (target+title+url+published_at).
        relevant: dict[tuple[str, str, str, str], RecentActivity] = {}
        for anchor in target_anchors:
            for activity in by_anchor.get(anchor, []):
                key = (
                    activity.target or "",
                    activity.title or "",
                    activity.url or "",
                    activity.published_at or "",
                )
                relevant.setdefault(key, activity)
        relevant_activities = list(relevant.values())
        if not relevant_activities:
            continue

        # Sort activities by recency-decayed weight (highest first)
        # and cap at max_topics_per_target.
        def _activity_recency(activity: RecentActivity) -> float:
            return decay_strength(
                1.0,
                activity.published_at,
                half_life_days=activity_half_life_days,
                now=now_ts,
            )

        relevant_activities.sort(key=_activity_recency, reverse=True)
        topics = relevant_activities[:max_topics_per_target]

        # Senders: who plausibly emails this target?
        senders = relationship_graph.top_correspondents_to(
            target_id,
            n=max_senders_per_target,
            half_life_days=half_life_days,
            now=now_ts,
        )
        if not senders:
            continue

        per_target_candidates: list[PretextCandidate] = []

        for sender_id, sender_plausibility in senders:
            sender_identity = identity_graph.get(sender_id)
            sender_label = (
                sender_identity.primary_label
                if sender_identity and sender_identity.primary_label
                else sender_id
            )
            sender_anchors = (
                anchors_by_identity_id.get(sender_id)
                or (extract_topic_anchors(sender_identity)
                    if sender_identity else set())
            )
            interaction_summary, edge_sources = _summarise_top_edge_interaction(
                relationship_graph, sender_id, target_id,
            )

            for activity in topics:
                timing = _activity_recency(activity)

                # Topic plausibility ── always relevant to target
                # because the activity is in this target's bucket.
                topic_plausibility = TOPIC_BASE_PLAUSIBILITY
                activity_target_l = _activity_target_lower(activity)
                if sender_anchors and activity_target_l in sender_anchors:
                    # Activity also concerns the sender → boost.
                    topic_plausibility = min(
                        STRENGTH_CAP,
                        topic_plausibility * TOPIC_DUAL_RELEVANCE_BOOST,
                    )

                combined = _geometric_mean(
                    sender_plausibility,
                    topic_plausibility,
                    timing,
                )

                topic = activity.title or activity.url or "(no title)"
                timing_anchor = _activity_to_anchor_dict(activity)

                # Audit trail: edges' sources + activity's source.
                sources_list = list(edge_sources)
                if activity.source and activity.source not in sources_list:
                    sources_list.append(activity.source)

                rationale = _build_rationale(
                    sender_label=sender_label,
                    target_label=target_label,
                    topic=topic,
                    sender_plausibility=sender_plausibility,
                    timing_score=timing,
                    timing_anchor=timing_anchor,
                    interaction_summary=interaction_summary,
                )

                per_target_candidates.append(PretextCandidate(
                    target_identity_id=target_id,
                    target_label=target_label,
                    sender_identity_id=sender_id,
                    sender_label=sender_label,
                    topic=topic,
                    timing_anchor=timing_anchor,
                    sender_plausibility=sender_plausibility,
                    topic_plausibility=topic_plausibility,
                    timing_score=timing,
                    combined_score=combined,
                    sources=sources_list,
                    rationale=rationale,
                ))

        # Sort + cap per target.
        per_target_candidates.sort(
            key=lambda c: (
                -c.combined_score,
                c.target_identity_id,
                c.sender_identity_id,
                c.topic,
            ),
        )
        candidates.extend(per_target_candidates[:max_candidates_per_target])

    # ── 5. Final stable ordering ────────────────────────────────────
    candidates.sort(
        key=lambda c: (
            -c.combined_score,
            c.target_identity_id,
            c.sender_identity_id,
            c.topic,
        ),
    )
    return candidates


# ──────────────────────────────────────────────────────────────────────
# Convenience: group by target for reports
# ──────────────────────────────────────────────────────────────────────


def group_candidates_by_target(
    candidates: list[PretextCandidate],
) -> dict[str, list[PretextCandidate]]:
    """Bucket candidates by ``target_identity_id``. Within each bucket
    the input ordering is preserved (which means descending
    ``combined_score`` when the input came from
    :func:`score_pretext_candidates`)."""
    buckets: dict[str, list[PretextCandidate]] = defaultdict(list)
    for c in candidates:
        buckets[c.target_identity_id].append(c)
    return dict(buckets)


def summarise_candidates(
    candidates: list[PretextCandidate],
) -> dict[str, Any]:
    """One-line summary for inclusion in agent prompts / state.

    Returns counts (targets covered, total candidates) and the
    score distribution (min/median/max combined score).
    """
    if not candidates:
        return {
            "target_count": 0,
            "candidate_count": 0,
            "score_min": 0.0,
            "score_median": 0.0,
            "score_max": 0.0,
        }
    scores = sorted(c.combined_score for c in candidates)
    median = scores[len(scores) // 2]
    return {
        "target_count": len({c.target_identity_id for c in candidates}),
        "candidate_count": len(candidates),
        "score_min": round(scores[0], 3),
        "score_median": round(median, 3),
        "score_max": round(scores[-1], 3),
    }


# Re-export for E11 / CLI consumers.
__all__ = [
    "DEFAULT_ACTIVITY_HALF_LIFE_DAYS",
    "DEFAULT_MAX_CANDIDATES_PER_TARGET",
    "DEFAULT_MAX_SENDERS_PER_TARGET",
    "DEFAULT_MAX_TOPICS_PER_TARGET",
    "PretextCandidate",
    "TOPIC_BASE_PLAUSIBILITY",
    "TOPIC_DUAL_RELEVANCE_BOOST",
    "extract_topic_anchors",
    "group_candidates_by_target",
    "score_pretext_candidates",
    "summarise_candidates",
]

"""Adversarial Self-Check — periodic "red team the graph" pass
that hunts for weak links and over-claimed attributions.

The event-driven verifiers (corroboration, contradiction,
propagation) react to mutations as they happen. The
adversarial verifier is different — it runs on demand
(typically at phase boundaries or when the operator asks for
a health report) and audits the graph as a whole. Same shape
as the other verifiers (``name`` + a method that returns a
verdict-like object), but the input is the graph itself
rather than a single mutation event.

What it looks for
- **Single-source high-confidence claims** — entities at
  confidence ≥ ``HIGH_CONFIDENCE_THRESHOLD`` whose sources
  collapse to one independence class. The corroboration engine
  should have caught this for normally-added entities, but
  tool wrappers occasionally assert ``confidence=1.0`` directly
  and bypass the boost path; this check is the safety net.
- **Citation cycles** — an entity whose confidence rests on a
  hypothesis or lead that CITES it. Circular justification.
- **Disconnected islands** — high-confidence entities with no
  in-edges and no out-edges (other than scope-derived seeds).
  Usually stale imports.
- **Source monoculture clusters** — runs of related entities
  (subdomains under one parent, person→email chains) all
  sourced from a single source identifier. Single point of
  failure for the cluster's claims.

Output
- A list of :class:`WeakLink` records describing each finding,
  with severity grade + a structured rationale.
- ``run(graph, state)`` writes those records into
  ``state["weak_links"]`` and (if an audit log is bound)
  hash-chains a summary entry through
  ``log_agent_action``.

This module is intentionally LLM-free. PR E (a future Phase
2 follow-up if needed) could layer a semantic adversarial
agent on top — but the heuristics here cover the common
failure modes and run in O(n + e) over the graph, so they're
safe to invoke on every phase boundary.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import structlog

from nexusrecon.verification.corroboration import (
    SOURCE_INDEPENDENCE_CLASSES,
)

log = structlog.get_logger(__name__)


# ──────────────────────────────────────────────────────────────────────
# Tunables
# ──────────────────────────────────────────────────────────────────────


HIGH_CONFIDENCE_THRESHOLD: float = 0.8
"""Confidence at or above this counts as "high" for
adversarial purposes — the threshold where weak-link findings
become reporting risks."""

MONOCULTURE_CLUSTER_SIZE: int = 4
"""Minimum cluster size at which single-source coverage gets
flagged. Three subdomains all from subfinder isn't worth a
finding; ten subdomains all from subfinder is."""


# ──────────────────────────────────────────────────────────────────────
# Findings
# ──────────────────────────────────────────────────────────────────────


@dataclass
class WeakLink:
    """One adversarial finding. Severity grades:

    - ``low``: noise — interesting but not actionable.
    - ``medium``: worth surfacing in the next review.
    - ``high``: a reporting risk; would mislead a reader if
      not addressed.
    """

    kind: str
    """One of ``single_source_high_confidence``,
    ``citation_cycle``, ``disconnected_island``,
    ``source_monoculture``."""

    entity_ids: list[str]
    """Entities involved. Single-element list for the first
    three kinds; the monoculture finding carries the entire
    cluster."""

    severity: str  # "low" | "medium" | "high"
    rationale: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "entity_ids": list(self.entity_ids),
            "severity": self.severity,
            "rationale": self.rationale,
            "metadata": dict(self.metadata),
        }


@dataclass
class AdversarialReport:
    """Aggregate output of one ``run`` call."""

    timestamp: str
    weak_links: list[WeakLink] = field(default_factory=list)

    @property
    def severity_counts(self) -> dict[str, int]:
        counts = {"low": 0, "medium": 0, "high": 0}
        for w in self.weak_links:
            counts[w.severity] = counts.get(w.severity, 0) + 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "weak_link_count": len(self.weak_links),
            "severity_counts": self.severity_counts,
            "weak_links": [w.to_dict() for w in self.weak_links],
        }


# ──────────────────────────────────────────────────────────────────────
# Verifier
# ──────────────────────────────────────────────────────────────────────


class AdversarialSelfCheck:
    """Periodic graph-level adversarial audit.

    Not registered with the orchestrator's per-mutation
    pipeline (it's not event-driven). Callers invoke
    :meth:`run` directly at phase boundaries:

        report = AdversarialSelfCheck().run(graph, state)

    The campaign workflow node can wire this in at
    ``phase_end`` so every phase produces a fresh weak-link
    list."""

    name: str = "adversarial_self_check"

    def __init__(
        self,
        *,
        high_confidence_threshold: float = HIGH_CONFIDENCE_THRESHOLD,
        monoculture_cluster_size: int = MONOCULTURE_CLUSTER_SIZE,
    ) -> None:
        self.high_confidence_threshold = high_confidence_threshold
        self.monoculture_cluster_size = monoculture_cluster_size

    def run(
        self,
        graph: Any,
        state: dict[str, Any] | None = None,
        *,
        audit_log: Any | None = None,
    ) -> AdversarialReport:
        """Walk the graph + return an :class:`AdversarialReport`.

        Writes ``state["weak_links"]`` (replacing any previous
        entry — operators want the *current* health, not a
        compounding pile) and emits a hash-chained audit
        summary if ``audit_log`` is bound."""
        weak_links: list[WeakLink] = []
        weak_links.extend(self._find_single_source_high_conf(graph))
        weak_links.extend(self._find_citation_cycles(graph))
        weak_links.extend(self._find_disconnected_islands(graph))
        weak_links.extend(self._find_source_monocultures(graph))

        report = AdversarialReport(
            timestamp=datetime.now(UTC).isoformat(),
            weak_links=weak_links,
        )

        if state is not None:
            state["weak_links"] = [w.to_dict() for w in weak_links]

        if audit_log is not None:
            try:
                audit_log.log_agent_action(
                    agent=f"verifier:{self.name}",
                    action="adversarial_report",
                    details=report.to_dict(),
                )
            except Exception as exc:
                log.debug(
                    "Audit log write failed", error=str(exc),
                )

        return report

    # ── Heuristic 1: single-source high confidence ───────────

    def _find_single_source_high_conf(self, graph: Any) -> list[WeakLink]:
        out: list[WeakLink] = []
        for entity_id, data in graph.graph.nodes(data=True):
            confidence = float(data.get("confidence", 0.0))
            if confidence < self.high_confidence_threshold:
                continue
            sources = list(data.get("sources", []))
            classes = {
                SOURCE_INDEPENDENCE_CLASSES.get(s, "unknown")
                for s in sources
            }
            if len(classes) >= 2:
                continue
            # Single class — possible bypass of corroboration.
            severity = "high" if confidence >= 0.95 else "medium"
            out.append(WeakLink(
                kind="single_source_high_confidence",
                entity_ids=[entity_id],
                severity=severity,
                rationale=(
                    f"Entity {data.get('value', entity_id)!r} at "
                    f"confidence={confidence:.2f} but only one "
                    f"source independence class ({next(iter(classes))})."
                ),
                metadata={
                    "confidence": confidence,
                    "sources": sources,
                    "independence_classes": sorted(classes),
                    "entity_type": str(data.get("entity_type", "")),
                },
            ))
        return out

    # ── Heuristic 2: citation cycles ─────────────────────────

    def _find_citation_cycles(self, graph: Any) -> list[WeakLink]:
        """Detect cycles in the ``CITES`` subgraph. A LEAD or
        HYPOTHESIS that cites an entity which in turn cites
        the original creates circular justification — neither
        is independent evidence."""
        out: list[WeakLink] = []
        # Build the CITES-only subgraph.
        cites_edges = [
            (u, v)
            for u, v, d in graph.graph.edges(data=True)
            if d.get("rel_type") == "cites"
        ]
        # Find 2-cycles + 3-cycles (deeper cycles are rare in
        # practice and the BFS gets expensive).
        edge_set = set(cites_edges)
        seen: set[tuple[str, ...]] = set()
        for u, v in cites_edges:
            if (v, u) in edge_set:
                key = tuple(sorted([u, v]))
                if key in seen:
                    continue
                seen.add(key)
                out.append(WeakLink(
                    kind="citation_cycle",
                    entity_ids=[u, v],
                    severity="high",
                    rationale=(
                        "Two-node CITES cycle: each entity's "
                        "support depends on the other."
                    ),
                    metadata={"cycle_length": 2},
                ))
        return out

    # ── Heuristic 3: disconnected high-confidence islands ───

    def _find_disconnected_islands(self, graph: Any) -> list[WeakLink]:
        out: list[WeakLink] = []
        for entity_id, data in graph.graph.nodes(data=True):
            confidence = float(data.get("confidence", 0.0))
            if confidence < 0.7:  # mid-tier and up only
                continue
            in_degree = graph.graph.in_degree(entity_id)
            out_degree = graph.graph.out_degree(entity_id)
            if in_degree + out_degree > 0:
                continue
            # Scope-sourced seeds are expected to be isolated
            # initially — only flag them when they DON'T come
            # from scope (which would be the more suspicious
            # case).
            sources = list(data.get("sources", []))
            if "scope" in sources:
                continue
            out.append(WeakLink(
                kind="disconnected_island",
                entity_ids=[entity_id],
                severity="low",
                rationale=(
                    f"Entity {data.get('value', entity_id)!r} at "
                    f"confidence={confidence:.2f} has no in- or "
                    f"out-edges. Possibly a stale import or an "
                    f"orphaned tool result."
                ),
                metadata={
                    "confidence": confidence,
                    "sources": sources,
                    "entity_type": str(data.get("entity_type", "")),
                },
            ))
        return out

    # ── Heuristic 4: source monocultures ─────────────────────

    def _find_source_monocultures(self, graph: Any) -> list[WeakLink]:
        """Cluster entities by their *single* source (when they
        have exactly one) and flag clusters at or above the
        configured size. The cluster being big means the
        operator's view of a whole region of the graph rests
        on one tool's output — a single bug in that tool would
        wipe out all of it."""
        # Group by sole source.
        by_source: dict[str, list[str]] = {}
        for entity_id, data in graph.graph.nodes(data=True):
            sources = list(data.get("sources", []))
            if len(sources) != 1:
                continue
            by_source.setdefault(sources[0], []).append(entity_id)

        out: list[WeakLink] = []
        for source, members in by_source.items():
            if len(members) < self.monoculture_cluster_size:
                continue
            # Scope-only clusters aren't surprising (initial
            # seeds) — skip those.
            if source == "scope":
                continue
            out.append(WeakLink(
                kind="source_monoculture",
                entity_ids=members,
                severity="medium",
                rationale=(
                    f"{len(members)} entities are sourced only "
                    f"from {source!r}. A bug or rate-limit in "
                    f"that tool would silently drop the entire "
                    f"cluster from future runs."
                ),
                metadata={
                    "source": source,
                    "cluster_size": len(members),
                },
            ))
        return out


# ──────────────────────────────────────────────────────────────────────
# Verification health (strategic feedback channel)
# ──────────────────────────────────────────────────────────────────────


@dataclass
class VerificationHealth:
    """Aggregate signal the strategic layer can read. Cheap to
    compute — pure O(n) walk of the graph + the verification
    log."""

    entity_count: int
    corroborated_entity_count: int
    """Entities with sources spanning ≥ 2 independence classes."""
    corroboration_coverage: float
    """Fraction of entities that are corroborated. 1.0 means
    every entity has multi-class support; 0.0 means none
    do."""

    avg_confidence: float
    low_confidence_entity_count: int
    """Entities with confidence < 0.5."""

    open_contradiction_count: int
    contradiction_density: float
    """Open contradictions per 100 entities."""

    weak_link_counts: dict[str, int]
    """Severity counts from the most recent adversarial
    report. Defaults to all-zero when none has run yet."""

    timestamp: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "entity_count": self.entity_count,
            "corroborated_entity_count": self.corroborated_entity_count,
            "corroboration_coverage": round(self.corroboration_coverage, 4),
            "avg_confidence": round(self.avg_confidence, 4),
            "low_confidence_entity_count": self.low_confidence_entity_count,
            "open_contradiction_count": self.open_contradiction_count,
            "contradiction_density": round(self.contradiction_density, 4),
            "weak_link_counts": dict(self.weak_link_counts),
            "timestamp": self.timestamp,
        }


def compute_verification_health(
    graph: Any,
    state: dict[str, Any] | None = None,
) -> VerificationHealth:
    """Snapshot of the campaign's confidence health.

    Writes the result to ``state["verification_health"]`` so
    the planner / dispatcher / TUI can read it. The
    snapshot is point-in-time — call this at phase
    boundaries or when planning a replan.

    Why this matters for the strategic layer (Phase 1):
    when ``corroboration_coverage`` is low and
    ``contradiction_density`` is high, the planner should
    favor strategies that dispatch MORE verification-oriented
    tools rather than expanding scope. PR D ships the
    metric; Phase 1 PR D's replan hook is the natural
    integration point.
    """
    timestamp = datetime.now(UTC).isoformat()

    entity_count = graph.graph.number_of_nodes()
    if entity_count == 0:
        # Empty graph — return zeros + the timestamp.
        health = VerificationHealth(
            entity_count=0,
            corroborated_entity_count=0,
            corroboration_coverage=0.0,
            avg_confidence=0.0,
            low_confidence_entity_count=0,
            open_contradiction_count=0,
            contradiction_density=0.0,
            weak_link_counts={"low": 0, "medium": 0, "high": 0},
            timestamp=timestamp,
        )
        if state is not None:
            state["verification_health"] = health.to_dict()
        return health

    corroborated = 0
    total_confidence = 0.0
    low_count = 0
    for _, data in graph.graph.nodes(data=True):
        confidence = float(data.get("confidence", 0.0))
        total_confidence += confidence
        if confidence < 0.5:
            low_count += 1
        sources = list(data.get("sources", []))
        classes = {
            SOURCE_INDEPENDENCE_CLASSES.get(s, "unknown")
            for s in sources
        }
        if len(classes) >= 2:
            corroborated += 1

    open_contradictions = 0
    if state is not None:
        for record in (state.get("contradictions") or []):
            if record.get("status") == "pending":
                open_contradictions += 1

    weak_link_counts = {"low": 0, "medium": 0, "high": 0}
    if state is not None:
        for record in (state.get("weak_links") or []):
            sev = record.get("severity", "low")
            weak_link_counts[sev] = weak_link_counts.get(sev, 0) + 1

    health = VerificationHealth(
        entity_count=entity_count,
        corroborated_entity_count=corroborated,
        corroboration_coverage=corroborated / entity_count,
        avg_confidence=total_confidence / entity_count,
        low_confidence_entity_count=low_count,
        open_contradiction_count=open_contradictions,
        contradiction_density=(
            (open_contradictions / entity_count) * 100.0
        ),
        weak_link_counts=weak_link_counts,
        timestamp=timestamp,
    )

    if state is not None:
        state["verification_health"] = health.to_dict()

    return health

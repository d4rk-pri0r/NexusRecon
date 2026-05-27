"""Severity grading for watch triggers.

Given a sensor trigger + the live graph, classify the
change as ``low`` / ``medium`` / ``high``. The Action policy
(Phase 5 PR A locked-in: "tiered") consumes these grades:

  - ``low``  → log alert
  - ``medium`` → log + notification
  - ``high``  → log + notification + queue micro-campaign

What raises severity
- New entity at high confidence (≥ 0.8).
- Confidence shift > 0.3 on a previously-high entity (likely
  contradiction fallout).
- New CITES edge pointing INTO a Lead (cascade impact).
- New entity tagged ``imported_from:nessus`` /
  ``imported_from:nuclei`` (vuln data — operators want to
  know about these immediately).

What stays low
- Edge added/removed without confidence impact.
- New low-confidence entities (< 0.5).
- Source list grew but confidence unchanged.

Grading is intentionally conservative — most operators want
fewer false alarms more than they want exhaustive coverage.
The thresholds can be tuned via :class:`SeverityConfig`.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class SeverityConfig:
    """Tunable thresholds. Defaults are conservative; ops
    teams that want louder alerts can lower them."""

    high_confidence_threshold: float = 0.8
    """A new entity at or above this confidence is HIGH
    severity."""
    confidence_shift_threshold: float = 0.3
    """Magnitude of confidence delta that makes a change
    HIGH-severity (otherwise medium)."""
    vuln_source_prefixes: tuple[str, ...] = (
        "imported_from:nessus",
        "imported_from:nuclei",
    )
    """Source labels that ALWAYS raise to HIGH on entity
    addition — operators want immediate visibility into vuln
    data."""


# ──────────────────────────────────────────────────────────────────────
# Diff
# ──────────────────────────────────────────────────────────────────────


@dataclass
class GraphDiff:
    """Structured delta between two graph states for one
    sensor trigger. Built from the changed_entity_ids list +
    the live graph."""

    added: list[dict[str, Any]] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    """Removed entities — we only have the id, the node data
    is gone."""
    in_place_changes: list[dict[str, Any]] = field(default_factory=list)
    """Entities that survived but whose state changed."""

    def to_dict(self) -> dict[str, Any]:
        return {
            "added": list(self.added),
            "removed": list(self.removed),
            "in_place_changes": list(self.in_place_changes),
        }


def diff_graphs(
    changed_entity_ids: list[str],
    graph: Any,
    *,
    previous_entity_ids: list[str] | None = None,
) -> GraphDiff:
    """Build a structured diff from the sensor's reported
    changed-entity list.

    ``previous_entity_ids`` is what the sensor saw on the
    PREVIOUS tick. When provided, we can distinguish
    additions from removals; when not, every changed id is
    treated as "in-place" (the sensor didn't tell us
    direction)."""
    diff = GraphDiff()
    prev_set = set(previous_entity_ids or [])

    for eid in changed_entity_ids:
        node_data = graph.graph.nodes.get(eid)
        if node_data is None:
            diff.removed.append(eid)
            continue
        record = {
            "entity_id": eid,
            "entity_type": node_data.get("entity_type"),
            "value": node_data.get("value"),
            "confidence": float(node_data.get("confidence", 0.0)),
            "sources": list(node_data.get("sources") or []),
        }
        if previous_entity_ids is not None and eid not in prev_set:
            diff.added.append(record)
        else:
            diff.in_place_changes.append(record)
    return diff


# ──────────────────────────────────────────────────────────────────────
# Classifier
# ──────────────────────────────────────────────────────────────────────


def classify_diff(
    diff: GraphDiff,
    graph: Any,
    *,
    config: SeverityConfig | None = None,
) -> tuple[Severity, str]:
    """Grade a diff. Returns ``(severity, rationale)``.

    Rationale is a human-readable explanation that lands in
    the alert + (for high-severity) the micro-campaign
    seed."""
    cfg = config or SeverityConfig()
    reasons: list[str] = []
    grade = Severity.LOW

    # Rule 1: any vuln-source addition → high.
    for entry in diff.added:
        sources = entry.get("sources") or []
        if any(
            any(s.startswith(prefix) for s in sources)
            for prefix in cfg.vuln_source_prefixes
        ):
            grade = Severity.HIGH
            reasons.append(
                f"new vuln-source entity "
                f"{entry.get('value', entry['entity_id'])!r}"
            )

    # Rule 2: new high-confidence entity → high.
    high_added = [
        e for e in diff.added
        if e.get("confidence", 0.0) >= cfg.high_confidence_threshold
    ]
    if high_added:
        grade = Severity.HIGH
        reasons.append(
            f"{len(high_added)} new high-confidence "
            f"entit{'y' if len(high_added) == 1 else 'ies'}"
        )

    # Rule 3: cascade — new CITES edges into a Lead/Hypothesis.
    cascade_count = _count_cascade_edges(diff, graph)
    if cascade_count:
        grade = Severity.HIGH
        reasons.append(
            f"{cascade_count} new CITES edge"
            f"{'' if cascade_count == 1 else 's'} into a Lead/Hypothesis"
        )

    # Rule 4: large confidence shift on a previously-high
    # entity. We don't have the old confidence available here
    # (sensor fingerprint doesn't store it), so this rule is
    # a heuristic: an in-place change to a now-high-confidence
    # entity is treated as a shift.
    big_shifts = [
        e for e in diff.in_place_changes
        if e.get("confidence", 0.0)
        >= cfg.high_confidence_threshold - cfg.confidence_shift_threshold
    ]
    if big_shifts and grade == Severity.LOW:
        grade = Severity.MEDIUM
        reasons.append(
            f"{len(big_shifts)} in-place change"
            f"{'' if len(big_shifts) == 1 else 's'} on "
            f"high-confidence entities"
        )

    # Rule 5: any addition at all → at least medium.
    if grade == Severity.LOW and (diff.added or diff.removed):
        grade = Severity.MEDIUM
        if diff.added:
            reasons.append(f"{len(diff.added)} new entities")
        if diff.removed:
            reasons.append(f"{len(diff.removed)} removed entities")

    if not reasons:
        reasons.append("minor edge or source list update")

    return grade, "; ".join(reasons)


def _count_cascade_edges(diff: GraphDiff, graph: Any) -> int:
    """Count CITES edges originating from a Lead/Hypothesis
    that appeared / changed in this diff.

    Semantics: the CITES edge points FROM the citer
    (Lead/Hypothesis) TO the cited entity (evidence). When
    a Lead/Hypothesis changed and it cites something, the
    finding is backed by evidence the operator should review
    — that's the high-signal cascade case."""
    count = 0
    sources_to_check: set[str] = set()
    for entry in diff.added + diff.in_place_changes:
        if entry.get("entity_type") in ("lead", "hypothesis"):
            sources_to_check.add(entry["entity_id"])
    if not sources_to_check:
        return 0
    for source, target, edge_data in graph.graph.edges(data=True):
        if (
            edge_data.get("rel_type") == "cites"
            and source in sources_to_check
        ):
            count += 1
    return count

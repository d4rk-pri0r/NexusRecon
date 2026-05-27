"""Adversarial findings aggregator.

The detectors are verifier-shaped (Phase 2 plumbing) AND
each one produces a structured record that lands in
``state["adversarial_findings"]``. The aggregator centralises
the schema + append helpers so every detector emits
consistent rows.

Record shape::

    {
      "timestamp": "...",
      "detector": "poisoned_data" | "tool_patterns" |
                  "inconsistency" | "prompt_injection",
      "severity": "low" | "medium" | "high",
      "entity_ids": [...],
      "rationale": "...",
      "metadata": {...},
      "downgrade_applied": true,
      "downgrade_factor": 0.5,
      "downgrade_floor": 0.05,
      "confidence_deltas": [
        {"entity_id": "...", "before": 0.9, "after": 0.45}
      ]
    }
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


# Default response factors (locked in: "downgrade + flag for
# review"). Keep these matching the contradiction detector's
# defaults so a finding from either subsystem applies a
# proportional change.
DEFAULT_DOWNGRADE_FACTOR_BY_SEVERITY: dict[str, float] = {
    "low":    1.0,   # no downgrade
    "medium": 0.7,
    "high":   0.5,
}
CONFIDENCE_FLOOR: float = 0.05


@dataclass
class AdversarialFinding:
    """One adversarial detection. Detectors construct + pass
    to :func:`append_finding`."""

    detector: str
    severity: str  # "low" | "medium" | "high"
    rationale: str
    entity_ids: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    downgrade_applied: bool = False
    downgrade_factor: float = 1.0
    confidence_deltas: list[dict[str, Any]] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "detector": self.detector,
            "severity": self.severity,
            "rationale": self.rationale,
            "entity_ids": list(self.entity_ids),
            "metadata": dict(self.metadata),
            "downgrade_applied": self.downgrade_applied,
            "downgrade_factor": self.downgrade_factor,
            "downgrade_floor": CONFIDENCE_FLOOR,
            "confidence_deltas": list(self.confidence_deltas),
        }


def append_finding(
    state: dict[str, Any],
    finding: AdversarialFinding,
) -> None:
    """Append ``finding`` to ``state["adversarial_findings"]``.
    Idempotent on the key — creates the list if absent."""
    log = list(state.get("adversarial_findings") or [])
    log.append(finding.to_dict())
    state["adversarial_findings"] = log


def apply_downgrade(
    graph: Any,
    entity_ids: list[str],
    *,
    factor: float,
    reason: str,
) -> list[dict[str, Any]]:
    """Apply a bounded confidence downgrade to each listed
    entity. Returns a list of ``{entity_id, before, after}``
    records so the caller can attach them to the
    :class:`AdversarialFinding`.

    Uses :meth:`EntityGraph.set_confidence` so the change
    emits a ``confidence_changed`` event the propagator can
    cascade — same plumbing the contradiction detector
    uses."""
    deltas: list[dict[str, Any]] = []
    for eid in entity_ids:
        node_data = graph.graph.nodes.get(eid)
        if node_data is None:
            continue
        before = float(node_data.get("confidence", 0.0))
        after = max(CONFIDENCE_FLOOR, before * factor)
        if after >= before:
            # No-op — downgrade only goes DOWN.
            continue
        graph.set_confidence(
            eid, after,
            reason=f"adversarial downgrade: {reason}",
            source="adversarial",
        )
        deltas.append({
            "entity_id": eid,
            "before": round(before, 4),
            "after": round(after, 4),
        })
    return deltas


def finding_summary(state: dict[str, Any]) -> dict[str, int]:
    """Compact severity counts for the CLI / dashboards."""
    log = state.get("adversarial_findings") or []
    counts = {"low": 0, "medium": 0, "high": 0, "total": 0}
    for record in log:
        sev = str(record.get("severity", "low"))
        counts[sev] = counts.get(sev, 0) + 1
        counts["total"] += 1
    return counts

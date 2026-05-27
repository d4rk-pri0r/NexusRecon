"""Confidence Propagation — when an entity is downgraded,
walk the graph and adjust downstream findings that rely on it.

Motivation: when the contradiction detector downgrades a
``CloudAsset`` from 0.9 to 0.45, a ``LeadEntity`` that
``CITES`` the asset stays at its old confidence — the report
shows a high-confidence finding pointing to a now-doubted
underlying claim. The propagator closes that loop.

How it walks
- Listens to ``confidence_changed`` events emitted by
  :meth:`EntityGraph.set_confidence`.
- Only acts on DOWNGRADES (delta < 0). Upgrades aren't
  propagated automatically — corroboration is the explicit
  upgrade path; propagating upgrades would risk runaway
  positive feedback loops.
- Walks INCOMING edges of the downgraded entity (i.e.
  predecessors — the entities that point to the downgraded
  one), following only relationship types in
  ``PROPAGATING_REL_TYPES``. ``CITES``, ``BELONGS_TO``,
  ``PART_OF``, ``HOSTED_ON``, ``REGISTERED_BY`` carry
  reliance semantics — a predecessor pointing to a downgraded
  node has reason to lose confidence.
- Caps walk depth at ``max_depth`` (default 3) to prevent
  runaway cascades on densely-connected graphs.

Decay formula
- Each level scales the impact by ``decay`` (default 0.5).
- For a predecessor at depth ``d``:
    delta_pct = (old_upstream - new_upstream) / old_upstream
    impact = delta_pct * (decay^d)
    predecessor_new = max(floor, predecessor_old * (1 - impact))

So a 50% upstream downgrade becomes a 25% downgrade at depth
1, 12.5% at depth 2, 6.25% at depth 3 — diminishing impact
that mirrors how trust really attenuates with chain length.

Cycle protection
- Per-event ``visited`` set keyed on entity_id. A node is
  visited at most once per propagation cycle. This is the
  primary defense against cyclic graphs.
- ``source="propagation"`` on the originating event means
  the propagator's own ``set_confidence`` calls emit further
  ``confidence_changed`` events — but those carry the same
  source tag, so the propagator's ``verify`` SHORT-CIRCUITS
  on events with ``source="propagation"`` to prevent
  recursive re-entry.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

log = structlog.get_logger(__name__)


# ──────────────────────────────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────────────────────────────


#: Relationship types whose semantics imply reliance:
#: if A --rel--> B and B loses confidence, A's confidence in
#: whatever it's claiming should drop too. Membership here is
#: deliberately narrow — over-inclusion produces too-eager
#: cascades that confuse operators.
PROPAGATING_REL_TYPES: frozenset[str] = frozenset({
    "cites",          # Lead/Hypothesis CITES the evidence
    "belongs_to",     # Subdomain BELONGS_TO domain
    "part_of",
    "hosted_on",
    "registered_by",
    "blocks",         # an OPEN_QUESTION BLOCKS a downstream LEAD
})


PROPAGATION_FLOOR: float = 0.05
"""Lower bound for propagated confidences. Same floor as the
contradiction detector — keeps cascades from manufacturing
negative certainty."""

PROPAGATION_DECAY: float = 0.5
"""Per-depth dampening of the propagated impact."""

PROPAGATION_MAX_DEPTH: int = 3
"""Hard cap on traversal depth. Three hops is the natural
upper bound — beyond that the dampening makes the impact
negligible and the audit log noise outweighs the signal."""


# ──────────────────────────────────────────────────────────────────────
# Verdict
# ──────────────────────────────────────────────────────────────────────


@dataclass
class PropagationStep:
    """One propagation hop. The propagator's verdict carries a
    list of these so reviewers can see exactly which downstream
    entities were affected."""

    entity_id: str
    entity_type: str
    rel_type: str
    depth: int
    confidence_before: float
    confidence_after: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "entity_type": self.entity_type,
            "rel_type": self.rel_type,
            "depth": self.depth,
            "confidence_before": round(self.confidence_before, 4),
            "confidence_after": round(self.confidence_after, 4),
            "delta": round(self.confidence_after - self.confidence_before, 4),
        }


@dataclass
class PropagationVerdict:
    """The propagator's verdict for one ``confidence_changed``
    event. Returned to the orchestrator for the audit log."""

    origin_entity_id: str
    origin_delta_pct: float
    """Fractional downgrade applied upstream (positive number
    even though the underlying delta is negative). 0.5 means
    "halved upstream"."""

    steps: list[PropagationStep] = field(default_factory=list)
    """Each downstream entity touched, in BFS order."""

    rationale: str = ""
    skipped: bool = False
    """True when the event was an upgrade or had
    ``source="propagation"`` (cycle protection)."""

    def to_dict(self) -> dict[str, Any]:
        return {
            "origin_entity_id": self.origin_entity_id,
            "origin_delta_pct": round(self.origin_delta_pct, 4),
            "steps": [s.to_dict() for s in self.steps],
            "rationale": self.rationale,
            "skipped": self.skipped,
        }


# ──────────────────────────────────────────────────────────────────────
# Propagator
# ──────────────────────────────────────────────────────────────────────


class ConfidencePropagator:
    """Verifier that cascades downgrades through the graph.

    Configurable knobs match the module constants:
      - ``rel_types``: which edges propagate (default
        :data:`PROPAGATING_REL_TYPES`).
      - ``decay``: per-depth dampening (0–1).
      - ``max_depth``: hard cap on hops.
      - ``floor``: lower bound for any propagated
        confidence.
    """

    name: str = "propagation"

    def __init__(
        self,
        *,
        rel_types: frozenset[str] = PROPAGATING_REL_TYPES,
        decay: float = PROPAGATION_DECAY,
        max_depth: int = PROPAGATION_MAX_DEPTH,
        floor: float = PROPAGATION_FLOOR,
    ) -> None:
        self.rel_types = frozenset(rel_types)
        self.decay = decay
        self.max_depth = max_depth
        self.floor = floor

    def verify(
        self,
        event: dict[str, Any],
        graph: Any,
    ) -> PropagationVerdict | None:
        if event.get("kind") != "confidence_changed":
            return None

        # Cycle protection: don't react to our own writes.
        if event.get("source") == "propagation":
            return None

        delta = float(event.get("delta", 0.0))
        if delta >= 0:
            # Upgrades don't cascade.
            return None

        origin = str(event.get("entity_id") or "")
        old = float(event.get("old_confidence", 0.0))
        new = float(event.get("new_confidence", 0.0))
        if old <= 0:
            # Can't compute a meaningful percentage from a
            # zero baseline.
            return None
        delta_pct = (old - new) / old

        verdict = PropagationVerdict(
            origin_entity_id=origin,
            origin_delta_pct=delta_pct,
            rationale=(
                f"upstream {origin} downgraded by "
                f"{delta_pct:.2%}; propagating through "
                f"{', '.join(sorted(self.rel_types))} at depth "
                f"≤ {self.max_depth}"
            ),
        )

        # BFS up the graph along propagating edges.
        visited: set[str] = {origin}
        frontier: list[tuple[str, int]] = [(origin, 0)]
        while frontier:
            current_id, depth = frontier.pop(0)
            if depth >= self.max_depth:
                continue
            try:
                predecessors = list(graph.graph.in_edges(current_id, data=True))
            except Exception as exc:
                log.debug(
                    "Propagator: in_edges failed",
                    entity_id=current_id, error=str(exc),
                )
                continue

            for pred_id, _, edge_data in predecessors:
                if pred_id in visited:
                    continue
                rel_type = str(edge_data.get("rel_type", ""))
                if rel_type not in self.rel_types:
                    continue

                node_data = graph.graph.nodes.get(pred_id)
                if node_data is None:
                    continue

                step_depth = depth + 1
                impact = delta_pct * (self.decay ** step_depth)
                old_conf = float(node_data.get("confidence", 0.0))
                new_conf = max(self.floor, old_conf * (1 - impact))
                if new_conf < old_conf:
                    written = graph.set_confidence(
                        pred_id, new_conf,
                        reason=(
                            f"propagation from {origin} via "
                            f"{rel_type} (depth {step_depth})"
                        ),
                        source="propagation",
                    )
                    if written:
                        verdict.steps.append(PropagationStep(
                            entity_id=pred_id,
                            entity_type=str(
                                node_data.get("entity_type", ""),
                            ),
                            rel_type=rel_type,
                            depth=step_depth,
                            confidence_before=old_conf,
                            confidence_after=new_conf,
                        ))

                visited.add(pred_id)
                frontier.append((pred_id, step_depth))

        return verdict

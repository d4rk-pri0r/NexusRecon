"""Contradiction Detector — flag direct contradictions in
graph data + queue for human review.

The detector fires on two specific event kinds the
:class:`~nexusrecon.core.entity_graph.EntityGraph` emits in
addition to the basic mutation events:

  - ``sticky_field_conflict`` — a merge tried to set an
    entity field to a value that disagrees with the value
    already on the node (e.g. ``cloud_provider="azure"`` when
    the existing record says ``"aws"``). The merge itself
    silently drops the incoming value (existing wins by
    default); this event records the divergence so the
    detector can decide whether to act.
  - ``exclusive_rel_conflict`` — a new singular-ownership
    relationship (``belongs_to``, ``owns``, ``part_of``,
    ``registered_by``, ``hosted_on``) arrived alongside an
    existing edge of the same type from the same source.

What "act" means
- Append a :class:`ContradictionRecord` to
  ``state["contradictions"]`` so the operator can review.
- Downgrade the contradicted entity's confidence proportional
  to how severe the conflict is (driven by ``severity_threshold``
  + ``downgrade_factor``). The downgrade is bounded — never
  reduces confidence below the configured floor.
- Return a :class:`ContradictionVerdict` for the audit log.

What this is NOT
- An LLM-driven semantic conflict detector. PR D may layer
  one on top; for now we trade recall for precision.
- A scope-violation detector — that's the scope_guard's job.
- A *resolver* — the detector flags, the operator decides.

Why downgrade automatically (and not just queue)
- Auditability First (sacred): a contradicted high-confidence
  finding remains "high" in reports until the operator
  reviews, which masks real risk. A small auto-downgrade
  surfaces the doubt without overwriting the operator's
  judgment.
- Bounded: the downgrade is multiplicative + capped, so it
  can't drive confidence to zero in one pass. The
  contradiction queue is the authoritative resolution
  surface.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import structlog

log = structlog.get_logger(__name__)


# ──────────────────────────────────────────────────────────────────────
# Verdict + record types
# ──────────────────────────────────────────────────────────────────────


@dataclass
class ContradictionVerdict:
    """Returned to the orchestrator for the audit log. Mirrors
    :class:`CorroborationVerdict` so the verification log has a
    consistent shape across verifiers."""

    entity_id: str
    kind: str
    """``sticky_field_conflict`` or ``exclusive_rel_conflict``."""

    field_or_rel: str
    existing_claim: Any
    incoming_claim: Any
    severity: str  # "low" | "medium" | "high"
    confidence_before: float
    confidence_after: float
    delta: float
    queued: bool
    """True when the contradiction was added to the
    pending-review queue. False when severity was below the
    configured threshold + we just downgraded silently."""
    rationale: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "kind": self.kind,
            "field_or_rel": self.field_or_rel,
            "existing_claim": _stringify(self.existing_claim),
            "incoming_claim": _stringify(self.incoming_claim),
            "severity": self.severity,
            "confidence_before": round(self.confidence_before, 4),
            "confidence_after": round(self.confidence_after, 4),
            "delta": round(self.delta, 4),
            "queued": self.queued,
            "rationale": self.rationale,
            "metadata": dict(self.metadata),
        }


# ──────────────────────────────────────────────────────────────────────
# Detector
# ──────────────────────────────────────────────────────────────────────


CONFIDENCE_FLOOR: float = 0.05
"""Hard floor for auto-downgrades — a single contradiction
shouldn't drive a finding's confidence to zero. Repeat
contradictions DO compound, but the floor prevents the engine
from manufacturing certainty in the negative direction."""


class ContradictionDetector:
    """Verifier that flags direct contradictions.

    Configurable knobs:
      - ``severity_threshold``: existing confidence below this
        is treated as a *low-severity* conflict (downgrade
        applied, queue add skipped). At or above → ``medium``
        / ``high`` depending on the absolute confidence gap.
      - ``downgrade_factor``: multiplicative downgrade applied
        to the contradicted entity. 0.5 means "halve the
        confidence"; 0.7 is more conservative.
      - ``queue_severity_threshold``: severity at which the
        contradiction is appended to ``state["contradictions"]``.
        Default ``medium`` — low-severity conflicts downgrade
        silently."""

    name: str = "contradiction"

    def __init__(
        self,
        *,
        state: dict[str, Any] | None = None,
        severity_threshold: float = 0.7,
        downgrade_factor: float = 0.6,
        queue_severity_threshold: str = "medium",
        floor: float = CONFIDENCE_FLOOR,
    ) -> None:
        # Holding state on the detector lets the orchestrator
        # stay graph-only; the detector writes the queue
        # records itself. Same pattern PR D used for
        # bounded_agency's pending_approvals.
        self.state: dict[str, Any] = state if state is not None else {}
        self.severity_threshold = severity_threshold
        self.downgrade_factor = downgrade_factor
        self.queue_severity_threshold = queue_severity_threshold
        self.floor = floor

    # ── Public verifier surface ──────────────────────────────

    def verify(
        self,
        event: dict[str, Any],
        graph: Any,
    ) -> ContradictionVerdict | None:
        kind = event.get("kind")
        if kind == "sticky_field_conflict":
            return self._handle_sticky_conflict(event, graph)
        if kind == "exclusive_rel_conflict":
            return self._handle_rel_conflict(event, graph)
        return None

    # ── Sticky-field conflicts ───────────────────────────────

    def _handle_sticky_conflict(
        self,
        event: dict[str, Any],
        graph: Any,
    ) -> ContradictionVerdict | None:
        entity_id = str(event.get("entity_id") or "")
        node_data = graph.graph.nodes.get(entity_id)
        if node_data is None:
            return None

        field_name = str(event.get("field", ""))
        existing_value = event.get("existing_value")
        incoming_value = event.get("incoming_value")
        existing_confidence = float(event.get("existing_confidence", 0.0))

        severity = _grade_sticky_severity(
            existing_confidence=existing_confidence,
            severity_threshold=self.severity_threshold,
        )
        conf_before = float(node_data.get("confidence", 0.0))
        conf_after = max(self.floor, conf_before * self.downgrade_factor)
        node_data["confidence"] = conf_after

        queued = self._maybe_queue(
            entity_id=entity_id, severity=severity,
            kind="sticky_field_conflict",
            field_or_rel=field_name,
            existing_claim=existing_value,
            incoming_claim=incoming_value,
            existing_sources=list(event.get("existing_sources") or []),
            incoming_sources=list(event.get("incoming_sources") or []),
        )

        return ContradictionVerdict(
            entity_id=entity_id,
            kind="sticky_field_conflict",
            field_or_rel=field_name,
            existing_claim=existing_value,
            incoming_claim=incoming_value,
            severity=severity,
            confidence_before=conf_before,
            confidence_after=conf_after,
            delta=conf_after - conf_before,
            queued=queued,
            rationale=(
                f"Sticky field '{field_name}' divergence: "
                f"{existing_value!r} vs {incoming_value!r}; "
                f"existing claim confidence={existing_confidence:.2f}"
            ),
            metadata={
                "existing_sources": list(event.get("existing_sources") or []),
                "incoming_sources": list(event.get("incoming_sources") or []),
            },
        )

    # ── Exclusive-relationship conflicts ─────────────────────

    def _handle_rel_conflict(
        self,
        event: dict[str, Any],
        graph: Any,
    ) -> ContradictionVerdict | None:
        source_id = str(event.get("source_id") or "")
        node_data = graph.graph.nodes.get(source_id)
        if node_data is None:
            return None

        rel_type = str(event.get("rel_type", ""))
        existing_target = event.get("existing_target")
        incoming_target = event.get("incoming_target")
        existing_conf = float(event.get("existing_confidence", 0.0))
        incoming_conf = float(event.get("incoming_confidence", 0.0))

        severity = _grade_rel_severity(
            existing_confidence=existing_conf,
            incoming_confidence=incoming_conf,
            severity_threshold=self.severity_threshold,
        )
        conf_before = float(node_data.get("confidence", 0.0))
        conf_after = max(self.floor, conf_before * self.downgrade_factor)
        node_data["confidence"] = conf_after

        queued = self._maybe_queue(
            entity_id=source_id, severity=severity,
            kind="exclusive_rel_conflict",
            field_or_rel=rel_type,
            existing_claim=existing_target,
            incoming_claim=incoming_target,
            existing_sources=[str(event.get("existing_source_tool") or "")],
            incoming_sources=[str(event.get("incoming_source_tool") or "")],
        )

        return ContradictionVerdict(
            entity_id=source_id,
            kind="exclusive_rel_conflict",
            field_or_rel=rel_type,
            existing_claim=existing_target,
            incoming_claim=incoming_target,
            severity=severity,
            confidence_before=conf_before,
            confidence_after=conf_after,
            delta=conf_after - conf_before,
            queued=queued,
            rationale=(
                f"Exclusive relationship '{rel_type}' conflict: "
                f"existing→{existing_target} (conf {existing_conf:.2f}) "
                f"vs incoming→{incoming_target} (conf {incoming_conf:.2f})"
            ),
            metadata={
                "existing_source_tool": str(event.get("existing_source_tool") or ""),
                "incoming_source_tool": str(event.get("incoming_source_tool") or ""),
            },
        )

    # ── Queue management ─────────────────────────────────────

    def _maybe_queue(
        self,
        *,
        entity_id: str,
        severity: str,
        kind: str,
        field_or_rel: str,
        existing_claim: Any,
        incoming_claim: Any,
        existing_sources: list[str],
        incoming_sources: list[str],
    ) -> bool:
        """Append to ``state["contradictions"]`` when severity
        meets the queue threshold. Returns ``True`` when a
        record was queued."""
        if not _severity_meets(severity, self.queue_severity_threshold):
            return False
        record = {
            "queued_at": datetime.now(UTC).isoformat(),
            "entity_id": entity_id,
            "kind": kind,
            "field_or_rel": field_or_rel,
            "existing_claim": _stringify(existing_claim),
            "incoming_claim": _stringify(incoming_claim),
            "existing_sources": list(existing_sources),
            "incoming_sources": list(incoming_sources),
            "severity": severity,
            "status": "pending",
        }
        pending = list(self.state.get("contradictions") or [])
        pending.append(record)
        self.state["contradictions"] = pending
        return True


# ──────────────────────────────────────────────────────────────────────
# Review queue helpers
# ──────────────────────────────────────────────────────────────────────


def resolve_contradiction(
    state: dict[str, Any],
    *,
    entity_id: str,
    kind: str,
    field_or_rel: str,
    resolution: str,
    operator: str,
    notes: str = "",
) -> dict[str, Any] | None:
    """Resolve a queued contradiction.

    ``resolution`` is one of ``existing_wins`` / ``incoming_wins``
    / ``both`` / ``investigate_further``. The TUI surfaces these
    as a small radio group; the audit-log record captures
    whatever the operator picked verbatim.

    Returns the resolved record (with ``status`` updated). The
    record also lands in ``state["contradiction_log"]`` for
    forensic retrieval. Returns ``None`` when no matching
    pending record exists (idempotent re-resolution)."""
    pending = list(state.get("contradictions") or [])
    record: dict[str, Any] | None = None
    for entry in pending:
        if (
            entry.get("entity_id") == entity_id
            and entry.get("kind") == kind
            and entry.get("field_or_rel") == field_or_rel
            and entry.get("status") == "pending"
        ):
            record = entry
            break
    if record is None:
        log.warning(
            "Contradiction resolve: no pending record found",
            entity_id=entity_id, kind=kind,
        )
        return None
    record["status"] = "resolved"
    record["resolution"] = resolution
    record["resolved_at"] = datetime.now(UTC).isoformat()
    record["resolved_by"] = operator
    record["resolution_notes"] = notes
    state["contradictions"] = pending

    history = list(state.get("contradiction_log") or [])
    history.append(dict(record))
    state["contradiction_log"] = history
    return record


# ──────────────────────────────────────────────────────────────────────
# Severity grading
# ──────────────────────────────────────────────────────────────────────


_SEVERITY_ORDER: dict[str, int] = {"low": 0, "medium": 1, "high": 2}


def _grade_sticky_severity(
    *,
    existing_confidence: float,
    severity_threshold: float,
) -> str:
    """Sticky-field conflicts grade off the *existing* claim's
    confidence — a high-confidence finding being challenged is
    a bigger deal than a low-confidence one. When the existing
    is ≥ ``severity_threshold + 0.2``, it's ``high``."""
    if existing_confidence >= severity_threshold + 0.2:
        return "high"
    if existing_confidence >= severity_threshold:
        return "medium"
    return "low"


def _grade_rel_severity(
    *,
    existing_confidence: float,
    incoming_confidence: float,
    severity_threshold: float,
) -> str:
    """Relationship conflicts grade off the MAX of the two
    confidences — either side being high makes it worth
    surfacing. Two low-confidence edges disagreeing is much
    less interesting."""
    peak = max(existing_confidence, incoming_confidence)
    if peak >= severity_threshold + 0.2:
        return "high"
    if peak >= severity_threshold:
        return "medium"
    return "low"


def _severity_meets(actual: str, threshold: str) -> bool:
    return _SEVERITY_ORDER.get(actual, -1) >= _SEVERITY_ORDER.get(threshold, 99)


# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────


def _stringify(value: Any) -> str:
    """Coerce arbitrary claim values to a string for the audit
    log + review queue. Keeping it lossy on purpose — operators
    don't need pickled objects in their review UI."""
    if value is None:
        return ""
    if isinstance(value, (str, int, float, bool)):
        return str(value)
    return repr(value)

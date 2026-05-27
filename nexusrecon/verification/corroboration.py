"""Corroboration Engine — boost confidence when distinct
independence classes of source signals agree.

The intuition: three subdomain results from three different
passive DNS feeds aren't really independent — they probably
share the same underlying scrape. But ``passive_dns +
certificate_transparency + active_probe`` is three different
*kinds* of evidence; agreement across them is dramatically
stronger.

This module maps individual source identifiers (the strings
that land in ``entity.sources`` — e.g. ``"subfinder"``,
``"crtsh"``, ``"naabu"``) onto a small set of
*independence classes*. An entity's corroboration boost is a
function of how many distinct classes it has sources from,
not the raw source count.

Formula (kept deliberately simple so reviewers can reason
about it):

    distinct_classes >= 2:
        new_confidence = old + (CAP - old) * (1 - DECAY^(n - 1))

    where:
        n     = number of distinct classes
        DECAY = 0.5  (each additional class closes half the
                      remaining headroom to CAP)
        CAP   = 0.99 (never assert certainty — leave room for
                      the contradiction detector in PR B)

So 2 classes lifts a 0.5-confidence entity to 0.745, 3 to
0.871, 4 to 0.934, 5 to 0.967, 6 to 0.984. The boost is
saturating — diminishing returns from more agreement, which
matches the real-world signal value of "yet another passive
DNS source agreed."

Confidence only goes UP from corroboration; downgrades come
from the contradiction detector (PR B) and propagation (PR C).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

log = structlog.get_logger(__name__)


# ──────────────────────────────────────────────────────────────────────
# Source → independence-class mapping
# ──────────────────────────────────────────────────────────────────────

#: Maps a source identifier (the string that lands in
#: ``entity.sources``) to its *independence class*. Sources in
#: the same class share signal lineage; different classes are
#: independent enough that agreement carries weight.
#:
#: Conservative defaults: unknown sources land in
#: ``"unknown"``, which is treated as its own class but never
#: as evidence of itself (so an entity with only ``unknown``
#: sources gets no boost). Real plugins should
#: :func:`register_source_class` rather than relying on the
#: ``unknown`` bucket.
SOURCE_INDEPENDENCE_CLASSES: dict[str, str] = {
    # Passive DNS / subdomain enumeration
    "subfinder":         "passive_dns",
    "amass_passive":     "passive_dns",
    "amass":             "passive_dns",  # default amass mode is passive
    "dnsdumpster":       "passive_dns",
    "securitytrails":    "passive_dns",
    "virustotal":        "passive_dns",
    "anubis":            "passive_dns",

    # Certificate transparency
    "crtsh":             "certificate",
    "certspotter":       "certificate",
    "censys_certs":      "certificate",
    "google_ct":         "certificate",

    # Active probing
    "naabu":             "active_probe",
    "httpx":             "active_probe",
    "amass_active":      "active_probe",
    "nmap":              "active_probe",
    "masscan":           "active_probe",

    # Breach corpora
    "h8mail":            "breach_corpus",
    "hibp":              "breach_corpus",
    "dehashed":          "breach_corpus",
    "snusbase":          "breach_corpus",

    # Code intelligence
    "github_dorks":      "code_intel",
    "trufflehog":        "code_intel",
    "gitleaks":          "code_intel",
    "gitlab_search":     "code_intel",

    # Cloud enumeration
    "cloud_enum":        "cloud_enum",
    "s3_enum":           "cloud_enum",
    "azure_enum":        "cloud_enum",

    # Social / SOCMINT
    "github_users":      "social",
    "linkedin":          "social",
    "mastodon":          "social",
    "twitter":           "social",

    # Scope (genesis) — the one source we trust unconditionally
    "scope":             "scope",

    # Operator-supplied
    "manual":            "manual",
}


def register_source_class(source: str, independence_class: str) -> None:
    """Plugin hook: register a new ``source → class`` mapping
    so a community recon pack's verifier can declare its
    independence class without monkey-patching the dict.

    Idempotent; subsequent calls overwrite the previous
    mapping. Logs a debug message so operators can spot
    surprising re-registrations during plugin load."""
    if source in SOURCE_INDEPENDENCE_CLASSES:
        log.debug(
            "Overwriting source class registration",
            source=source,
            old=SOURCE_INDEPENDENCE_CLASSES[source],
            new=independence_class,
        )
    SOURCE_INDEPENDENCE_CLASSES[source] = independence_class


# ──────────────────────────────────────────────────────────────────────
# Verdict
# ──────────────────────────────────────────────────────────────────────


@dataclass
class CorroborationVerdict:
    """The corroboration engine's verdict for one mutation
    event. Returned to the orchestrator, which writes it to
    the audit log."""

    entity_id: str
    entity_type: str
    independence_classes: list[str]
    """Distinct classes the entity has evidence from. Length
    of this list drives the boost magnitude."""

    old_confidence: float
    new_confidence: float
    delta: float
    applied: bool
    """True when the engine actually wrote the new confidence
    back to the graph. False when the boost was non-positive
    (e.g. only one class, already at CAP, etc.) — verdict is
    still recorded so the audit trail shows the engine ran."""

    rationale: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "entity_type": self.entity_type,
            "independence_classes": list(self.independence_classes),
            "old_confidence": round(self.old_confidence, 4),
            "new_confidence": round(self.new_confidence, 4),
            "delta": round(self.delta, 4),
            "applied": self.applied,
            "rationale": self.rationale,
            "metadata": dict(self.metadata),
        }


# ──────────────────────────────────────────────────────────────────────
# Engine
# ──────────────────────────────────────────────────────────────────────


CORROBORATION_CAP: float = 0.99
"""Confidence ceiling for corroboration-driven boosts. Leaving
≥0.01 headroom matters — the contradiction detector (PR B)
needs somewhere to land a downgrade without flipping straight
to zero."""

CORROBORATION_DECAY: float = 0.5
"""Each additional independence class closes half the
remaining headroom to ``CORROBORATION_CAP``. Lower values
(more aggressive boost) overstate cross-source agreement;
higher values (more conservative) under-rewards real
independence. 0.5 is the sweet spot — verify with telemetry."""


class CorroborationEngine:
    """Increases an entity's ``confidence`` when distinct
    source independence classes agree on it.

    Stateless aside from the configurable cap/decay (held as
    instance attributes so tests can override without
    monkey-patching globals). The engine reads the entity
    out of the graph at verdict time + writes the new
    confidence back via the same node — no shadow state."""

    name: str = "corroboration"
    """Identifier surfaced in audit-log entries. Each verifier
    has a unique name so reviewers can filter."""

    def __init__(
        self,
        *,
        cap: float = CORROBORATION_CAP,
        decay: float = CORROBORATION_DECAY,
    ) -> None:
        self.cap = cap
        self.decay = decay

    def verify(
        self,
        event: dict[str, Any],
        graph: Any,
    ) -> CorroborationVerdict | None:
        """Process one mutation event. Returns a verdict when
        the event is something this engine cares about
        (``entity_added`` / ``entity_merged``); ``None``
        otherwise (relationships, irrelevant kinds)."""
        kind = event.get("kind")
        if kind not in ("entity_added", "entity_merged"):
            return None

        entity_id = str(event.get("entity_id") or "")
        if not entity_id:
            return None

        node_data = graph.graph.nodes.get(entity_id)
        if node_data is None:
            log.debug(
                "Corroboration: entity gone before verdict",
                entity_id=entity_id,
            )
            return None

        sources = list(node_data.get("sources", []))
        classes = _distinct_classes(sources)
        old_conf = float(node_data.get("confidence", 0.0))

        # No boost when only 0-1 distinct classes — single
        # source of evidence isn't corroboration.
        if len(classes) < 2:
            return CorroborationVerdict(
                entity_id=entity_id,
                entity_type=str(node_data.get("entity_type", "")),
                independence_classes=classes,
                old_confidence=old_conf,
                new_confidence=old_conf,
                delta=0.0,
                applied=False,
                rationale="insufficient distinct independence classes",
                metadata={"sources": sources},
            )

        new_conf = _compute_boost(
            old=old_conf,
            distinct_class_count=len(classes),
            cap=self.cap,
            decay=self.decay,
        )
        delta = new_conf - old_conf

        if delta <= 0:
            # Already at cap (or above — possible if a tool
            # asserted confidence > our cap). Record but
            # don't write back.
            return CorroborationVerdict(
                entity_id=entity_id,
                entity_type=str(node_data.get("entity_type", "")),
                independence_classes=classes,
                old_confidence=old_conf,
                new_confidence=old_conf,
                delta=0.0,
                applied=False,
                rationale=(
                    "already at or above corroboration cap"
                    if old_conf >= self.cap
                    else "boost would not improve confidence"
                ),
                metadata={"sources": sources},
            )

        node_data["confidence"] = new_conf
        return CorroborationVerdict(
            entity_id=entity_id,
            entity_type=str(node_data.get("entity_type", "")),
            independence_classes=classes,
            old_confidence=old_conf,
            new_confidence=new_conf,
            delta=delta,
            applied=True,
            rationale=(
                f"{len(classes)} independence class(es) agree; "
                f"+{delta:.4f} (cap {self.cap}, decay {self.decay})"
            ),
            metadata={"sources": sources},
        )


# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────


def _distinct_classes(sources: list[str]) -> list[str]:
    """Map a list of source identifiers to the sorted list of
    distinct independence classes. ``unknown`` sources are
    bucketed together (so 5 unknown sources don't all count
    as independent), and the ``unknown`` bucket itself is
    INCLUDED in the returned list — but counted at most once,
    so two unknown sources contribute 1 to the class count,
    same as one. Real plugins should register their classes
    via :func:`register_source_class`."""
    seen: set[str] = set()
    for src in sources:
        cls = SOURCE_INDEPENDENCE_CLASSES.get(src, "unknown")
        seen.add(cls)
    return sorted(seen)


def _compute_boost(
    *,
    old: float,
    distinct_class_count: int,
    cap: float,
    decay: float,
) -> float:
    """new = old + (cap - old) * (1 - decay^(n - 1)). See the
    module docstring for the rationale."""
    if distinct_class_count < 2:
        return old
    headroom = max(0.0, cap - old)
    coverage = 1.0 - (decay ** (distinct_class_count - 1))
    return round(old + headroom * coverage, 6)

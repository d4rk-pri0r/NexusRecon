"""End-to-end NL → (Scope, Strategy) orchestrator.

Combines :func:`extract_intent` + :func:`build_scope_stub` +
the Phase 1 :class:`Strategy` synthesis into one call.
The CLI commands + TUI tab call this with the operator's
sentence; the result carries everything they need to
review + save before running.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

from nexusrecon.intent.intent_parser import (
    IntentRecord,
    extract_intent,
)
from nexusrecon.intent.scope_builder import build_scope_stub
from nexusrecon.strategy import Strategy

log = structlog.get_logger(__name__)


# ──────────────────────────────────────────────────────────────────────
# Phase mapping
# ──────────────────────────────────────────────────────────────────────

#: Which workflow phases to enable for each intent category.
#: Conservative bias — we'd rather under-cover and let the
#: operator add phases than over-cover and burn budget on
#: irrelevant work.
_PHASES_BY_INTENT: dict[str, list[str]] = {
    "credentials": [
        "phase1", "phase2", "phase3", "phase4",
        "phase8", "phase9",
    ],
    "subdomains": [
        "phase1", "phase2", "phase2_5", "phase4", "phase9",
    ],
    "cloud": [
        "phase1", "phase2", "phase4", "phase5", "phase8", "phase9",
    ],
    "identity": [
        "phase1", "phase3", "phase4", "phase6", "phase9",
    ],
    "pretext": [
        "phase1", "phase3", "phase4", "phase6", "phase7", "phase7_5",
        "phase7_7", "phase9",
    ],
    "vulnerabilities": [
        "phase1", "phase2", "phase4", "phase8", "phase9",
    ],
    "executives": [
        "phase1", "phase3", "phase4", "phase6", "phase7_5",
        "phase7_7", "phase9",
    ],
    "supply_chain": [
        "phase1", "phase2", "phase4", "phase5", "phase9",
    ],
}

#: When the parser found NO intent categories, run this
#: default footprint. Matches today's hardcoded default phase
#: order but with phase7 (phishing draft) removed because the
#: operator hasn't asked for it.
_DEFAULT_PHASES: list[str] = [
    "phase1", "phase2", "phase2_5", "phase3", "phase4",
    "phase8", "phase9",
]


# ──────────────────────────────────────────────────────────────────────
# Result
# ──────────────────────────────────────────────────────────────────────


@dataclass
class IntentPlanResult:
    """Aggregate output of :func:`plan_from_intent`."""

    intent: IntentRecord
    scope_stub: dict[str, Any]
    strategy: Strategy
    warnings: list[str] = field(default_factory=list)
    """Operator-facing notes about gaps the planner couldn't
    fill in (e.g. "no targets extracted — replace
    REPLACE_ME.example before running")."""

    def to_dict(self) -> dict[str, Any]:
        return {
            "intent": self.intent.to_dict(),
            "scope_stub": dict(self.scope_stub),
            "strategy": self.strategy.to_dict(),
            "warnings": list(self.warnings),
        }


# ──────────────────────────────────────────────────────────────────────
# Phase + strategy synthesis
# ──────────────────────────────────────────────────────────────────────


def _phases_for_intent(intent: IntentRecord) -> list[str]:
    """Union of per-category phase lists, preserving order
    seen across the matched categories. Falls back to the
    default footprint when no category matched."""
    if not intent.intent_categories:
        return list(_DEFAULT_PHASES)
    seen: list[str] = []
    seen_set: set[str] = set()
    for category in intent.intent_categories:
        for phase in _PHASES_BY_INTENT.get(category, []):
            if phase not in seen_set:
                seen.append(phase)
                seen_set.add(phase)
    if not seen:
        return list(_DEFAULT_PHASES)
    return seen


def _strategy_from_intent(intent: IntentRecord) -> Strategy:
    """Synthesize a :class:`Strategy` consistent with the
    extracted intent. The Strategy name mirrors the rationale
    so the audit trail shows where it came from."""
    phases = _phases_for_intent(intent)
    metadata: dict[str, Any] = {
        "intent_raw": intent.raw_sentence,
        "intent_confidence": intent.confidence,
        "intent_rationale": intent.rationale,
        "intent_categories": list(intent.intent_categories),
    }
    # Choose a name that fingerprints the intent — short,
    # operator-readable, audit-friendly.
    if intent.intent_categories:
        name = "intent_" + "_".join(
            sorted(intent.intent_categories)[:2]
        )
    else:
        name = "intent_default"
    return Strategy(
        name=name,
        phases=phases,
        dispatch_policy_name=intent.dispatch_policy_name,
        metadata=metadata,
    )


# ──────────────────────────────────────────────────────────────────────
# Public entry
# ──────────────────────────────────────────────────────────────────────


def plan_from_intent(
    sentence: str,
    *,
    executor: Any | None = None,
    prefer_fallback: bool = False,
) -> IntentPlanResult:
    """Top-level: parse + build scope + synthesize strategy.

    ``executor`` injects an :class:`AgentExecutor` for the
    LLM path. ``prefer_fallback`` forces the regex extractor
    (no LLM round-trip). The CLI uses both: ``--no-llm`` flag
    sets ``prefer_fallback=True``; otherwise the LLM runs
    when configured."""
    intent = extract_intent(
        sentence, executor=executor, prefer_fallback=prefer_fallback,
    )
    scope_stub = build_scope_stub(intent)
    strategy = _strategy_from_intent(intent)

    warnings: list[str] = []
    if not intent.targets:
        warnings.append(
            "No targets extracted; scope.yaml carries a "
            "placeholder — REPLACE_ME.example must be edited "
            "before running."
        )
    if intent.confidence == "low":
        warnings.append(
            "Parser confidence is LOW. Review the extracted "
            "fields carefully — the planner may have missed "
            "key parts of the operator sentence."
        )
    if intent.max_tier in ("T2", "T3"):
        warnings.append(
            f"Tier ceiling defaulted to {intent.max_tier} — "
            f"ensure the engagement authorization covers "
            f"active/aggressive testing."
        )

    return IntentPlanResult(
        intent=intent,
        scope_stub=scope_stub,
        strategy=strategy,
        warnings=warnings,
    )

"""Tool-call pattern analyzer.

Walks ``state["dynamic_dispatch_log"]`` looking for sequences
the LLM dispatcher shouldn't be producing. Four patterns:

  - **Rapid pivots**: too many distinct target_types in a
    short window. Recon is supposed to drill down on a
    seed; rapid pivots suggest either an LLM that's confused
    or a planted suggestion in the prompt context.
  - **Low-yield bursts**: ≥N consecutive dispatches returning
    0 entities. Either the LLM is chasing nothing or
    upstream tools are silently failing.
  - **Repeat hits**: same (tool, target) pair dispatched ≥N
    times. Real value comes from one good hit; repeat
    requests suggest the LLM is stuck in a loop or
    being prompted into one.
  - **Tier escalation**: dispatch log contains T2/T3 entries
    when the scope's max_tier is T0/T1. The scope_guard
    already blocks these at execution time; surfacing them
    here makes a deliberate escalation attempt visible.

The analyzer is state-driven — runs at phase boundaries or
on demand. It doesn't subscribe to mutation events because
the dispatcher already serialises its decisions.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any

import structlog

from nexusrecon.adversarial.aggregator import (
    AdversarialFinding,
    append_finding,
    DEFAULT_DOWNGRADE_FACTOR_BY_SEVERITY,
)

log = structlog.get_logger(__name__)


_TIER_ORDER: dict[str, int] = {"T0": 0, "T1": 1, "T2": 2, "T3": 3}


@dataclass
class PatternVerdict:
    """One pattern finding."""

    kind: str
    severity: str
    rationale: str
    affected_entries: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "severity": self.severity,
            "rationale": self.rationale,
            "affected_entries": list(self.affected_entries),
            "metadata": dict(self.metadata),
        }


class ToolPatternAnalyzer:
    """Sweeps the dispatch log for suspicious sequences."""

    name: str = "tool_patterns"

    def __init__(
        self,
        *,
        rapid_pivot_window: int = 5,
        rapid_pivot_threshold: int = 4,
        low_yield_burst_threshold: int = 5,
        repeat_hit_threshold: int = 3,
    ) -> None:
        self.rapid_pivot_window = rapid_pivot_window
        self.rapid_pivot_threshold = rapid_pivot_threshold
        self.low_yield_burst_threshold = low_yield_burst_threshold
        self.repeat_hit_threshold = repeat_hit_threshold

    def scan(
        self,
        state: dict[str, Any] | None,
    ) -> list[PatternVerdict]:
        """Run every pattern check. ``state`` carries the
        dispatch log; ``None``/empty short-circuits to []."""
        if state is None:
            return []
        log_entries = list(state.get("dynamic_dispatch_log") or [])
        if not log_entries:
            return []

        verdicts: list[PatternVerdict] = []
        verdicts.extend(self._check_rapid_pivots(log_entries))
        verdicts.extend(self._check_low_yield_bursts(log_entries))
        verdicts.extend(self._check_repeat_hits(log_entries))
        verdicts.extend(self._check_tier_escalation(log_entries, state))

        for v in verdicts:
            factor = DEFAULT_DOWNGRADE_FACTOR_BY_SEVERITY.get(
                v.severity, 1.0,
            )
            # Tool-pattern findings don't directly downgrade
            # entities — they downgrade DISPATCH CONFIDENCE
            # (operator's trust in the dispatcher's recent
            # choices). For v1 we record + flag; the next PR
            # can wire a strategic-feedback hook that lifts
            # this into a planner replan trigger.
            append_finding(state, AdversarialFinding(
                detector=self.name,
                severity=v.severity,
                rationale=v.rationale,
                entity_ids=[],
                metadata={
                    "kind": v.kind,
                    "affected_entries": v.affected_entries,
                    **v.metadata,
                },
                downgrade_applied=False,
                downgrade_factor=factor,
            ))

        return verdicts

    # ── Per-pattern checks ───────────────────────────────────

    def _check_rapid_pivots(
        self, log_entries: list[dict[str, Any]],
    ) -> list[PatternVerdict]:
        """Sliding window over the dispatch log: when ≥N
        distinct target_types appear in the last W entries,
        that's a rapid pivot."""
        out: list[PatternVerdict] = []
        if len(log_entries) < self.rapid_pivot_window:
            return out
        for i in range(
            self.rapid_pivot_window, len(log_entries) + 1,
        ):
            window = log_entries[i - self.rapid_pivot_window:i]
            distinct = {
                str(entry.get("target_type", "")) for entry in window
            }
            distinct.discard("")
            if len(distinct) >= self.rapid_pivot_threshold:
                out.append(PatternVerdict(
                    kind="rapid_pivot",
                    severity="medium",
                    rationale=(
                        f"{len(distinct)} distinct target_types "
                        f"in a {self.rapid_pivot_window}-call "
                        f"window. Real recon focuses; rapid "
                        f"pivots suggest LLM confusion or "
                        f"adversarial steering."
                    ),
                    affected_entries=window[-3:],
                    metadata={
                        "window_size": self.rapid_pivot_window,
                        "distinct_types": sorted(distinct),
                    },
                ))
                # Only emit once per scan to avoid spam.
                break
        return out

    def _check_low_yield_bursts(
        self, log_entries: list[dict[str, Any]],
    ) -> list[PatternVerdict]:
        """≥N consecutive entries where ``success`` is False."""
        out: list[PatternVerdict] = []
        streak: list[dict[str, Any]] = []
        for entry in log_entries:
            if not entry.get("success", True):
                streak.append(entry)
                if len(streak) >= self.low_yield_burst_threshold:
                    out.append(PatternVerdict(
                        kind="low_yield_burst",
                        severity="medium",
                        rationale=(
                            f"{len(streak)} consecutive "
                            f"unsuccessful dispatches. Either "
                            f"the LLM is chasing dry holes or "
                            f"the upstream is suppressing "
                            f"output."
                        ),
                        affected_entries=streak[:3],
                        metadata={"streak_length": len(streak)},
                    ))
                    streak = []  # reset; only one finding per burst
            else:
                streak = []
        return out

    def _check_repeat_hits(
        self, log_entries: list[dict[str, Any]],
    ) -> list[PatternVerdict]:
        """Same ``(tool, target)`` ≥N times in the whole log."""
        counter: Counter[tuple[str, str]] = Counter()
        first_entry_for_pair: dict[
            tuple[str, str], dict[str, Any],
        ] = {}
        for entry in log_entries:
            key = (
                str(entry.get("tool", "")),
                str(entry.get("target", "")),
            )
            counter[key] += 1
            first_entry_for_pair.setdefault(key, entry)
        out: list[PatternVerdict] = []
        for (tool, target), count in counter.items():
            if count < self.repeat_hit_threshold:
                continue
            out.append(PatternVerdict(
                kind="repeat_hit",
                severity="medium",
                rationale=(
                    f"Tool {tool!r} dispatched against "
                    f"{target!r} {count} times. Loop-like "
                    f"pattern — LLM may be stuck or being "
                    f"steered into wasted budget."
                ),
                affected_entries=[first_entry_for_pair[(tool, target)]],
                metadata={
                    "tool": tool, "target": target, "count": count,
                },
            ))
        return out

    def _check_tier_escalation(
        self,
        log_entries: list[dict[str, Any]],
        state: dict[str, Any],
    ) -> list[PatternVerdict]:
        """Look for dispatches above the scope's max_tier."""
        scope = state.get("scope") or {}
        max_tier = ""
        if isinstance(scope, dict):
            max_tier = str(
                (scope.get("constraints") or {}).get("max_tier", "")
            )
        if not max_tier:
            max_tier = str(state.get("scope_max_tier", ""))
        if max_tier not in _TIER_ORDER:
            return []

        max_rank = _TIER_ORDER[max_tier]
        offending: list[dict[str, Any]] = []
        for entry in log_entries:
            tier = str(entry.get("tier", entry.get("tool_tier", "")))
            if tier in _TIER_ORDER and _TIER_ORDER[tier] > max_rank:
                offending.append(entry)
        if not offending:
            return []
        return [PatternVerdict(
            kind="tier_escalation",
            severity="high",
            rationale=(
                f"{len(offending)} dispatch attempt"
                f"{'s' if len(offending) != 1 else ''} above "
                f"scope ceiling {max_tier!r}. Scope guard "
                f"blocks at execution but the attempt "
                f"itself is the adversarial signal."
            ),
            affected_entries=offending[:3],
            metadata={
                "max_tier": max_tier,
                "count": len(offending),
            },
        )]

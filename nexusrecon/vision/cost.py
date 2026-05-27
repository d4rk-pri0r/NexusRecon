"""Strategy-driven cost gate.

The Phase 1 Strategy's ``tool_budgets`` dict carries
operator-set per-tool / per-category caps. We use the key
``vision_calls`` for the number of vision LLM calls a
campaign is allowed to make.

Defaults
- No key set → budget 0 → all vision calls skipped with a
  warning logged into ``state["vision_skip_log"]``.
- This is the conservative posture: vision is opt-in, not
  default-on. Operators set the key explicitly when they
  want it.

State counters
- ``state["vision_call_count"]`` — running count of
  successful describe_image / describe_text calls.
- ``state["vision_skip_log"]`` — per-skip records (source,
  reason) for the audit trail.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any


@dataclass
class CostGateDecision:
    """One gate decision. The extractor uses ``allowed`` to
    decide whether to fire the backend call."""

    allowed: bool
    budget: int
    used: int
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "budget": self.budget,
            "used": self.used,
            "reason": self.reason,
        }


class CostGate:
    """Reads + updates the campaign state's vision-call
    counters. Stateless across instances — all persistence
    lives in ``state``."""

    BUDGET_KEY: str = "vision_calls"

    def consult(self, state: dict[str, Any]) -> CostGateDecision:
        """Check whether one more vision call is allowed."""
        used = int(state.get("vision_call_count", 0))
        budget = self._budget_for(state)
        if budget <= 0:
            return CostGateDecision(
                allowed=False, budget=budget, used=used,
                reason=(
                    "vision_calls budget is 0 in the active "
                    "Strategy.tool_budgets — set it to a "
                    "positive integer to enable vision."
                ),
            )
        if used >= budget:
            return CostGateDecision(
                allowed=False, budget=budget, used=used,
                reason=(
                    f"vision_calls budget exhausted "
                    f"({used}/{budget})."
                ),
            )
        return CostGateDecision(
            allowed=True, budget=budget, used=used,
            reason=f"within budget ({used}/{budget})",
        )

    def record_call(self, state: dict[str, Any]) -> None:
        """Increment the running counter. Called on every
        successful backend invocation."""
        state["vision_call_count"] = int(
            state.get("vision_call_count", 0)
        ) + 1

    def record_skip(
        self,
        state: dict[str, Any],
        *,
        source: str,
        decision: CostGateDecision,
    ) -> None:
        """Append a skip record to the audit log."""
        log = list(state.get("vision_skip_log") or [])
        log.append({
            "timestamp": datetime.now(UTC).isoformat(),
            "source": source,
            "budget": decision.budget,
            "used": decision.used,
            "reason": decision.reason,
        })
        state["vision_skip_log"] = log

    # ── Internal ─────────────────────────────────────────────

    def _budget_for(self, state: dict[str, Any]) -> int:
        strategy = state.get("strategy") or {}
        if not isinstance(strategy, dict):
            return 0
        budgets = strategy.get("tool_budgets") or {}
        if not isinstance(budgets, dict):
            return 0
        try:
            return int(budgets.get(self.BUDGET_KEY, 0))
        except (TypeError, ValueError):
            return 0

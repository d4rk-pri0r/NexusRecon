"""
LLM and API cost tracker.

Tracks per-agent, per-campaign token usage and USD spend.
Hard-stops when the campaign budget is exceeded.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import datetime

import structlog

log = structlog.get_logger(__name__)

# Pricing as of mid-2026 (USD per million tokens) — update as needed
MODEL_PRICING: dict[str, dict[str, float]] = {
    "claude-opus-4-7": {"input": 15.0, "output": 75.0},
    "claude-opus-4-6": {"input": 15.0, "output": 75.0},
    "claude-opus-4-5": {"input": 15.0, "output": 75.0},
    "claude-sonnet-4-6": {"input": 3.0, "output": 15.0},
    "claude-sonnet-4-5": {"input": 3.0, "output": 15.0},
    "claude-haiku-4-5": {"input": 0.8, "output": 4.0},
    "claude-haiku-3-5": {"input": 0.8, "output": 4.0},
    "gpt-4o": {"input": 5.0, "output": 15.0},
    "gpt-4o-mini": {"input": 0.15, "output": 0.6},
    # Ollama / local — free
    "ollama": {"input": 0.0, "output": 0.0},
    "llama3.1:8b": {"input": 0.0, "output": 0.0},
    "llama3.1:70b": {"input": 0.0, "output": 0.0},
    # Deterministic MockLLM fallback — makes no API call, so it costs
    # nothing. Pricing it at zero (rather than letting it fall through to
    # the opus default) is what makes "cost == 0 and model == mock_llm" an
    # unambiguous signal that findings came from the fallback, not a live
    # model (Wave F-A6).
    "mock_llm": {"input": 0.0, "output": 0.0},
}


class BudgetExceededError(Exception):
    """Raised when LLM spend exceeds the campaign budget."""

    def __init__(self, current: float, limit: float) -> None:
        super().__init__(
            f"LLM budget exceeded: ${current:.4f} > ${limit:.4f}. "
            "Campaign checkpointed. Use 'nexusrecon resume' to continue with a higher budget."
        )
        self.current = current
        self.limit = limit


@dataclass
class AgentCostRecord:
    agent_name: str
    input_tokens: int = 0
    output_tokens: int = 0
    llm_calls: int = 0
    cost_usd: float = 0.0
    model: str = ""
    started_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class ToolCostRecord:
    tool_name: str
    api_calls: int = 0
    cost_usd: float = 0.0  # for paid APIs


class CostTracker:
    """
    Tracks and enforces campaign LLM and API spend budgets.
    Thread-safe.
    """

    def __init__(self, campaign_id: str, max_llm_cost_usd: float = 50.0) -> None:
        self.campaign_id = campaign_id
        self.max_llm_cost_usd = max_llm_cost_usd
        self._lock = threading.Lock()

        self.total_input_tokens: int = 0
        self.total_output_tokens: int = 0
        self.total_llm_calls: int = 0
        self.total_llm_cost_usd: float = 0.0
        self.total_api_cost_usd: float = 0.0

        self._agent_records: dict[str, AgentCostRecord] = {}
        self._tool_records: dict[str, ToolCostRecord] = {}
        self._call_log: list[dict] = []

    def record_llm_call(
        self,
        agent_name: str,
        model: str,
        input_tokens: int,
        output_tokens: int,
    ) -> float:
        """
        Record an LLM API call and return the cost in USD.
        Raises BudgetExceededError if total cost exceeds limit.
        """
        # Normalize model name
        model_key = model.lower().split("/")[-1]  # e.g. "anthropic/claude-opus-4-5" -> "claude-opus-4-5"
        pricing = MODEL_PRICING.get(model_key, MODEL_PRICING.get("claude-opus-4-5"))
        if pricing is None:
            pricing = {"input": 3.0, "output": 15.0}

        cost_usd = (
            input_tokens * pricing["input"] / 1_000_000
            + output_tokens * pricing["output"] / 1_000_000
        )

        with self._lock:
            self.total_input_tokens += input_tokens
            self.total_output_tokens += output_tokens
            self.total_llm_calls += 1
            self.total_llm_cost_usd += cost_usd

            # Per-agent tracking
            if agent_name not in self._agent_records:
                self._agent_records[agent_name] = AgentCostRecord(
                    agent_name=agent_name, model=model
                )
            rec = self._agent_records[agent_name]
            rec.input_tokens += input_tokens
            rec.output_tokens += output_tokens
            rec.llm_calls += 1
            rec.cost_usd += cost_usd

            self._call_log.append({
                "agent": agent_name,
                "model": model,
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "cost_usd": cost_usd,
                "timestamp": datetime.utcnow().isoformat(),
            })

            if self.total_llm_cost_usd > self.max_llm_cost_usd:
                raise BudgetExceededError(self.total_llm_cost_usd, self.max_llm_cost_usd)

        log.debug(
            "LLM call recorded",
            agent=agent_name,
            model=model,
            tokens_in=input_tokens,
            tokens_out=output_tokens,
            cost_usd=round(cost_usd, 4),
            total_usd=round(self.total_llm_cost_usd, 4),
        )
        return cost_usd

    def record_tool_call(self, tool_name: str, api_cost_usd: float = 0.0) -> None:
        """Record an API tool call (for paid API tracking)."""
        with self._lock:
            if tool_name not in self._tool_records:
                self._tool_records[tool_name] = ToolCostRecord(tool_name=tool_name)
            rec = self._tool_records[tool_name]
            rec.api_calls += 1
            rec.cost_usd += api_cost_usd
            self.total_api_cost_usd += api_cost_usd

    def total_cost_usd(self) -> float:
        return self.total_llm_cost_usd + self.total_api_cost_usd

    def remaining_budget_usd(self) -> float:
        return max(0.0, self.max_llm_cost_usd - self.total_llm_cost_usd)

    def budget_utilization_pct(self) -> float:
        if self.max_llm_cost_usd == 0:
            return 100.0
        return (self.total_llm_cost_usd / self.max_llm_cost_usd) * 100.0

    def summary(self) -> dict:
        """Return a cost summary dict for reporting."""
        with self._lock:
            return {
                "campaign_id": self.campaign_id,
                "total_llm_cost_usd": round(self.total_llm_cost_usd, 4),
                "total_api_cost_usd": round(self.total_api_cost_usd, 4),
                "total_cost_usd": round(self.total_cost_usd(), 4),
                "budget_usd": self.max_llm_cost_usd,
                "remaining_usd": round(self.remaining_budget_usd(), 4),
                "utilization_pct": round(self.budget_utilization_pct(), 1),
                "total_llm_calls": self.total_llm_calls,
                "total_input_tokens": self.total_input_tokens,
                "total_output_tokens": self.total_output_tokens,
                "by_agent": {
                    name: {
                        "cost_usd": round(r.cost_usd, 4),
                        "llm_calls": r.llm_calls,
                        "input_tokens": r.input_tokens,
                        "output_tokens": r.output_tokens,
                    }
                    for name, r in self._agent_records.items()
                },
                "by_tool": {
                    name: {"api_calls": r.api_calls, "cost_usd": round(r.cost_usd, 4)}
                    for name, r in self._tool_records.items()
                },
            }

    def warn_if_high_utilization(self, threshold_pct: float = 80.0) -> str | None:
        """Return warning string if utilization is above threshold, else None."""
        pct = self.budget_utilization_pct()
        if pct >= threshold_pct:
            return (
                f"LLM budget {pct:.0f}% utilized (${self.total_llm_cost_usd:.2f} "
                f"of ${self.max_llm_cost_usd:.2f}). Consider reducing depth or stopping."
            )
        return None

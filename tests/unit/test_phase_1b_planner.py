"""Tests for Phase 1 PR B: planner orchestrator.

PR B operationalises the CampaignPlannerAgent + adds the
``--plan-only`` CLI flag. The orchestrator in
``nexusrecon.strategy.planner`` is the single seam every test
here exercises: it owns prompt construction, response parsing,
fallback behavior, and the strategy-history audit hook.

Coverage
- :func:`plan_campaign` returns a parsed :class:`Strategy`
  when the planner LLM produces well-formed JSON.
- Code-fenced + plain JSON object responses both parse.
- Unknown phase identifiers in the planner response are
  dropped silently (don't crash the campaign on a
  hallucinated phase name).
- Unknown ``dispatch_policy_name`` values fall back to
  ``lite`` (matches :func:`get_policy`'s posture so the
  written strategy agrees with what the dispatcher would
  resolve later).
- Planner failures (exception in ``run_agent``, malformed
  JSON, missing required fields) degrade to
  :meth:`Strategy.default` with ``metadata.
  planner_response_kind == "fallback"`` so the audit trail
  records the planner ran but didn't yield a usable result.
- The strategy-history audit hook fires when ``state`` is
  passed in.
- :func:`replan` produces a new strategy and tags the history
  record with the operator-supplied reason.
"""
from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest

from nexusrecon.strategy import Strategy, plan_campaign, replan


# ──────────────────────────────────────────────────────────────────────
# Test doubles
# ──────────────────────────────────────────────────────────────────────


class _FakeExecutor:
    """Minimal AgentExecutor double — captures the prompt the
    planner saw + returns a scripted response."""

    def __init__(self, response: str, raise_on_run: Exception | None = None):
        self._response = response
        self._raise = raise_on_run
        self.captured_calls: list[dict[str, Any]] = []

    async def run_agent(
        self,
        agent_name: str,
        task_data: dict[str, Any],
        task_prompt: str,
        state: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        self.captured_calls.append({
            "agent_name": agent_name,
            "task_data": task_data,
            "task_prompt": task_prompt,
            "state_passed": state is not None,
        })
        if self._raise is not None:
            raise self._raise
        return {"output": self._response, "agent": agent_name}


def _well_formed_response(
    *,
    name: str = "structured_plan",
    phases: list[str] | None = None,
    dispatch_policy_name: str = "full",
    extras: dict[str, Any] | None = None,
) -> str:
    """A code-fenced JSON response that exercises every
    coercion path. ``extras`` overlays/overrides top-level keys."""
    body: dict[str, Any] = {
        "name": name,
        "rationale": "Picked full mode because seeds are wide-cast.",
        "phases": phases or ["phase1", "phase4", "phase7", "phase8"],
        "dispatch_policy_name": dispatch_policy_name,
        "tool_budgets": {"shodan": 10, "category:cloud": 25},
        "success_criteria": [
            {
                "metric": "confirmed_leads",
                "op": ">=",
                "threshold": 5,
                "description": "Five confirmed leads = engagement done.",
            },
        ],
        "kill_criteria": [
            {
                "metric": "llm_cost_usd",
                "op": ">",
                "threshold": 20.0,
                "action": "abort",
                "description": "Hard ceiling — abort on overrun.",
            },
        ],
    }
    if extras:
        body.update(extras)
    return f"Here's the plan:\n```json\n{json.dumps(body)}\n```\nThat should cover it."


# ──────────────────────────────────────────────────────────────────────
# Happy path
# ──────────────────────────────────────────────────────────────────────


class TestPlanCampaignSuccess:
    @pytest.mark.asyncio
    async def test_returns_parsed_strategy(self):
        executor = _FakeExecutor(_well_formed_response())
        strategy = await plan_campaign(
            scope_summary="acme.com, T1, stealth=medium",
            seeds=["acme.com"],
            mode="medium",
            dispatch_policy_name="lite",
            executor=executor,
        )
        assert strategy.name == "structured_plan"
        assert strategy.dispatch_policy_name == "full"
        assert "phase1" in strategy.phases
        assert "phase4" in strategy.phases
        assert strategy.tool_budgets["shodan"] == 10
        assert len(strategy.success_criteria) == 1
        assert strategy.success_criteria[0].metric == "confirmed_leads"
        assert len(strategy.kill_criteria) == 1
        assert strategy.kill_criteria[0].action == "abort"
        # Operator metadata captured verbatim for audit.
        assert strategy.metadata["planner_operator_inputs"]["mode"] == "medium"
        assert strategy.metadata["planner_response_kind"] == "structured"
        assert "Picked full mode" in strategy.metadata["planner_rationale"]

    @pytest.mark.asyncio
    async def test_prompt_includes_operator_inputs(self):
        executor = _FakeExecutor(_well_formed_response())
        await plan_campaign(
            scope_summary="acme.com",
            seeds=["acme.com", "acme.io"],
            mode="deep",
            dispatch_policy_name="full",
            max_llm_cost_usd=15.25,
            executor=executor,
        )
        prompt = executor.captured_calls[0]["task_prompt"]
        assert "acme.com" in prompt
        assert "acme.io" in prompt
        assert "deep" in prompt
        assert "15.25" in prompt
        # Strict-JSON contract surfaced to the planner.
        assert "success_criteria" in prompt
        assert "kill_criteria" in prompt

    @pytest.mark.asyncio
    async def test_parses_plain_json_without_code_fence(self):
        body = {
            "name": "no_fence",
            "phases": ["phase1", "phase2"],
            "dispatch_policy_name": "lite",
        }
        executor = _FakeExecutor(
            f"some preamble {json.dumps(body)} some trailing chatter",
        )
        strategy = await plan_campaign(
            scope_summary="s",
            seeds=["x.com"],
            mode="light",
            executor=executor,
        )
        assert strategy.name == "no_fence"
        assert strategy.phases == ["phase1", "phase2"]


# ──────────────────────────────────────────────────────────────────────
# Coercion / validation
# ──────────────────────────────────────────────────────────────────────


class TestCoercion:
    @pytest.mark.asyncio
    async def test_unknown_phase_identifiers_dropped(self):
        executor = _FakeExecutor(_well_formed_response(
            phases=["phase1", "phase99", "phaseX", "phase4"],
        ))
        strategy = await plan_campaign(
            scope_summary="s", seeds=["x"],
            mode="medium", executor=executor,
        )
        assert "phase1" in strategy.phases
        assert "phase4" in strategy.phases
        assert "phase99" not in strategy.phases
        assert "phaseX" not in strategy.phases

    @pytest.mark.asyncio
    async def test_empty_phases_after_filter_falls_back_to_canonical(self):
        executor = _FakeExecutor(_well_formed_response(
            phases=["phaseAlpha", "phaseBeta"],  # all invalid
        ))
        strategy = await plan_campaign(
            scope_summary="s", seeds=["x"],
            mode="medium", executor=executor,
        )
        # Should land on the canonical default order rather
        # than running zero phases.
        assert "phase1" in strategy.phases
        assert "phase9" in strategy.phases

    @pytest.mark.asyncio
    async def test_unknown_dispatch_policy_name_falls_back_to_lite(self):
        executor = _FakeExecutor(_well_formed_response(
            dispatch_policy_name="aggressive",  # not registered
        ))
        strategy = await plan_campaign(
            scope_summary="s", seeds=["x"],
            mode="medium", executor=executor,
        )
        assert strategy.dispatch_policy_name == "lite"

    @pytest.mark.asyncio
    async def test_kill_criterion_with_bad_action_becomes_pause(self):
        executor = _FakeExecutor(_well_formed_response(extras={
            "kill_criteria": [
                {"metric": "x", "op": ">", "threshold": 1, "action": "nuke"},
            ],
        }))
        strategy = await plan_campaign(
            scope_summary="s", seeds=["x"],
            mode="medium", executor=executor,
        )
        assert strategy.kill_criteria[0].action == "pause_for_review"

    @pytest.mark.asyncio
    async def test_malformed_criteria_dropped(self):
        executor = _FakeExecutor(_well_formed_response(extras={
            "success_criteria": [
                {"metric": "x", "op": ">=", "threshold": 1},  # valid
                {"op": ">", "threshold": 1},                   # missing metric
                "not a dict",                                  # garbage
            ],
        }))
        strategy = await plan_campaign(
            scope_summary="s", seeds=["x"],
            mode="medium", executor=executor,
        )
        assert len(strategy.success_criteria) == 1

    @pytest.mark.asyncio
    async def test_negative_tool_budgets_dropped(self):
        executor = _FakeExecutor(_well_formed_response(extras={
            "tool_budgets": {"valid": 5, "broken": -1, "string": "abc"},
        }))
        strategy = await plan_campaign(
            scope_summary="s", seeds=["x"],
            mode="medium", executor=executor,
        )
        assert strategy.tool_budgets == {"valid": 5}


# ──────────────────────────────────────────────────────────────────────
# Fallback behavior
# ──────────────────────────────────────────────────────────────────────


class TestFallback:
    @pytest.mark.asyncio
    async def test_executor_exception_yields_fallback_strategy(self):
        executor = _FakeExecutor(
            "irrelevant",
            raise_on_run=RuntimeError("LLM unreachable"),
        )
        strategy = await plan_campaign(
            scope_summary="s", seeds=["x"],
            mode="medium", executor=executor,
        )
        assert strategy.metadata["planner_response_kind"] == "fallback"
        assert "LLM unreachable" in strategy.metadata["planner_fallback_reason"]
        # Default phases + lite policy preserved.
        assert strategy.dispatch_policy_name == "lite"
        assert "phase1" in strategy.phases

    @pytest.mark.asyncio
    async def test_malformed_response_yields_fallback(self):
        executor = _FakeExecutor("this is not JSON at all !!!@@#$")
        strategy = await plan_campaign(
            scope_summary="s", seeds=["x"],
            mode="medium", executor=executor,
        )
        assert strategy.metadata["planner_response_kind"] == "fallback"
        assert strategy.metadata["planner_fallback_reason"] == "parse_failure"
        # Raw output captured (truncated) for audit forensics.
        assert "planner_raw_output" in strategy.metadata

    @pytest.mark.asyncio
    async def test_no_executor_no_config_yields_fallback(self, monkeypatch):
        """When ``executor`` isn't passed and config can't build
        one, the planner degrades gracefully instead of
        crashing the campaign launch."""
        import nexusrecon.strategy.planner as planner_mod

        # Force the executor constructor path to raise.
        def _boom(*_a, **_kw):
            raise RuntimeError("no config")
        monkeypatch.setattr(
            "nexusrecon.core.config.get_config", _boom, raising=False,
        )

        strategy = await plan_campaign(
            scope_summary="s", seeds=["x"], mode="medium",
        )
        assert strategy.metadata["planner_response_kind"] == "fallback"
        assert strategy.metadata["planner_fallback_reason"] == "no_executor"


# ──────────────────────────────────────────────────────────────────────
# Strategy-history audit hook
# ──────────────────────────────────────────────────────────────────────


class TestStrategyHistory:
    @pytest.mark.asyncio
    async def test_state_passed_appends_initial_history_record(self):
        executor = _FakeExecutor(_well_formed_response())
        state: dict[str, Any] = {"strategy_history": []}
        strategy = await plan_campaign(
            scope_summary="s", seeds=["x"],
            mode="medium", executor=executor, state=state,
        )
        history = state["strategy_history"]
        assert len(history) == 1
        record = history[0]
        assert record["reason"] == "initial"
        assert record["strategy"]["name"] == strategy.name
        assert "timestamp" in record

    @pytest.mark.asyncio
    async def test_state_omitted_does_not_touch_history(self):
        executor = _FakeExecutor(_well_formed_response())
        await plan_campaign(
            scope_summary="s", seeds=["x"],
            mode="medium", executor=executor,
        )
        # No state passed → no side effects to chase here; the
        # absence of an exception is the assertion.

    @pytest.mark.asyncio
    async def test_replan_overwrites_last_reason(self):
        executor = _FakeExecutor(_well_formed_response())
        state: dict[str, Any] = {
            "strategy_history": [],
            "seeds": ["acme.com"],
            "campaign_mode": "deep",
            "dispatch_policy_name": "full",
            "max_llm_cost_usd": 12.0,
            "scope_summary": "acme.com summary",
        }
        new_strategy = await replan(
            state, reason="new high-value finding", executor=executor,
        )
        assert isinstance(new_strategy, Strategy)
        history = state["strategy_history"]
        assert len(history) == 1
        assert history[-1]["reason"].startswith("replan: ")
        assert "new high-value finding" in history[-1]["reason"]


# ──────────────────────────────────────────────────────────────────────
# Smoke: package __init__ surface
# ──────────────────────────────────────────────────────────────────────


class TestPackageSurface:
    def test_public_symbols_exposed(self):
        from nexusrecon import strategy as s
        assert hasattr(s, "plan_campaign")
        assert hasattr(s, "replan")
        assert hasattr(s, "Strategy")
        assert hasattr(s, "DispatchPolicy")

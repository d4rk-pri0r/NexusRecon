"""Tests for Phase 1 PR C: Simulation & What-If.

PR C introduces a synchronous, cheap (<100ms) forecaster that
runs over a validated dispatch plan and produces a
:class:`SimulationResult`. The dispatcher hooks it in between
validation and execution, always records the result to
``state["simulation_log"]``, and optionally aborts execution
when ``state["simulation_gating"]`` is set + the simulator
recommends ``abort``.

Coverage
- Cost estimate sums per-tool ``cost_per_run_usd``.
- Expected graph growth comes from the per-category heuristic
  (and a per-tool ``expected_new_nodes_per_run`` override
  wins when set).
- ``tier_exceeds_scope`` flag fires when a tool's tier > the
  scope's ``max_tier``.
- ``pivot_to_new_target`` flag fires when the target isn't
  in the graph's known entities.
- Confidence falls when many tools lack a cost field.
- Recommendation logic: tier_exceeds_scope → abort, high cost
  fraction → warn, pivot → warn, otherwise proceed.
- Empty plan returns a sensible empty result.
- :func:`append_simulation_log` writes the record + decision.
- Dispatcher integration: simulation is recorded after a
  successful execute; gating aborts (only when opt-in is
  set) while producing the same audit record with
  ``decision == "aborted_by_gate"``.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from nexusrecon.strategy.simulation import (
    SimulationResult,
    _DEFAULT_EXPECTED_NEW_NODES,
    _EXPECTED_NEW_NODES_PER_TOOL,
    append_simulation_log,
    simulate_dispatch_plan,
)


# ──────────────────────────────────────────────────────────────────────
# Test doubles
# ──────────────────────────────────────────────────────────────────────


@dataclass
class _FakeCategory:
    value: str


@dataclass
class _FakeTool:
    name: str
    tier: str = "T0"
    category_value: str = "subdomain"
    cost_per_run_usd: float = 0.0
    avg_runtime_sec: int = 30
    expected_new_nodes_per_run: int | None = None

    @property
    def category(self) -> _FakeCategory:
        return _FakeCategory(self.category_value)


class _FakeRegistry:
    def __init__(self, tools: dict[str, _FakeTool]):
        self._tools = tools

    def get(self, name: str) -> _FakeTool | None:
        return self._tools.get(name)


def _plan_item(
    tool: str = "subfinder",
    target: str = "acme.com",
    target_type: str = "domain",
    reason: str = "trigger hint matched",
) -> dict[str, Any]:
    return {
        "tool": tool, "target": target,
        "target_type": target_type, "reason": reason,
    }


# ──────────────────────────────────────────────────────────────────────
# Cost estimation
# ──────────────────────────────────────────────────────────────────────


class TestCostEstimate:
    def test_sums_per_tool_cost(self):
        registry = _FakeRegistry({
            "subfinder": _FakeTool("subfinder", cost_per_run_usd=0.0),
            "shodan":    _FakeTool("shodan",    cost_per_run_usd=0.5,
                                   category_value="infrastructure"),
            "hunter":    _FakeTool("hunter",    cost_per_run_usd=0.25,
                                   category_value="email"),
        })
        plan = [
            _plan_item("subfinder", "acme.com", "domain"),
            _plan_item("shodan",    "1.2.3.4",  "ip"),
            _plan_item("hunter",    "acme.com", "domain"),
        ]
        result = simulate_dispatch_plan(plan, registry=registry)
        assert result.estimated_cost_usd == pytest.approx(0.75)
        assert result.plan_size == 3

    def test_zero_cost_tools_dont_inflate_total(self):
        registry = _FakeRegistry({
            "subfinder": _FakeTool("subfinder", cost_per_run_usd=0.0),
        })
        plan = [_plan_item("subfinder", "acme.com", "domain")] * 5
        result = simulate_dispatch_plan(plan, registry=registry)
        assert result.estimated_cost_usd == 0.0

    def test_runtime_aggregates_avg_runtime_sec(self):
        registry = _FakeRegistry({
            "fast": _FakeTool("fast", avg_runtime_sec=5),
            "slow": _FakeTool("slow", avg_runtime_sec=120),
        })
        result = simulate_dispatch_plan(
            [_plan_item("fast", "x", "domain"),
             _plan_item("slow", "y", "domain")],
            registry=registry,
        )
        assert result.estimated_runtime_sec == 125


# ──────────────────────────────────────────────────────────────────────
# Graph growth heuristic
# ──────────────────────────────────────────────────────────────────────


class TestExpectedNewNodes:
    def test_uses_category_heuristic(self):
        registry = _FakeRegistry({
            "sub":   _FakeTool("sub",   category_value="subdomain"),
            "email": _FakeTool("email", category_value="email"),
            "vuln":  _FakeTool("vuln",  category_value="vulnerability"),
        })
        plan = [
            _plan_item("sub", "a.com", "domain"),
            _plan_item("email", "a.com", "domain"),
            _plan_item("vuln", "a.com", "domain"),
        ]
        result = simulate_dispatch_plan(plan, registry=registry)
        expected_total = (
            _EXPECTED_NEW_NODES_PER_TOOL["subdomain"]
            + _EXPECTED_NEW_NODES_PER_TOOL["email"]
            + _EXPECTED_NEW_NODES_PER_TOOL["vulnerability"]
        )
        assert result.expected_new_nodes == expected_total

    def test_per_tool_override_wins(self):
        registry = _FakeRegistry({
            "tuned": _FakeTool(
                "tuned", category_value="subdomain",
                # Override beats the category default (25).
                expected_new_nodes_per_run=2,
            ),
        })
        result = simulate_dispatch_plan(
            [_plan_item("tuned", "a.com", "domain")],
            registry=registry,
        )
        assert result.expected_new_nodes == 2

    def test_unknown_category_falls_back_to_default(self):
        registry = _FakeRegistry({
            "weird": _FakeTool("weird", category_value="unmapped_category"),
        })
        result = simulate_dispatch_plan(
            [_plan_item("weird", "x", "domain")],
            registry=registry,
        )
        assert result.expected_new_nodes == _DEFAULT_EXPECTED_NEW_NODES

    def test_breakdown_groups_by_category(self):
        registry = _FakeRegistry({
            "sub1": _FakeTool("sub1", category_value="subdomain"),
            "sub2": _FakeTool("sub2", category_value="subdomain"),
            "em":   _FakeTool("em",   category_value="email"),
        })
        plan = [
            _plan_item("sub1", "a", "domain"),
            _plan_item("sub2", "b", "domain"),
            _plan_item("em",   "c", "domain"),
        ]
        result = simulate_dispatch_plan(plan, registry=registry)
        assert result.expected_new_nodes_by_category["subdomain"] == (
            2 * _EXPECTED_NEW_NODES_PER_TOOL["subdomain"]
        )
        assert result.expected_new_nodes_by_category["email"] == (
            _EXPECTED_NEW_NODES_PER_TOOL["email"]
        )


# ──────────────────────────────────────────────────────────────────────
# Scope-creep flags
# ──────────────────────────────────────────────────────────────────────


class TestScopeCreepFlags:
    def test_tier_exceeds_scope_flag(self):
        registry = _FakeRegistry({
            "aggressive": _FakeTool(
                "aggressive", tier="T3", category_value="infrastructure",
            ),
        })
        result = simulate_dispatch_plan(
            [_plan_item("aggressive", "x", "domain")],
            registry=registry,
            scope_max_tier="T1",
        )
        kinds = {f["kind"] for f in result.scope_creep_flags}
        assert "tier_exceeds_scope" in kinds

    def test_no_tier_flag_when_within_scope(self):
        registry = _FakeRegistry({
            "safe": _FakeTool("safe", tier="T0"),
        })
        result = simulate_dispatch_plan(
            [_plan_item("safe", "x", "domain")],
            registry=registry,
            scope_max_tier="T2",
        )
        kinds = {f["kind"] for f in result.scope_creep_flags}
        assert "tier_exceeds_scope" not in kinds

    def test_pivot_flag_when_target_not_in_graph(self):
        registry = _FakeRegistry({
            "sub": _FakeTool("sub", category_value="subdomain"),
        })
        state = {
            "seeds": ["acme.com"],
            "entity_graph": {
                "nodes": [
                    {"id": "acme.com", "value": "acme.com"},
                ],
            },
        }
        result = simulate_dispatch_plan(
            [_plan_item("sub", "competitor.com", "domain")],
            state=state, registry=registry,
        )
        kinds = {f["kind"] for f in result.scope_creep_flags}
        assert "pivot_to_new_target" in kinds

    def test_no_pivot_flag_for_known_targets(self):
        registry = _FakeRegistry({
            "sub": _FakeTool("sub", category_value="subdomain"),
        })
        state = {
            "seeds": ["acme.com"],
            "entity_graph": {
                "nodes": [{"id": "acme.com", "value": "acme.com"}],
            },
        }
        result = simulate_dispatch_plan(
            [_plan_item("sub", "acme.com", "domain")],
            state=state, registry=registry,
        )
        kinds = {f["kind"] for f in result.scope_creep_flags}
        assert "pivot_to_new_target" not in kinds


# ──────────────────────────────────────────────────────────────────────
# Confidence
# ──────────────────────────────────────────────────────────────────────


class TestConfidence:
    def test_high_confidence_when_costs_known(self):
        registry = _FakeRegistry({
            "a": _FakeTool("a", cost_per_run_usd=0.1),
            "b": _FakeTool("b", cost_per_run_usd=0.2),
        })
        result = simulate_dispatch_plan(
            [_plan_item("a", "x", "domain"), _plan_item("b", "y", "domain")],
            registry=registry,
        )
        assert result.confidence == "high"

    def test_low_confidence_when_most_costs_missing(self):
        registry = _FakeRegistry({
            "a": _FakeTool("a", cost_per_run_usd=0.0),
            "b": _FakeTool("b", cost_per_run_usd=0.0),
            "c": _FakeTool("c", cost_per_run_usd=0.0),
            "d": _FakeTool("d", cost_per_run_usd=0.0),
        })
        plan = [
            _plan_item("a", "x", "domain"),
            _plan_item("b", "y", "domain"),
            _plan_item("c", "z", "domain"),
            _plan_item("d", "w", "domain"),
        ]
        result = simulate_dispatch_plan(plan, registry=registry)
        assert result.confidence == "low"


# ──────────────────────────────────────────────────────────────────────
# Recommendation
# ──────────────────────────────────────────────────────────────────────


class TestRecommendation:
    def test_abort_on_tier_violation(self):
        registry = _FakeRegistry({
            "loud": _FakeTool("loud", tier="T3"),
        })
        result = simulate_dispatch_plan(
            [_plan_item("loud", "x", "domain")],
            registry=registry, scope_max_tier="T1",
        )
        assert result.recommendation == "abort"
        assert "scope" in result.rationale.lower()

    def test_warn_on_high_cost_fraction(self):
        registry = _FakeRegistry({
            "pricey": _FakeTool("pricey", cost_per_run_usd=5.0),
        })
        # state budget of 10.0 → 25% threshold is 2.50; 5.0 > 2.50
        state = {"max_llm_cost_usd": 10.0}
        result = simulate_dispatch_plan(
            [_plan_item("pricey", "x", "domain")],
            state=state, registry=registry,
        )
        assert result.recommendation == "warn"
        assert "budget" in result.rationale.lower()

    def test_warn_on_pivot(self):
        registry = _FakeRegistry({
            "sub": _FakeTool("sub", category_value="subdomain"),
        })
        state = {
            "seeds": ["acme.com"],
            "entity_graph": {"nodes": [{"id": "acme.com"}]},
        }
        result = simulate_dispatch_plan(
            [_plan_item("sub", "new-target.com", "domain")],
            state=state, registry=registry,
        )
        assert result.recommendation == "warn"
        assert "pivot" in result.rationale.lower()

    def test_proceed_when_clean(self):
        registry = _FakeRegistry({
            "safe": _FakeTool("safe", tier="T0", cost_per_run_usd=0.01,
                              category_value="subdomain"),
        })
        state = {
            "seeds": ["acme.com"],
            "entity_graph": {
                "nodes": [{"id": "acme.com", "value": "acme.com"}],
            },
            "max_llm_cost_usd": 100.0,
        }
        result = simulate_dispatch_plan(
            [_plan_item("safe", "acme.com", "domain")],
            state=state, registry=registry, scope_max_tier="T2",
        )
        assert result.recommendation == "proceed"


# ──────────────────────────────────────────────────────────────────────
# Edge cases
# ──────────────────────────────────────────────────────────────────────


class TestEdgeCases:
    def test_empty_plan_returns_zeros(self):
        registry = _FakeRegistry({})
        result = simulate_dispatch_plan([], registry=registry)
        assert result.plan_size == 0
        assert result.estimated_cost_usd == 0.0
        assert result.expected_new_nodes == 0
        assert result.recommendation == "proceed"

    def test_unknown_tool_flagged_but_doesnt_crash(self):
        registry = _FakeRegistry({})
        result = simulate_dispatch_plan(
            [_plan_item("phantom", "x", "domain")],
            registry=registry,
        )
        assert result.plan_size == 1
        assert result.items[0].flags == ["unknown_tool"]


# ──────────────────────────────────────────────────────────────────────
# Audit log
# ──────────────────────────────────────────────────────────────────────


class TestAuditLog:
    def test_appends_with_decision(self):
        registry = _FakeRegistry({
            "safe": _FakeTool("safe", cost_per_run_usd=0.01),
        })
        result = simulate_dispatch_plan(
            [_plan_item("safe", "x", "domain")],
            registry=registry,
        )
        state: dict[str, Any] = {}
        append_simulation_log(state, result, decision="executed")
        log_entries = state["simulation_log"]
        assert len(log_entries) == 1
        assert log_entries[0]["decision"] == "executed"
        assert log_entries[0]["plan_size"] == 1

    def test_serialisation_preserves_shape(self):
        registry = _FakeRegistry({
            "safe": _FakeTool("safe", cost_per_run_usd=0.5,
                              tier="T1", category_value="subdomain"),
        })
        result = simulate_dispatch_plan(
            [_plan_item("safe", "x", "domain")],
            registry=registry,
        )
        d = result.to_dict()
        # Critical fields downstream forensics tools rely on.
        for key in (
            "plan_size", "estimated_cost_usd", "estimated_runtime_sec",
            "expected_new_nodes", "expected_new_nodes_by_category",
            "scope_creep_flags", "items", "recommendation",
            "rationale", "confidence", "timestamp",
        ):
            assert key in d


# ──────────────────────────────────────────────────────────────────────
# Dispatcher integration
# ──────────────────────────────────────────────────────────────────────


class TestDispatcherIntegration:
    """The simulator must (a) always log alongside actual
    dispatch, and (b) only short-circuit execution when the
    operator opts in via ``state["simulation_gating"]``."""

    @pytest.mark.asyncio
    async def test_gate_aborts_when_opt_in_and_simulation_aborts(self):
        from nexusrecon.graph import dynamic_dispatcher as dd

        # Construct a state that yields a "abort" recommendation.
        # We use a phase eligible for lite dispatch so the
        # per-phase gate doesn't pre-empt the simulator gate.
        state: dict[str, Any] = {
            "dispatch_mode": "full",
            "current_phase": "phase1",
            "seeds": ["acme.com"],
            "scope_max_tier": "T0",
            "simulation_gating": True,
            "dynamic_dispatch_log": [],
            "max_llm_cost_usd": 100.0,
        }

        # Mock the LLM call to return a plan with a T3 tool —
        # that flips simulator → abort.
        with patch(
            "nexusrecon.graph.dynamic_dispatcher._build_dispatch_prompt",
            return_value="prompt",
        ), patch(
            "nexusrecon.agents.dynamic_dispatcher.DISPATCHER_SYSTEM_PROMPT",
            "",
            create=True,
        ), patch(
            "nexusrecon.core.config.get_config",
            return_value=MagicMock(),
        ), patch(
            "nexusrecon.graph.agent_executor.get_llm_from_config",
        ) as mock_get_llm, patch(
            "nexusrecon.graph.dynamic_dispatcher._validate_plan",
            return_value=[_plan_item(
                "aggressive_tool", "acme.com", "domain",
            )],
        ), patch.object(
            dd, "_resolve_policy",
            return_value=type("P", (), {
                "name": "full", "max_per_cycle": 5, "max_total": 50,
                "should_dispatch_for_phase": lambda self, p: True,
            })(),
        ):
            mock_llm = MagicMock()
            mock_llm.invoke.return_value = MagicMock(content="[{}]")
            mock_get_llm.return_value = mock_llm

            # Make the registry return a T3 tool for the
            # validated plan item.
            registry_mock = MagicMock()
            tool_mock = MagicMock()
            tool_mock.tier = "T3"
            tool_mock.cost_per_run_usd = 0.0
            tool_mock.avg_runtime_sec = 30
            tool_mock.category.value = "subdomain"
            tool_mock.expected_new_nodes_per_run = None
            registry_mock.get.return_value = tool_mock
            registry_mock.available_tools.return_value = []

            with patch(
                "nexusrecon.tools.registry.get_registry",
                return_value=registry_mock,
            ):
                result_state = await dd.run_dynamic_dispatch(state)

        # No execution → log unchanged…
        assert result_state["dynamic_dispatch_log"] == []
        # …and the simulation record is present with the gate
        # decision marker.
        sim_log = result_state["simulation_log"]
        assert len(sim_log) == 1
        assert sim_log[0]["decision"] == "aborted_by_gate"
        assert sim_log[0]["recommendation"] == "abort"

    @pytest.mark.asyncio
    async def test_no_gate_means_warn_and_proceed(self):
        """Without ``simulation_gating`` the simulator's
        recommendation is advisory — execution still happens
        and the simulation is recorded with
        ``decision == "executed"``."""
        from nexusrecon.graph import dynamic_dispatcher as dd

        state: dict[str, Any] = {
            "dispatch_mode": "full",
            "current_phase": "phase1",
            "seeds": ["acme.com"],
            "scope_max_tier": "T0",
            # No simulation_gating: gate is off.
            "dynamic_dispatch_log": [],
            "max_llm_cost_usd": 100.0,
        }

        with patch(
            "nexusrecon.graph.dynamic_dispatcher._build_dispatch_prompt",
            return_value="prompt",
        ), patch(
            "nexusrecon.agents.dynamic_dispatcher.DISPATCHER_SYSTEM_PROMPT",
            "", create=True,
        ), patch(
            "nexusrecon.core.config.get_config",
            return_value=MagicMock(),
        ), patch(
            "nexusrecon.graph.agent_executor.get_llm_from_config",
        ) as mock_get_llm, patch(
            "nexusrecon.graph.dynamic_dispatcher._validate_plan",
            return_value=[_plan_item("aggressive_tool", "acme.com", "domain")],
        ), patch(
            "nexusrecon.graph.dynamic_dispatcher._execute_plan",
        ) as mock_execute, patch.object(
            dd, "_resolve_policy",
            return_value=type("P", (), {
                "name": "full", "max_per_cycle": 5, "max_total": 50,
                "should_dispatch_for_phase": lambda self, p: True,
            })(),
        ):
            mock_llm = MagicMock()
            mock_llm.invoke.return_value = MagicMock(content="[{}]")
            mock_get_llm.return_value = mock_llm

            async def _fake_exec(plan, state):
                return state
            mock_execute.side_effect = _fake_exec

            registry_mock = MagicMock()
            tool_mock = MagicMock()
            tool_mock.tier = "T3"  # would still flag abort…
            tool_mock.cost_per_run_usd = 0.0
            tool_mock.avg_runtime_sec = 30
            tool_mock.category.value = "subdomain"
            tool_mock.expected_new_nodes_per_run = None
            registry_mock.get.return_value = tool_mock
            registry_mock.available_tools.return_value = []

            with patch(
                "nexusrecon.tools.registry.get_registry",
                return_value=registry_mock,
            ):
                result_state = await dd.run_dynamic_dispatch(state)

        # …but execution still ran because gating is off.
        mock_execute.assert_called_once()
        sim_log = result_state["simulation_log"]
        assert len(sim_log) == 1
        assert sim_log[0]["decision"] == "executed"

"""Tests for Phase 1 PR D: strategic audit surface + advanced
bounded-agency primitives.

PR D ships two related pieces:

1. New :class:`~nexusrecon.core.audit.AuditLog` methods for
   every strategic decision: ``log_strategy_generated``,
   ``log_strategy_replan``, ``log_dispatch_policy_resolved``,
   ``log_simulation``, ``log_deep_pivot_grant``,
   ``log_human_approval_queued``, ``log_human_approval_decision``.
   Each writes a hash-chained entry through ``_append_raw``.
2. :mod:`nexusrecon.strategy.bounded_agency` — primitives the
   dispatcher uses to route plan items: ``route_plan_items``
   (split execute / deep-pivot / human-approval),
   ``queue_for_approval`` + ``resolve_approval`` (the queue
   state machine), and ``resolve_pivot_policy`` (per-item
   policy escalation that refuses to *narrow* agency).

Plus dispatcher integration: the new audit methods are
called at the right points, deep-pivot items still execute
(audit is observability, not gating), and human-approval
items land in ``state["pending_approvals"]`` instead of being
executed.

Coverage
- Audit hash chain stays intact across new event types
  (``verify_chain`` returns True).
- ``route_plan_items`` correctly splits a mixed plan.
- Queue/approve/reject state machine.
- Pivot policy resolution refuses to narrow.
- Dispatcher routes human-approval items off the execution
  path; deep-pivot items still execute.
- All new audit hooks fire when AuditLog is bound.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from nexusrecon.core.audit import AuditLog
from nexusrecon.strategy.bounded_agency import (
    queue_for_approval,
    resolve_approval,
    resolve_pivot_policy,
    route_plan_items,
)


# ──────────────────────────────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────────────────────────────


@pytest.fixture
def temp_audit() -> AuditLog:
    """Audit log in a tempdir — verify_chain works against the
    actual JSONL output."""
    with tempfile.TemporaryDirectory() as tmp:
        log = AuditLog(
            Path(tmp) / "audit.jsonl",
            campaign_id="cmp-test",
            scope_hash="sha256:abc",
        )
        yield log


def _plan_item(**overrides: Any) -> dict[str, Any]:
    base = {
        "tool": "subfinder", "target": "acme.com",
        "target_type": "domain", "reason": "trigger hint matched",
    }
    base.update(overrides)
    return base


# ──────────────────────────────────────────────────────────────────────
# AuditLog: strategic event methods
# ──────────────────────────────────────────────────────────────────────


class TestStrategicAuditMethods:
    def test_log_strategy_generated_writes_entry(self, temp_audit: AuditLog):
        h = temp_audit.log_strategy_generated(
            strategy_name="corp_recon",
            dispatch_policy_name="full",
            phases=["phase1", "phase4"],
            response_kind="structured",
        )
        assert h.startswith("sha256:")
        # Round-trip via the JSONL file to verify the schema
        # downstream consumers will see. ``[-1]`` because the
        # constructor writes an ``audit_log_init`` entry first.
        line = Path(temp_audit.log_path).read_text().strip().splitlines()[-1]
        entry = json.loads(line)
        assert entry["event_type"] == "strategy_generated"
        assert entry["strategy_name"] == "corp_recon"
        assert entry["dispatch_policy_name"] == "full"
        assert entry["phases"] == ["phase1", "phase4"]
        assert entry["response_kind"] == "structured"

    def test_log_strategy_replan(self, temp_audit: AuditLog):
        temp_audit.log_strategy_replan(
            reason="new high-value finding",
            old_name="default",
            new_name="aggressive_pivot",
            new_dispatch_policy_name="full",
        )
        entry = json.loads(
            Path(temp_audit.log_path).read_text().strip().splitlines()[-1]
        )
        assert entry["event_type"] == "strategy_replan"
        assert "new high-value finding" in entry["reason"]
        assert entry["old_strategy_name"] == "default"
        assert entry["new_strategy_name"] == "aggressive_pivot"

    def test_log_dispatch_policy_resolved(self, temp_audit: AuditLog):
        temp_audit.log_dispatch_policy_resolved(
            policy_name="lite", source="strategy",
            current_phase="phase4", eligible=True,
        )
        entry = json.loads(
            Path(temp_audit.log_path).read_text().strip().splitlines()[-1]
        )
        assert entry["event_type"] == "dispatch_policy_resolved"
        assert entry["source"] == "strategy"
        assert entry["eligible"] is True

    def test_log_simulation(self, temp_audit: AuditLog):
        temp_audit.log_simulation(
            plan_size=3,
            estimated_cost_usd=0.75,
            expected_new_nodes=42,
            recommendation="warn",
            confidence="high",
            decision="executed",
            flag_kinds=["pivot_to_new_target"],
        )
        entry = json.loads(
            Path(temp_audit.log_path).read_text().strip().splitlines()[-1]
        )
        assert entry["event_type"] == "simulation"
        assert entry["recommendation"] == "warn"
        assert entry["confidence"] == "high"
        assert entry["decision"] == "executed"
        assert entry["flag_kinds"] == ["pivot_to_new_target"]
        assert entry["estimated_cost_usd"] == 0.75

    def test_log_deep_pivot_grant(self, temp_audit: AuditLog):
        temp_audit.log_deep_pivot_grant(
            tool="shodan", target="1.2.3.4",
            granting_policy="lite", override_policy="full",
            rationale="suspicious port pattern warrants depth",
        )
        entry = json.loads(
            Path(temp_audit.log_path).read_text().strip().splitlines()[-1]
        )
        assert entry["event_type"] == "deep_pivot_grant"
        assert entry["granting_policy"] == "lite"
        assert entry["override_policy"] == "full"

    def test_log_human_approval_queued_then_decision(self, temp_audit: AuditLog):
        temp_audit.log_human_approval_queued(
            tool="nuclei", target="https://acme.com",
            reason="active scan against prod endpoint",
            tier="T2", estimated_cost_usd=0.0,
        )
        temp_audit.log_human_approval_decision(
            tool="nuclei", target="https://acme.com",
            approved=True, operator="op-jane",
            notes="approved for off-hours window",
        )
        entries = [
            json.loads(line)
            for line in Path(temp_audit.log_path).read_text().splitlines()
        ]
        assert entries[-2]["event_type"] == "human_approval_queued"
        assert entries[-1]["event_type"] == "human_approval_decision"
        assert entries[-1]["approved"] is True
        assert entries[-1]["operator"] == "op-jane"


class TestAuditChainIntegrity:
    """Phase 1 PR D MUST NOT weaken the hash chain. Every new
    event type still chains correctly and ``verify_chain``
    accepts the resulting log."""

    def test_chain_intact_across_all_new_event_types(self, temp_audit: AuditLog):
        temp_audit.log_strategy_generated(
            strategy_name="x", dispatch_policy_name="lite",
            phases=["phase1"], response_kind="structured",
        )
        temp_audit.log_dispatch_policy_resolved(
            policy_name="lite", source="strategy",
            current_phase="phase1", eligible=True,
        )
        temp_audit.log_simulation(
            plan_size=1, estimated_cost_usd=0.0,
            expected_new_nodes=5, recommendation="proceed",
            confidence="high", decision="executed",
        )
        temp_audit.log_deep_pivot_grant(
            tool="t", target="x", granting_policy="lite",
            override_policy="full", rationale="r",
        )
        temp_audit.log_human_approval_queued(
            tool="t", target="x", reason="r", tier="T2",
            estimated_cost_usd=0.0,
        )
        temp_audit.log_human_approval_decision(
            tool="t", target="x", approved=False,
            operator="op", notes="",
        )
        temp_audit.log_strategy_replan(
            reason="r", old_name="x", new_name="y",
            new_dispatch_policy_name="full",
        )
        assert temp_audit.verify_chain() is True


# ──────────────────────────────────────────────────────────────────────
# Routing
# ──────────────────────────────────────────────────────────────────────


class TestRoutePlanItems:
    def test_default_items_execute(self):
        plan = [_plan_item(), _plan_item(tool="hunter")]
        decisions = route_plan_items(plan, default_policy_name="lite")
        assert all(d.action == "execute" for d in decisions)
        assert all(
            d.override_policy_name == "lite" for d in decisions
        )

    def test_human_approval_items_routed_to_approval(self):
        plan = [
            _plan_item(),
            _plan_item(
                tool="nuclei",
                requires_human_approval=True,
                approval_reason="active scan",
            ),
            _plan_item(tool="hunter"),
        ]
        decisions = route_plan_items(plan, default_policy_name="lite")
        assert decisions[0].action == "execute"
        assert decisions[1].action == "human_approval"
        assert decisions[1].queue_reason == "active scan"
        assert decisions[2].action == "execute"

    def test_deep_pivot_items_get_override(self):
        plan = [
            _plan_item(
                tool="shodan",
                deep_pivot="full",
                pivot_reason="found suspicious port pattern",
            ),
        ]
        decisions = route_plan_items(plan, default_policy_name="lite")
        assert decisions[0].action == "deep_pivot"
        assert decisions[0].override_policy_name == "full"
        assert "suspicious port" in decisions[0].queue_reason

    def test_human_approval_wins_over_deep_pivot(self):
        """Belt-and-braces: an item asking for both
        capabilities lands in the approval queue (the more
        conservative path). The operator can grant pivot on
        approval."""
        plan = [_plan_item(
            requires_human_approval=True, deep_pivot="full",
        )]
        decisions = route_plan_items(plan, default_policy_name="lite")
        assert decisions[0].action == "human_approval"

    def test_malformed_items_skipped(self):
        decisions = route_plan_items(
            ["not a dict", None, 42, _plan_item()],  # type: ignore[list-item]
            default_policy_name="lite",
        )
        # Only the valid dict survives.
        assert len(decisions) == 1


# ──────────────────────────────────────────────────────────────────────
# Approval queue
# ──────────────────────────────────────────────────────────────────────


class TestApprovalQueue:
    def test_queue_for_approval_appends_record(self):
        state: dict[str, Any] = {}
        queue_for_approval(
            state, _plan_item(tool="nuclei", target="https://x"),
            reason="active scan against prod",
            estimated_cost_usd=0.05,
            tier="T2",
        )
        pending = state["pending_approvals"]
        assert len(pending) == 1
        record = pending[0]
        assert record["tool"] == "nuclei"
        assert record["target"] == "https://x"
        assert record["status"] == "pending"
        assert record["approval_reason"] == "active scan against prod"
        assert record["tier"] == "T2"
        assert record["estimated_cost_usd"] == 0.05
        assert "queued_at" in record

    def test_resolve_approval_approves(self):
        state: dict[str, Any] = {}
        queue_for_approval(
            state, _plan_item(tool="nuclei", target="https://x"),
            reason="r",
        )
        record = resolve_approval(
            state, tool="nuclei", target="https://x",
            approved=True, operator="jane",
        )
        assert record is not None
        assert record["status"] == "approved"
        assert record["resolved_by"] == "jane"
        assert state["pending_approvals"][0]["status"] == "approved"
        assert len(state["approval_log"]) == 1

    def test_resolve_approval_rejects(self):
        state: dict[str, Any] = {}
        queue_for_approval(
            state, _plan_item(tool="nuclei", target="https://x"),
            reason="r",
        )
        record = resolve_approval(
            state, tool="nuclei", target="https://x",
            approved=False, operator="jane",
            notes="not authorized for prod",
        )
        assert record is not None
        assert record["status"] == "rejected"
        assert record["resolution_notes"] == "not authorized for prod"

    def test_resolve_approval_missing_returns_none(self):
        state: dict[str, Any] = {"pending_approvals": []}
        record = resolve_approval(
            state, tool="ghost", target="x",
            approved=True, operator="jane",
        )
        assert record is None

    def test_already_resolved_record_not_re_resolved(self):
        """Approving the same item twice shouldn't double-log
        or flip an approved item to rejected on a second
        rejection call."""
        state: dict[str, Any] = {}
        queue_for_approval(
            state, _plan_item(tool="nuclei", target="x"),
            reason="r",
        )
        resolve_approval(
            state, tool="nuclei", target="x",
            approved=True, operator="jane",
        )
        # Second call: pending list has no "pending"
        # records anymore → returns None.
        second = resolve_approval(
            state, tool="nuclei", target="x",
            approved=False, operator="bob",
        )
        assert second is None
        assert len(state["approval_log"]) == 1


# ──────────────────────────────────────────────────────────────────────
# Deep-pivot policy resolution
# ──────────────────────────────────────────────────────────────────────


class TestResolvePivotPolicy:
    def test_pivot_to_wider_policy_accepted(self):
        policy = resolve_pivot_policy("full", default_policy_name="lite")
        assert policy.name == "full"

    def test_pivot_to_narrower_policy_rejected(self):
        """A deep-pivot can WIDEN agency for one item but can't
        narrow it — narrowing should be a campaign-level
        decision, not an item-level one."""
        policy = resolve_pivot_policy("off", default_policy_name="lite")
        # Stays on lite.
        assert policy.name == "lite"

    def test_same_policy_passthrough(self):
        policy = resolve_pivot_policy("lite", default_policy_name="lite")
        assert policy.name == "lite"


# ──────────────────────────────────────────────────────────────────────
# Dispatcher integration
# ──────────────────────────────────────────────────────────────────────


class TestDispatcherBoundedAgencyIntegration:
    @pytest.mark.asyncio
    async def test_human_approval_item_not_executed(self):
        """When the planner marks an item ``requires_human_approval``,
        the dispatcher MUST queue it (not execute it). The
        ``_execute_plan`` call should receive an empty list (no
        non-approval items in this test plan)."""
        from nexusrecon.graph import dynamic_dispatcher as dd

        state: dict[str, Any] = {
            "dispatch_mode": "full",
            "current_phase": "phase1",
            "seeds": ["acme.com"],
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
            return_value=[_plan_item(
                tool="nuclei", target="https://acme.com",
                requires_human_approval=True,
                approval_reason="active scan",
            )],
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

            # Registry returns a tool so the simulator can find
            # it; audit_log returns None (no campaign context).
            registry_mock = MagicMock()
            tool_mock = MagicMock()
            tool_mock.tier = "T2"
            tool_mock.cost_per_run_usd = 0.0
            tool_mock.avg_runtime_sec = 30
            tool_mock.category.value = "vulnerability"
            tool_mock.expected_new_nodes_per_run = None
            registry_mock.get.return_value = tool_mock
            registry_mock.available_tools.return_value = []
            registry_mock.audit_log = None

            with patch(
                "nexusrecon.tools.registry.get_registry",
                return_value=registry_mock,
            ):
                result_state = await dd.run_dynamic_dispatch(state)

        # No execution path — approval-only plan.
        mock_execute.assert_not_called()
        # Approval queue populated.
        assert len(result_state["pending_approvals"]) == 1
        queued = result_state["pending_approvals"][0]
        assert queued["tool"] == "nuclei"
        assert queued["status"] == "pending"

    @pytest.mark.asyncio
    async def test_deep_pivot_item_still_executes(self):
        """Deep-pivot items execute — the override is recorded
        in the audit log but doesn't change the execution
        path."""
        from nexusrecon.graph import dynamic_dispatcher as dd

        state: dict[str, Any] = {
            "dispatch_mode": "lite",
            "current_phase": "phase1",
            "seeds": ["acme.com"],
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
            return_value=[_plan_item(
                tool="shodan", deep_pivot="full",
                pivot_reason="suspicious port pattern",
            )],
        ), patch(
            "nexusrecon.graph.dynamic_dispatcher._execute_plan",
        ) as mock_execute, patch.object(
            dd, "_resolve_policy",
            return_value=type("P", (), {
                "name": "lite", "max_per_cycle": 5, "max_total": 30,
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
            tool_mock.tier = "T1"
            tool_mock.cost_per_run_usd = 0.0
            tool_mock.avg_runtime_sec = 30
            tool_mock.category.value = "infrastructure"
            tool_mock.expected_new_nodes_per_run = None
            registry_mock.get.return_value = tool_mock
            registry_mock.available_tools.return_value = []
            registry_mock.audit_log = None

            with patch(
                "nexusrecon.tools.registry.get_registry",
                return_value=registry_mock,
            ):
                await dd.run_dynamic_dispatch(state)

        mock_execute.assert_called_once()
        executed_plan = mock_execute.call_args[0][0]
        assert len(executed_plan) == 1
        assert executed_plan[0]["tool"] == "shodan"

    @pytest.mark.asyncio
    async def test_audit_log_strategic_events_fire_when_bound(self):
        """When ``registry.audit_log`` is bound, the dispatcher
        writes the policy-resolved + simulation entries."""
        from nexusrecon.graph import dynamic_dispatcher as dd

        state: dict[str, Any] = {
            "dispatch_mode": "lite",
            "current_phase": "phase1",
            "seeds": ["acme.com"],
            "dynamic_dispatch_log": [],
            "max_llm_cost_usd": 100.0,
        }
        audit_mock = MagicMock()
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
            return_value=[_plan_item()],
        ), patch(
            "nexusrecon.graph.dynamic_dispatcher._execute_plan",
        ) as mock_execute, patch.object(
            dd, "_resolve_policy",
            return_value=type("P", (), {
                "name": "lite", "max_per_cycle": 5, "max_total": 30,
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
            tool_mock.tier = "T0"
            tool_mock.cost_per_run_usd = 0.0
            tool_mock.avg_runtime_sec = 30
            tool_mock.category.value = "subdomain"
            tool_mock.expected_new_nodes_per_run = None
            registry_mock.get.return_value = tool_mock
            registry_mock.available_tools.return_value = []
            registry_mock.audit_log = audit_mock

            # NB patch BOTH module locations: the simulator
            # uses ``nexusrecon.tools.registry.get_registry``
            # (lazy import), the dispatcher binds it at module
            # top so the local rebound name needs its own
            # patch.
            with patch(
                "nexusrecon.tools.registry.get_registry",
                return_value=registry_mock,
            ), patch(
                "nexusrecon.graph.dynamic_dispatcher.get_registry",
                return_value=registry_mock,
            ):
                await dd.run_dynamic_dispatch(state)

        audit_mock.log_dispatch_policy_resolved.assert_called_once()
        audit_mock.log_simulation.assert_called_once()
        # Decision logged as "executed".
        sim_call = audit_mock.log_simulation.call_args
        assert sim_call.kwargs["decision"] == "executed"

"""
Unit tests for the dynamic dispatcher (Move 4).

Acceptance criteria verified:
  AC-2: Bad JSON from LLM → returns empty plan, no crash
  AC-3: Tool name not in registry → skipped and logged, not executed
  AC-1: Off mode  → zero dispatches in dynamic_dispatch_log
  AC-4: Total cap → no more than MAX_TOTAL dispatches across campaign
  AC-5: Per-cycle cap → no more than MAX_PER_CYCLE per reflection_node call
"""
from __future__ import annotations

import asyncio
import json
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from nexusrecon.graph.dynamic_dispatcher import (
    MAX_PER_CYCLE,
    MAX_TOTAL,
    LITE_DISPATCH_PHASES,
    _parse_dispatch_plan,
    _validate_plan,
    run_dynamic_dispatch,
)
from nexusrecon.graph.nodes import reflection_node


# ── Helpers ───────────────────────────────────────────────────────────────────

def _base_state(**overrides: Any) -> Dict[str, Any]:
    """Minimal CampaignGraphState for testing."""
    state: Dict[str, Any] = {
        "seeds": ["acme.com"],
        "current_phase": "phase1",
        "dispatch_mode": "full",
        "dynamic_dispatch_log": [],
        "subdomain_intel": {},
        "email_intel": {"emails": {}},
        "dark_intel": {},
        "cloud_intel": {},
        "code_intel": {},
        "findings": [],
        "hypotheses": [],
    }
    state.update(overrides)
    return state


# ── AC-2: Bad JSON returns empty plan, no crash ───────────────────────────────

class TestParseDispatchPlan:
    """_parse_dispatch_plan must never raise, always return a list."""

    def test_valid_json_array(self):
        raw = '[{"tool": "shodan", "target": "acme.com", "target_type": "domain", "reason": "check"}]'
        result = _parse_dispatch_plan(raw)
        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0]["tool"] == "shodan"

    def test_empty_array(self):
        assert _parse_dispatch_plan("[]") == []

    def test_completely_empty_string(self):
        # AC-2: no crash on bad input
        assert _parse_dispatch_plan("") == []

    def test_prose_wrapping_valid_json(self):
        raw = 'Sure! Here is my plan:\n[{"tool": "dns", "target": "acme.com", "target_type": "domain", "reason": "ok"}]\nDone.'
        result = _parse_dispatch_plan(raw)
        assert len(result) == 1

    def test_truncated_json(self):
        # AC-2: truncated / malformed JSON → empty list, no crash
        assert _parse_dispatch_plan("[{bad json") == []

    def test_non_array_json(self):
        # AC-2: if LLM returns a dict instead of array → empty list
        assert _parse_dispatch_plan('{"tool": "shodan"}') == []

    def test_null_literal(self):
        assert _parse_dispatch_plan("null") == []

    def test_random_text(self):
        assert _parse_dispatch_plan("I cannot help with that request.") == []


# ── AC-3: Unknown tool name skipped ──────────────────────────────────────────

class TestValidatePlan:
    """_validate_plan must skip items whose tool is not in the registry."""

    def test_unknown_tool_skipped(self):
        plan = [
            {"tool": "nonexistent_tool_xyz", "target": "acme.com",
             "target_type": "domain", "reason": "test"},
        ]
        state = _base_state()
        valid = _validate_plan(plan, state)
        # AC-3: unknown tool → result must be empty
        assert valid == []

    def test_known_tool_passes(self):
        # Use a tool we know is always registered (no key required)
        plan = [
            {"tool": "whois", "target": "acme.com",
             "target_type": "domain", "reason": "check registration"},
        ]
        state = _base_state()
        valid = _validate_plan(plan, state)
        assert len(valid) == 1
        assert valid[0]["tool"] == "whois"

    def test_target_type_mismatch_skipped(self):
        # AC-3 variant: tool exists but target_type doesn't match
        plan = [
            {"tool": "whois", "target": "192.0.2.1",
             "target_type": "ip", "reason": "wrong type"},
        ]
        state = _base_state()
        valid = _validate_plan(plan, state)
        assert valid == []

    def test_missing_required_field_skipped(self):
        plan = [{"tool": "whois", "reason": "missing target"}]
        state = _base_state()
        valid = _validate_plan(plan, state)
        assert valid == []

    def test_dedup_already_run(self):
        plan = [
            {"tool": "whois", "target": "acme.com",
             "target_type": "domain", "reason": "check"},
        ]
        state = _base_state(dynamic_dispatch_log=[
            {"tool": "whois", "target": "acme.com", "target_type": "domain",
             "reason": "check", "phase": "phase1", "timestamp": "2026-01-01T00:00:00Z", "success": True},
        ])
        valid = _validate_plan(plan, state)
        assert valid == []

    def test_per_cycle_cap_applied(self):
        # More than MAX_PER_CYCLE items → only MAX_PER_CYCLE returned
        plan = [
            {"tool": "whois", "target": f"sub{i}.acme.com",
             "target_type": "domain", "reason": f"reason {i}"}
            for i in range(MAX_PER_CYCLE + 3)
        ]
        state = _base_state()
        valid = _validate_plan(plan, state)
        assert len(valid) <= MAX_PER_CYCLE


# ── AC-1: Off mode → zero dispatches ─────────────────────────────────────────

class TestReflectionNodeOffMode:
    """reflection_node with dispatch_mode='off' must not touch dynamic_dispatch_log."""

    @pytest.mark.asyncio
    async def test_off_mode_no_dispatch(self):
        state = _base_state(
            current_phase="phase1",
            dispatch_mode="off",
            dynamic_dispatch_log=[],
        )
        result = await reflection_node(state)
        assert result.get("dynamic_dispatch_log", []) == []

    @pytest.mark.asyncio
    async def test_off_mode_does_not_call_llm(self):
        """run_dynamic_dispatch must not be called in off mode."""
        state = _base_state(dispatch_mode="off")
        # Patch at the source module — reflection_node imports from there at call time
        with patch(
            "nexusrecon.graph.dynamic_dispatcher.run_dynamic_dispatch",
            new_callable=AsyncMock,
        ) as mock_dispatch:
            result = await reflection_node(state)
            mock_dispatch.assert_not_called()


# ── AC-4 / AC-5: Budget and per-cycle caps ───────────────────────────────────

class TestDispatchBudgetCaps:
    """Total and per-cycle caps are enforced."""

    @pytest.mark.asyncio
    async def test_total_cap_prevents_dispatch(self):
        """When dispatch_log already has MAX_TOTAL entries, no new dispatch occurs."""
        # Fill the log to capacity
        full_log = [
            {"tool": "whois", "target": f"t{i}.com", "target_type": "domain",
             "reason": "x", "phase": "phase1", "timestamp": "2026-01-01T00:00:00Z", "success": True}
            for i in range(MAX_TOTAL)
        ]
        state = _base_state(dynamic_dispatch_log=full_log, dispatch_mode="full")

        # reflection_node short-circuits via cap check before importing run_dynamic_dispatch,
        # so we verify by outcome: log length is unchanged at MAX_TOTAL.
        result = await reflection_node(state)
        assert len(result.get("dynamic_dispatch_log", [])) == MAX_TOTAL

    @pytest.mark.asyncio
    async def test_run_dynamic_dispatch_respects_total_cap(self):
        """run_dynamic_dispatch itself returns unchanged state when budget gone."""
        full_log = [
            {"tool": "whois", "target": f"t{i}.com", "target_type": "domain",
             "reason": "x", "phase": "phase1", "timestamp": "2026-01-01T00:00:00Z", "success": True}
            for i in range(MAX_TOTAL)
        ]
        state = _base_state(dynamic_dispatch_log=full_log)
        result = await run_dynamic_dispatch(state)
        assert len(result["dynamic_dispatch_log"]) == MAX_TOTAL


# ── AC-2 (integration): Bad LLM JSON doesn't crash run_dynamic_dispatch ───────

class TestBadJsonIntegration:
    """run_dynamic_dispatch must handle a malformed LLM response gracefully."""

    @pytest.mark.asyncio
    async def test_malformed_llm_response_no_crash(self):
        state = _base_state()

        mock_llm = MagicMock()
        mock_llm.invoke.return_value = MagicMock(content="This is not JSON at all! @@##")

        with (
            patch(
                "nexusrecon.core.config.get_config",
                return_value=MagicMock(),
            ),
            patch(
                "nexusrecon.graph.agent_executor.get_llm_from_config",
                return_value=mock_llm,
            ),
        ):
            # AC-2: must not raise
            result = await run_dynamic_dispatch(state)
            # No dispatches logged
            assert result.get("dynamic_dispatch_log", []) == []

    @pytest.mark.asyncio
    async def test_llm_returns_empty_array_no_dispatch(self):
        state = _base_state()

        mock_llm = MagicMock()
        mock_llm.invoke.return_value = MagicMock(content="[]")

        with (
            patch(
                "nexusrecon.core.config.get_config",
                return_value=MagicMock(),
            ),
            patch(
                "nexusrecon.graph.agent_executor.get_llm_from_config",
                return_value=mock_llm,
            ),
        ):
            result = await run_dynamic_dispatch(state)
            assert result.get("dynamic_dispatch_log", []) == []


# ── Lite mode phase gating ────────────────────────────────────────────────────

class TestLiteMode:
    """Lite mode only dispatches for phases in LITE_DISPATCH_PHASES."""

    @pytest.mark.asyncio
    async def test_lite_mode_skips_non_eligible_phase(self):
        state = _base_state(current_phase="phase3", dispatch_mode="lite")
        assert "phase3" not in LITE_DISPATCH_PHASES

        with patch(
            "nexusrecon.graph.dynamic_dispatcher.run_dynamic_dispatch",
            new_callable=AsyncMock,
        ) as mock_rdd:
            result = await reflection_node(state)
            mock_rdd.assert_not_called()

    @pytest.mark.asyncio
    async def test_lite_mode_allows_eligible_phase(self):
        """phase1 is eligible in lite mode — dispatcher should be attempted."""
        state = _base_state(current_phase="phase1", dispatch_mode="lite")
        assert "phase1" in LITE_DISPATCH_PHASES

        mock_llm = MagicMock()
        mock_llm.invoke.return_value = MagicMock(content="[]")

        with (
            patch(
                "nexusrecon.core.config.get_config",
                return_value=MagicMock(),
            ),
            patch(
                "nexusrecon.graph.agent_executor.get_llm_from_config",
                return_value=mock_llm,
            ),
        ):
            # Should not raise; LLM returns [] so no actual dispatch
            result = await reflection_node(state)
            assert result.get("dynamic_dispatch_log", []) == []

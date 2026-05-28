"""Wave F-A6 tests: trustworthy cost telemetry + live-vs-mock provenance.

The 2026-05-27 ginandjuice.shop run reported $0.00 for every phase, so it
was impossible to tell whether the analyst LLM actually ran or silently
fell back to the deterministic MockLLM. Root cause: the agent executor
recorded spend into its own private CostTracker while the campaign read a
different one. These tests pin the fix: a bound tracker receives the spend,
MockLLM is priced at zero (so $0 + model==mock_llm is an honest "fallback"
signal), and the run-health summary exposes the live-vs-mock verdict.
"""
from __future__ import annotations

import asyncio

from nexusrecon.core.config import get_config
from nexusrecon.core.cost_tracker import MODEL_PRICING, CostTracker
from nexusrecon.core.run_health import (
    llm_provenance_from_state,
    render_run_health_md,
    summarize_run_health,
)
from nexusrecon.graph.agent_executor import AgentExecutor


class TestPricing:
    def test_mock_llm_is_free(self):
        assert MODEL_PRICING["mock_llm"] == {"input": 0.0, "output": 0.0}

    def test_current_model_priced(self):
        # The live model must be in the table so real runs don't get mis-
        # priced via the fallback path.
        assert "claude-opus-4-7" in MODEL_PRICING

    def test_mock_call_costs_zero_real_call_does_not(self):
        t = CostTracker("c", max_llm_cost_usd=50.0)
        assert t.record_llm_call("a", "mock_llm", 1000, 1000) == 0.0
        assert t.record_llm_call("a", "claude-opus-4-7", 1000, 1000) > 0.0


class TestProvenanceDerivation:
    def test_none(self):
        assert llm_provenance_from_state({})["mode"] == "none"

    def test_mock_only(self):
        p = llm_provenance_from_state({"llm_calls_by_model": {"mock_llm": 3}})
        assert p["mode"] == "mock" and p["calls"] == 3

    def test_live_only(self):
        p = llm_provenance_from_state({"llm_calls_by_model": {"claude-opus-4-7": 2}})
        assert p["mode"] == "live"

    def test_mixed(self):
        p = llm_provenance_from_state(
            {"llm_calls_by_model": {"mock_llm": 1, "claude-opus-4-7": 1}}
        )
        assert p["mode"] == "mixed"


class TestRunHealthProvenance:
    def test_mock_caveat_and_render(self):
        h = summarize_run_health(
            [], {},
            llm_provenance={"mode": "mock", "calls": 9,
                            "models": {"mock_llm": 9}, "cost_usd": 0.0},
        )
        assert h.llm_mode == "mock"
        assert any("MockLLM" in c for c in h.caveats)
        md = render_run_health_md(h, "nr-x")
        assert "Analysis engine" in md
        assert "MockLLM fallback" in md

    def test_live_mode_no_mock_caveat(self):
        h = summarize_run_health(
            [], {},
            llm_provenance={"mode": "live", "calls": 5,
                            "models": {"claude-opus-4-7": 5}, "cost_usd": 0.42},
        )
        assert h.llm_mode == "live"
        assert not any("MockLLM" in c for c in h.caveats)


class _FakeResp:
    content = "Analysis complete.\nFINDINGS_JSON:[]"
    usage_metadata = {"input_tokens": 100, "output_tokens": 50}


class _FakeLLM:
    def __init__(self, model_name):
        self.model_name = model_name

    def invoke(self, prompt):
        return _FakeResp()


class TestExecutorRecordsIntoBoundTracker:
    """The core F-A6 fix: spend reaches the campaign tracker + state."""

    def _run(self, model_name):
        ex = AgentExecutor(get_config())
        ex.llm = _FakeLLM(model_name)  # avoid any real API call
        tracker = CostTracker("camp", max_llm_cost_usd=50.0)
        ex.bind_cost_tracker(tracker)
        state = {"current_phase": "phase1", "llm_cost_usd": 0.0, "max_llm_cost_usd": 50.0}
        asyncio.run(ex.run_agent("passive_recon", {"seeds": ["acme.com"]}, "analyze", state))
        return tracker, state

    def test_live_spend_recorded_on_bound_tracker(self):
        tracker, state = self._run("claude-opus-4-7")
        assert tracker.total_llm_calls == 1
        assert tracker.total_llm_cost_usd > 0.0
        assert state["llm_calls_by_model"] == {"claude-opus-4-7": 1}
        assert state["llm_cost_usd"] > 0.0

    def test_mock_run_records_zero_cost_but_provenance(self):
        tracker, state = self._run("mock_llm")
        assert tracker.total_llm_calls == 1
        assert tracker.total_llm_cost_usd == 0.0
        # Provenance is still recorded so the report can say "fallback used".
        assert state["llm_calls_by_model"] == {"mock_llm": 1}
        assert llm_provenance_from_state(state)["mode"] == "mock"

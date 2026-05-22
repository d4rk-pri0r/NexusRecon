"""Tests for graph/workflow.py and graph/nodes.py ── LangGraph workflow."""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from nexusrecon.graph.nodes import route_to_next_phase
from nexusrecon.graph.state import CampaignGraphState
from nexusrecon.graph.workflow import (
    PHASE_ORDER,
    PHASE_TIERS,
    build_campaign_workflow,
    run_workflow,
)
from nexusrecon.models.campaign import CampaignMode
from nexusrecon.tools.base import ToolResult


@pytest.fixture
def mock_workflow_deps():
    """Stub the registry and agent executor used by every phase node.

    Without these mocks ``run_workflow`` runs all 9 phases through to the
    real tool registry, which means real ``nuclei`` / ``subfinder`` /
    ``amass`` subprocesses, real LLM API calls, and 90+ second runtimes
    with no determinism. With them, every tool returns
    ``ToolResult(success=False, ...)`` and every agent returns a canned
    response, so the workflow exercises its plumbing (state passing,
    phase transitions, completion tracking) without leaving the test
    process.
    """
    mock_registry = MagicMock()

    async def _all_fail(tool_name, target, target_type="domain", **kwargs):
        return ToolResult(success=False, source=tool_name, error="mocked: tool not available in unit test")

    mock_registry.execute = AsyncMock(side_effect=_all_fail)
    mock_registry.available_tools = MagicMock(return_value=[])
    mock_registry.get = MagicMock(return_value=None)

    mock_executor = MagicMock()
    mock_executor.run_agent = AsyncMock(return_value={
        "output": "no findings (mocked)",
        "agent": "mocked",
        "step_count": 0,
    })
    mock_executor.audit_findings = MagicMock(return_value=([], []))

    with patch("nexusrecon.graph.nodes.get_registry", return_value=mock_registry), \
         patch("nexusrecon.graph.nodes._get_executor", return_value=mock_executor):
        yield {"registry": mock_registry, "executor": mock_executor}


class TestPhaseOrder:
    def test_phases_in_order(self):
        assert PHASE_ORDER == [
            "phase1", "phase2", "phase2_5", "phase3", "phase4",
            "phase5", "phase6", "phase7", "phase7_5", "phase7_7",
            "phase8", "phase9",
        ]

    def test_all_phases_present(self):
        # 12 phases: includes phase2_5 (D7) + phase7_7 (E11).
        assert len(PHASE_ORDER) == 12


class TestRouteToNextPhase:
    def test_routes_to_first_incomplete(self):
        state: CampaignGraphState = {
            "completed_phases": ["phase1"],
            "current_phase": "phase2",
        }
        assert route_to_next_phase(state) == "phase2"

    def test_routes_to_phase1_when_none_complete(self):
        state: CampaignGraphState = {
            "completed_phases": [],
            "current_phase": "init",
        }
        assert route_to_next_phase(state) == "phase1"

    def test_routes_to_end_when_all_complete(self):
        state: CampaignGraphState = {
            "completed_phases": list(PHASE_ORDER),
            "current_phase": "phase9",
        }
        assert route_to_next_phase(state) == "__end__"

    def test_skips_completed_phases(self):
        # phase2_5 is between phase2 and phase3; skip phase1, phase2, phase2_5, phase3
        state: CampaignGraphState = {
            "completed_phases": ["phase1", "phase2", "phase2_5", "phase3"],
            "current_phase": "phase3",
        }
        assert route_to_next_phase(state) == "phase4"

    def test_handles_gaps_in_completed(self):
        state: CampaignGraphState = {
            "completed_phases": ["phase1", "phase3", "phase5"],
            "current_phase": "phase5",
        }
        # Should return the first missing phase
        assert route_to_next_phase(state) == "phase2"


class TestBuildWorkflow:
    def test_workflow_builds(self):
        workflow = build_campaign_workflow()
        assert workflow is not None

    def test_workflow_has_all_nodes(self):
        workflow = build_campaign_workflow()
        compiled = workflow.compile()
        # Compiling should not raise
        assert compiled is not None

    def test_workflow_with_mode(self):
        workflow = build_campaign_workflow(mode=CampaignMode.DEEP)
        assert workflow is not None


class TestRunWorkflow:
    @pytest.mark.asyncio
    async def test_run_workflow_completes(self, mock_workflow_deps):
        state = {
            "campaign_id": "test-campaign",
            "seeds": ["example.com"],
            "completed_phases": [],
            "current_phase": "init",
            "findings": [],
            "subdomain_intel": {},
            "email_intel": {"emails": {}},
            "cloud_intel": {},
            "code_intel": {},
            "infra_intel": {},
            "domain_intel": {},
            "vuln_intel": {},
            "pretext_intel": {},
            "entity_graph": {},
            "hypotheses": [],
            "confirmed_leads": [],
            "llm_cost_usd": 0.0,
            "tool_cost_usd": 0.0,
            "step_count": 0,
            "errors": [],
            "agent_messages": [],
            "report_paths": {},
        }
        result = await run_workflow(state)
        assert result is not None
        assert "completed_phases" in result
        assert len(result.get("completed_phases", [])) > 0

    @pytest.mark.asyncio
    async def test_run_workflow_preserves_state(self, mock_workflow_deps):
        state = {
            "campaign_id": "test-002",
            "seeds": ["test.com"],
            "completed_phases": [],
            "current_phase": "init",
            "findings": [],
            "subdomain_intel": {},
            "email_intel": {"emails": {}},
            "cloud_intel": {},
            "code_intel": {},
            "infra_intel": {},
            "domain_intel": {},
            "vuln_intel": {},
            "pretext_intel": {},
            "entity_graph": {},
            "hypotheses": [],
            "confirmed_leads": [],
            "llm_cost_usd": 0.0,
            "tool_cost_usd": 0.0,
            "step_count": 0,
            "errors": [],
            "agent_messages": [],
            "report_paths": {},
        }
        result = await run_workflow(state)
        assert result["campaign_id"] == "test-002"
        assert len(result.get("completed_phases", [])) >= 1

    @pytest.mark.asyncio
    async def test_run_workflow_all_phases(self, mock_workflow_deps):
        """Verify all phases eligible for MEDIUM mode complete in the graph.

        MEDIUM mode (tier limit 2) excludes phase6 (tier 3).
        PHASE_ORDER now includes phase7_5 making the total 10 phases,
        but MEDIUM active phases = 9 (all except phase6).
        """
        # Compute expected phases for MEDIUM mode (tier limit 2)
        MEDIUM_TIER_LIMIT = 2
        expected_phases = {p for p in PHASE_ORDER if PHASE_TIERS.get(p, 0) <= MEDIUM_TIER_LIMIT}

        state = {
            "campaign_id": "test-all-phases",
            "seeds": ["example.org"],
            "completed_phases": [],
            "current_phase": "init",
            "findings": [],
            "subdomain_intel": {},
            "email_intel": {"emails": {}},
            "cloud_intel": {},
            "code_intel": {},
            "infra_intel": {},
            "domain_intel": {},
            "vuln_intel": {},
            "pretext_intel": {},
            "entity_graph": {},
            "hypotheses": [],
            "confirmed_leads": [],
            "llm_cost_usd": 0.0,
            "tool_cost_usd": 0.0,
            "step_count": 0,
            "errors": [],
            "agent_messages": [],
            "report_paths": {},
        }
        result = await run_workflow(state)
        completed = result.get("completed_phases", [])
        assert set(completed) == expected_phases

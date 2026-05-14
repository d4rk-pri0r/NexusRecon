"""Tests for graph/workflow.py and graph/nodes.py — LangGraph workflow."""
import pytest
from nexusrecon.graph.state import CampaignGraphState
from nexusrecon.graph.workflow import (
    build_campaign_workflow, PHASE_ORDER, PHASE_TIERS, run_workflow,
)
from nexusrecon.graph.nodes import route_to_next_phase
from nexusrecon.models.campaign import CampaignMode


class TestPhaseOrder:
    def test_phases_in_order(self):
        assert PHASE_ORDER == [
            "phase1", "phase2", "phase3", "phase4",
            "phase5", "phase6", "phase7", "phase7_5", "phase8", "phase9",
        ]

    def test_all_phases_present(self):
        assert len(PHASE_ORDER) == 10


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
        state: CampaignGraphState = {
            "completed_phases": ["phase1", "phase2", "phase3"],
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
    async def test_run_workflow_completes(self):
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
    async def test_run_workflow_preserves_state(self):
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
    async def test_run_workflow_all_phases(self):
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

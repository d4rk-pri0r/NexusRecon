"""Tests for models/campaign.py — CampaignState, CampaignMode, PhaseStatus."""
from nexusrecon.models.campaign import (
    CampaignMode,
    CampaignPlan,
    CampaignState,
    PhasePlan,
    PhaseResult,
    PhaseStatus,
    SuccessCriteria,
)


class TestCampaignMode:
    def test_values(self):
        assert CampaignMode.LIGHT.value == "light"
        assert CampaignMode.MEDIUM.value == "medium"
        assert CampaignMode.DEEP.value == "deep"
        assert CampaignMode.MONITOR.value == "monitor"


class TestPhaseStatus:
    def test_values(self):
        assert PhaseStatus.PENDING.value == "pending"
        assert PhaseStatus.COMPLETED.value == "completed"
        assert PhaseStatus.FAILED.value == "failed"


class TestPhaseResult:
    def test_defaults(self):
        pr = PhaseResult(phase_name="phase1", status=PhaseStatus.COMPLETED)
        assert pr.phase_name == "phase1"
        assert pr.status == PhaseStatus.COMPLETED
        assert pr.findings_count == 0
        assert pr.entities_discovered == 0
        assert pr.tools_run == []
        assert pr.errors == []
        assert pr.llm_cost_usd == 0.0

    def test_with_findings(self):
        pr = PhaseResult(
            phase_name="phase1",
            status=PhaseStatus.COMPLETED,
            findings_count=5,
            tools_run=["crtsh", "dns"],
            llm_cost_usd=0.10,
        )
        assert pr.findings_count == 5
        assert len(pr.tools_run) == 2


class TestCampaignState:
    def test_defaults(self):
        cs = CampaignState(campaign_id="test-001", engagement_id="eng-001", mode=CampaignMode.MEDIUM, scope_hash="abc")
        assert cs.campaign_id == "test-001"
        assert cs.current_phase == "init"
        assert cs.completed_phases == []
        assert cs.findings == []
        assert cs.llm_cost_usd == 0.0

    def test_mark_phase_complete(self):
        cs = CampaignState(campaign_id="t1", engagement_id="e1", mode=CampaignMode.LIGHT, scope_hash="h1")
        cs.mark_phase_complete("phase1")
        assert "phase1" in cs.completed_phases
        assert cs.current_phase == "phase1"

    def test_mark_phase_dedup(self):
        cs = CampaignState(campaign_id="t2", engagement_id="e2", mode=CampaignMode.LIGHT, scope_hash="h2")
        cs.mark_phase_complete("phase1")
        cs.mark_phase_complete("phase1")  # Should not duplicate
        assert len(cs.completed_phases) == 1

    def test_add_finding(self):
        cs = CampaignState(campaign_id="t3", engagement_id="e3", mode=CampaignMode.LIGHT, scope_hash="h3")
        cs.add_finding({"title": "test finding", "severity": "high"})
        assert len(cs.findings) == 1
        assert cs.findings[0]["title"] == "test finding"

    def test_touch_updates_updated_at(self):
        cs = CampaignState(campaign_id="t4", engagement_id="e4", mode=CampaignMode.LIGHT, scope_hash="h4")
        before = cs.updated_at
        import time
        time.sleep(0.001)
        cs.touch()
        assert cs.updated_at > before

    def test_total_cost_usd(self):
        cs = CampaignState(campaign_id="t5", engagement_id="e5", mode=CampaignMode.LIGHT, scope_hash="h5")
        cs.llm_cost_usd = 0.50
        cs.tool_cost_usd = 0.25
        assert cs.total_cost_usd() == 0.75

    def test_serialize_roundtrip(self):
        cs = CampaignState(campaign_id="t6", engagement_id="e6", mode=CampaignMode.DEEP, scope_hash="h6")
        cs.add_finding({"title": "finding1", "severity": "critical"})
        cs.mark_phase_complete("phase1")
        data = cs.model_dump_json()
        restored = CampaignState.model_validate_json(data)
        assert restored.campaign_id == "t6"
        assert len(restored.findings) == 1
        assert restored.completed_phases == ["phase1"]


class TestPhasePlan:
    def test_defaults(self):
        pp = PhasePlan(phase_name="phase1", description="Test phase", tier="T0")
        assert pp.phase_name == "phase1"
        assert pp.success_criteria.min_subdomains == 0
        assert pp.time_budget_min == 30
        assert pp.cost_budget_usd == 5.0

    def test_with_tools_and_agents(self):
        pp = PhasePlan(
            phase_name="phase2",
            description="Cloud recon",
            tier="T1",
            agents=["cloud_identity"],
            tools=["azure_m365"],
            success_criteria=SuccessCriteria(min_cloud_assets=1),
            time_budget_min=60,
        )
        assert "azure_m365" in pp.tools
        assert pp.success_criteria.min_cloud_assets == 1


class TestCampaignPlan:
    def test_defaults(self):
        cp = CampaignPlan(campaign_id="plan-001", mode=CampaignMode.MEDIUM)
        assert cp.phases == []
        assert cp.total_time_budget_min == 120

    def test_with_phases(self):
        cp = CampaignPlan(campaign_id="plan-002", mode=CampaignMode.DEEP)
        cp.phases.append(PhasePlan(phase_name="phase1", description="Passive", tier="T0"))
        cp.phases.append(PhasePlan(phase_name="phase2", description="Cloud", tier="T1"))
        assert len(cp.phases) == 2

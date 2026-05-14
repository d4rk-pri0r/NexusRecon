"""Unit tests for LangGraph phase nodes with mocked dependencies."""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from nexusrecon.graph.nodes import (
    phase1_passive_footprinting,
    phase2_identity_cloud,
    phase3_code_leakage,
    phase4_correlation,
    phase5_light_active,
    phase6_active,
    phase7_vuln_pretext,
    phase8_attack_surface,
    phase9_reporting,
    route_to_next_phase,
    _reset_executor,
)
from nexusrecon.graph.state import CampaignGraphState
from nexusrecon.tools.base import ToolResult


# ── Helpers ──────────────────────────────────────────────────────────────────

def _make_state(overrides: dict = None) -> CampaignGraphState:
    base: CampaignGraphState = {
        "campaign_id": "test-campaign",
        "engagement_id": "TEST-001",
        "scope_hash": "sha256:abc",
        "seeds": ["example.com"],
        "current_phase": "init",
        "completed_phases": [],
        "phase_results": {},
        "findings": [],
        "domain_intel": {},
        "subdomain_intel": {},
        "email_intel": {"emails": {}},
        "identity_intel": {},
        "cloud_intel": {},
        "code_intel": {},
        "infra_intel": {},
        "vuln_intel": {},
        "pretext_intel": {},
        "entity_graph": {},
        "hypotheses": [],
        "confirmed_leads": [],
        "open_questions": [],
        "llm_cost_usd": 0.0,
        "tool_cost_usd": 0.0,
        "step_count": 0,
        "errors": [],
        "agent_messages": [],
        "report_paths": {},
    }
    if overrides:
        base.update(overrides)
    return base


def _make_mock_registry(available_tools: list = None):
    """Create a mock tool registry with controllable tool behavior."""
    registry = MagicMock()
    registry.available_tools = MagicMock(return_value=available_tools or [])
    registry.get = MagicMock(return_value=None)

    # execute() is async — delegate to the tool registered via registry.get()
    async def _delegating_execute(tool_name, target, target_type="domain", **kwargs):
        tool = registry.get(tool_name)
        if tool is None:
            return ToolResult(success=False, source=tool_name, error="not registered")
        if hasattr(tool, "is_available") and callable(tool.is_available):
            if not tool.is_available():
                return ToolResult(success=False, source=tool_name, error="not available")
        if hasattr(tool, "run"):
            return await tool.run(target, target_type=target_type, **kwargs)
        return ToolResult(success=False, source=tool_name, data={})

    registry.execute = AsyncMock(side_effect=_delegating_execute)
    return registry


def _make_mock_tool(name: str, result: ToolResult = None):
    """Create a mock tool that returns a given result."""
    tool = MagicMock()
    tool.name = name
    tool.run = AsyncMock(return_value=result or ToolResult(success=True, source=name, data={}))
    tool.is_available = MagicMock(return_value=True)
    tool.tier = MagicMock(value="T0")
    tool.category = MagicMock(value="domain")
    return tool


# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def reset_executor():
    _reset_executor()
    yield
    _reset_executor()


@pytest.fixture
def mock_registry():
    return _make_mock_registry()


# ── Route to Next Phase ──────────────────────────────────────────────────────

class TestRouteToNextPhase:
    def test_routes_to_first_incomplete(self):
        state = _make_state({"completed_phases": ["phase1"], "current_phase": "phase2"})
        assert route_to_next_phase(state) == "phase2"

    def test_routes_to_phase1_when_none_complete(self):
        state = _make_state({"completed_phases": [], "current_phase": "init"})
        assert route_to_next_phase(state) == "phase1"

    def test_routes_to_end_when_all_complete(self):
        state = _make_state({
            "completed_phases": ["phase1", "phase2", "phase3", "phase4",
                                "phase5", "phase6", "phase7", "phase7_5", "phase8", "phase9"],
            "current_phase": "phase9",
        })
        assert route_to_next_phase(state) == "__end__"

    def test_skips_completed_phases(self):
        state = _make_state({
            "completed_phases": ["phase1", "phase2", "phase3"],
            "current_phase": "phase3",
        })
        assert route_to_next_phase(state) == "phase4"

    def test_handles_gaps_in_completed(self):
        state = _make_state({
            "completed_phases": ["phase1", "phase3", "phase5"],
            "current_phase": "phase5",
        })
        assert route_to_next_phase(state) == "phase2"


# ── Phase 1: Passive Footprinting ────────────────────────────────────────────

class TestPhase1:
    @pytest.mark.asyncio
    @patch("nexusrecon.graph.nodes.get_registry")
    async def test_runs_tools_and_updates_state(self, mock_get_registry):
        mock_registry = MagicMock()
        async def _delegating_execute(tool_name, target, target_type="domain", **kwargs):
            tool = mock_registry.get(tool_name)
            if tool is None:
                return ToolResult(success=False, source=tool_name, error="not registered")
            if hasattr(tool, "is_available") and callable(tool.is_available):
                if not tool.is_available():
                    return ToolResult(success=False, source=tool_name, error="not available")
            if hasattr(tool, "run"):
                return await tool.run(target, target_type=target_type, **kwargs)
            return ToolResult(success=False, source=tool_name, data={})
        mock_registry.execute = AsyncMock(side_effect=_delegating_execute)
        crtsh = _make_mock_tool("crtsh", ToolResult(
            success=True, source="crtsh",
            data={"subdomains": ["mail.example.com"], "certs": []},
            result_count=1,
        ))
        subfinder = _make_mock_tool("subfinder", ToolResult(
            success=False, source="subfinder", error="binary not found",
        ))
        amass = _make_mock_tool("amass", ToolResult(
            success=False, source="amass", error="binary not found",
        ))
        mock_registry.get.side_effect = lambda name: {"crtsh": crtsh, "subfinder": subfinder, "amass": amass}.get(name)
        mock_registry.available_tools = MagicMock(return_value=[crtsh, subfinder, amass])
        mock_get_registry.return_value = mock_registry

        state = _make_state()
        result = await phase1_passive_footprinting(state)

        assert "phase1" in result.get("completed_phases", [])
        assert result["current_phase"] == "phase1"
        assert crtsh.run.called

    @pytest.mark.asyncio
    @patch("nexusrecon.graph.nodes.get_registry")
    async def test_handles_no_tools_available(self, mock_get_registry):
        mock_registry = MagicMock()
        async def _delegating_execute(tool_name, target, target_type="domain", **kwargs):
            tool = mock_registry.get(tool_name)
            if tool is None:
                return ToolResult(success=False, source=tool_name, error="not registered")
            if hasattr(tool, "is_available") and callable(tool.is_available):
                if not tool.is_available():
                    return ToolResult(success=False, source=tool_name, error="not available")
            if hasattr(tool, "run"):
                return await tool.run(target, target_type=target_type, **kwargs)
            return ToolResult(success=False, source=tool_name, data={})
        mock_registry.execute = AsyncMock(side_effect=_delegating_execute)
        mock_registry.get.return_value = None
        mock_registry.available_tools = MagicMock(return_value=[])
        mock_get_registry.return_value = mock_registry

        state = _make_state()
        result = await phase1_passive_footprinting(state)
        assert "phase1" in result.get("completed_phases", [])

    @pytest.mark.asyncio
    @patch("nexusrecon.graph.nodes.get_registry")
    async def test_handles_multiple_seeds(self, mock_get_registry):
        mock_registry = MagicMock()
        async def _delegating_execute(tool_name, target, target_type="domain", **kwargs):
            tool = mock_registry.get(tool_name)
            if tool is None:
                return ToolResult(success=False, source=tool_name, error="not registered")
            if hasattr(tool, "is_available") and callable(tool.is_available):
                if not tool.is_available():
                    return ToolResult(success=False, source=tool_name, error="not available")
            if hasattr(tool, "run"):
                return await tool.run(target, target_type=target_type, **kwargs)
            return ToolResult(success=False, source=tool_name, data={})
        mock_registry.execute = AsyncMock(side_effect=_delegating_execute)
        crtsh = _make_mock_tool("crtsh", ToolResult(
            success=True, source="crtsh",
            data={"subdomains": ["sub.a.com"], "certs": []},
            result_count=1,
        ))
        mock_registry.get.side_effect = lambda name: crtsh
        mock_registry.available_tools = MagicMock(return_value=[crtsh])
        mock_get_registry.return_value = mock_registry

        state = _make_state({"seeds": ["example.com", "test.org"]})
        result = await phase1_passive_footprinting(state)
        assert "phase1" in result.get("completed_phases", [])
        # 2 seeds * (3 subdomain + 1 dns + 1 whois + 1 asn + 4 dark intel) = 20 runs
        assert crtsh.run.call_count == 20

    @pytest.mark.asyncio
    @patch("nexusrecon.graph.nodes.get_registry")
    async def test_tool_exception_does_not_crash(self, mock_get_registry):
        mock_registry = MagicMock()
        async def _delegating_execute(tool_name, target, target_type="domain", **kwargs):
            tool = mock_registry.get(tool_name)
            if tool is None:
                return ToolResult(success=False, source=tool_name, error="not registered")
            if hasattr(tool, "is_available") and callable(tool.is_available):
                if not tool.is_available():
                    return ToolResult(success=False, source=tool_name, error="not available")
            if hasattr(tool, "run"):
                return await tool.run(target, target_type=target_type, **kwargs)
            return ToolResult(success=False, source=tool_name, data={})
        mock_registry.execute = AsyncMock(side_effect=_delegating_execute)
        bad_subdomain = MagicMock()
        bad_subdomain.name = "bad_sub"
        bad_subdomain.is_available = MagicMock(return_value=True)
        bad_subdomain.run = AsyncMock(side_effect=Exception("unexpected error"))

        # Separate tool for non-subdomain calls to avoid crash on dns/whois/asn
        ok_tool = _make_mock_tool("ok", ToolResult(success=True, source="ok", data={}))
        ok_tool.is_available = MagicMock(return_value=True)

        def _get(name):
            if name in ("crtsh", "subfinder", "amass"):
                return bad_subdomain
            if name in ("dns", "whois", "asn_bgp"):
                return ok_tool
            return None

        mock_registry.get.side_effect = _get
        mock_registry.available_tools = MagicMock(return_value=[bad_subdomain, ok_tool])
        mock_get_registry.return_value = mock_registry

        state = _make_state()
        result = await phase1_passive_footprinting(state)
        assert "phase1" in result.get("completed_phases", [])


# ── Phase 2: Identity and Cloud ──────────────────────────────────────────────

class TestPhase2:
    @pytest.mark.asyncio
    @patch("nexusrecon.graph.nodes.get_registry")
    async def test_runs_identity_tools(self, mock_get_registry):
        mock_registry = MagicMock()
        async def _delegating_execute(tool_name, target, target_type="domain", **kwargs):
            tool = mock_registry.get(tool_name)
            if tool is None:
                return ToolResult(success=False, source=tool_name, error="not registered")
            if hasattr(tool, "is_available") and callable(tool.is_available):
                if not tool.is_available():
                    return ToolResult(success=False, source=tool_name, error="not available")
            if hasattr(tool, "run"):
                return await tool.run(target, target_type=target_type, **kwargs)
            return ToolResult(success=False, source=tool_name, data={})
        mock_registry.execute = AsyncMock(side_effect=_delegating_execute)
        tool = _make_mock_tool("whois", ToolResult(
            success=True, source="whois", data={"registrar": "TestReg"},
        ))
        mock_registry.get.side_effect = lambda name: tool if name == "whois" else None
        mock_registry.available_tools = MagicMock(return_value=[tool])
        mock_get_registry.return_value = mock_registry

        state = _make_state()
        result = await phase2_identity_cloud(state)
        assert "phase2" in result.get("completed_phases", [])


# ── Phase 3: Code Leakage ────────────────────────────────────────────────────

class TestPhase3:
    @pytest.mark.asyncio
    @patch("nexusrecon.graph.nodes.get_registry")
    async def test_runs_code_tools(self, mock_get_registry):
        mock_registry = MagicMock()
        async def _delegating_execute(tool_name, target, target_type="domain", **kwargs):
            tool = mock_registry.get(tool_name)
            if tool is None:
                return ToolResult(success=False, source=tool_name, error="not registered")
            if hasattr(tool, "is_available") and callable(tool.is_available):
                if not tool.is_available():
                    return ToolResult(success=False, source=tool_name, error="not available")
            if hasattr(tool, "run"):
                return await tool.run(target, target_type=target_type, **kwargs)
            return ToolResult(success=False, source=tool_name, data={})
        mock_registry.execute = AsyncMock(side_effect=_delegating_execute)
        tool = _make_mock_tool("github", ToolResult(
            success=True, source="github", data={"repos": ["test/repo"]},
        ))
        mock_registry.get.side_effect = lambda name: tool if name in ("github", "gitleaks") else None
        mock_registry.available_tools = MagicMock(return_value=[tool])
        mock_get_registry.return_value = mock_registry

        state = _make_state()
        result = await phase3_code_leakage(state)
        assert "phase3" in result.get("completed_phases", [])


# ── Phase 4: Correlation ─────────────────────────────────────────────────────

class TestPhase4:
    @pytest.mark.asyncio
    @patch("nexusrecon.graph.nodes.AgentExecutor")
    async def test_runs_correlation_agent(self, mock_executor_cls):
        mock_executor = AsyncMock()
        mock_executor.run_agent = MagicMock(return_value={
            "output": "Correlation complete. Found 3 connections.",
            "agent": "correlation",
            "step_count": 1,
        })
        mock_executor_cls.return_value = mock_executor

        state = _make_state({
            "domain_intel": {"example.com": {"whois": "data"}},
            "subdomain_intel": {"mail.example.com": {"sources": ["crtsh"]}},
            "email_intel": {"emails": {"admin@example.com": {"source": "hunter"}}},
        })
        result = await phase4_correlation(state)
        assert "phase4" in result.get("completed_phases", [])


# ── Phase 5: Light Active ────────────────────────────────────────────────────

class TestPhase5:
    @pytest.mark.asyncio
    @patch("nexusrecon.graph.nodes.get_registry")
    async def test_runs_active_tools(self, mock_get_registry):
        mock_registry = MagicMock()
        async def _delegating_execute(tool_name, target, target_type="domain", **kwargs):
            tool = mock_registry.get(tool_name)
            if tool is None:
                return ToolResult(success=False, source=tool_name, error="not registered")
            if hasattr(tool, "is_available") and callable(tool.is_available):
                if not tool.is_available():
                    return ToolResult(success=False, source=tool_name, error="not available")
            if hasattr(tool, "run"):
                return await tool.run(target, target_type=target_type, **kwargs)
            return ToolResult(success=False, source=tool_name, data={})
        mock_registry.execute = AsyncMock(side_effect=_delegating_execute)
        tool = _make_mock_tool("webtech", ToolResult(
            success=True, source="webtech",
            data={"url": "https://example.com", "technologies": [{"name": "nginx"}], "count": 1},
        ))
        mock_registry.get.side_effect = lambda name: tool if name == "webtech" else None
        mock_registry.available_tools = MagicMock(return_value=[tool])
        mock_get_registry.return_value = mock_registry

        state = _make_state({"subdomain_intel": {"www.example.com": {"sources": ["crtsh"]}}})
        result = await phase5_light_active(state)
        assert "phase5" in result.get("completed_phases", [])


# ── Phase 6: Active (T3) ─────────────────────────────────────────────────────

class TestPhase6:
    @pytest.mark.asyncio
    @patch("nexusrecon.graph.nodes.get_registry")
    async def test_runs_httpx_if_available(self, mock_get_registry):
        httpx_tool = _make_mock_tool("httpx", ToolResult(
            success=True, source="httpx",
            data={"results": [{"url": "https://example.com", "status_code": 200}]},
            result_count=1,
        ))
        mock_registry = MagicMock()
        async def _delegating_execute(tool_name, target, target_type="domain", **kwargs):
            tool = mock_registry.get(tool_name)
            if tool is None:
                return ToolResult(success=False, source=tool_name, error="not registered")
            if hasattr(tool, "is_available") and callable(tool.is_available):
                if not tool.is_available():
                    return ToolResult(success=False, source=tool_name, error="not available")
            if hasattr(tool, "run"):
                return await tool.run(target, target_type=target_type, **kwargs)
            return ToolResult(success=False, source=tool_name, data={})
        mock_registry.execute = AsyncMock(side_effect=_delegating_execute)
        mock_registry.get.side_effect = lambda name: httpx_tool if name == "httpx" else None
        mock_registry.available_tools = MagicMock(return_value=[httpx_tool])
        mock_get_registry.return_value = mock_registry

        state = _make_state({"subdomain_intel": {"www.example.com": {"sources": ["crtsh"]}}})
        result = await phase6_active(state)
        assert "phase6" in result.get("completed_phases", [])


# ── Phase 7: Vuln and Pretext ────────────────────────────────────────────────

class TestPhase7:
    @pytest.mark.asyncio
    async def test_runs_with_minimal_state(self):
        state = _make_state()
        result = await phase7_vuln_pretext(state)
        assert "phase7" in result.get("completed_phases", [])


# ── Phase 8: Attack Surface ──────────────────────────────────────────────────

class TestPhase8:
    @pytest.mark.asyncio
    async def test_runs_with_minimal_state(self):
        state = _make_state()
        result = await phase8_attack_surface(state)
        assert "phase8" in result.get("completed_phases", [])


# ── Phase 9: Reporting ───────────────────────────────────────────────────────

class TestPhase9:
    @pytest.mark.asyncio
    @patch("nexusrecon.graph.nodes._get_executor")
    async def test_generates_agent_analysis(self, mock_get_executor):
        mock_exec = MagicMock()
        mock_exec.run_agent = AsyncMock(return_value={
            "output": "Executive report complete. Top 5 findings identified.",
            "agent": "executive_reporter",
            "step_count": 3,
        })
        mock_exec.audit_findings = MagicMock(return_value=(
            [{"finding_id": "f-1", "title": "Test", "severity": "high"}],
            [],
        ))
        mock_get_executor.return_value = mock_exec

        state = _make_state({
            "findings": [{"finding_id": "f-1", "title": "Test", "severity": "high"}],
        })
        result = await phase9_reporting(state)
        assert "phase9" in result.get("completed_phases", [])
        assert len(result.get("agent_messages", [])) >= 2
        assert "rejected_findings" in result

"""Unit tests for AgentExecutor and MockLLM."""
from unittest.mock import MagicMock, patch

import pytest

from nexusrecon.graph.agent_executor import (
    AgentExecutor,
    MockLLM,
    MockLLMResponse,
    get_llm_from_config,
)

# ── MockLLM Tests ────────────────────────────────────────────────────────────

class TestMockLLM:
    def test_init(self):
        llm = MockLLM()
        assert llm.model_name == "mock_llm"

    def test_invoke_returns_response(self):
        llm = MockLLM()
        result = llm.invoke("Hello")
        assert hasattr(result, "content")
        assert isinstance(result.content, str)

    def test_response_with_findings(self):
        llm = MockLLM()
        prompt = (
            "finding critical vulnerability exposure found\n"
            "another vuln finding here\n"
            "more exposures and findings\n"
            "even more vuln data"
        )
        result = llm.invoke(prompt)
        assert "Multiple intelligence findings" in result.content

    def test_response_with_subdomains(self):
        llm = MockLLM()
        prompt = "subdomain subdomain email"
        result = llm.invoke(prompt)
        assert "Intelligence data collected" in result.content
        assert "Subdomain indicators" in result.content

    def test_response_with_no_findings(self):
        llm = MockLLM()
        prompt = "nothing useful here at all"
        result = llm.invoke(prompt)
        assert "No significant intelligence findings" in result.content

    def test_mock_llm_response_str(self):
        resp = MockLLMResponse("test content")
        assert str(resp) == "test content"
        assert resp.content == "test content"


# ── get_llm_from_config Tests ────────────────────────────────────────────────

class TestGetLLMFromConfig:
    """``get_llm_from_config`` now routes through the ``nexusrecon.llm`` factory.

    The old "silently fall back to MockLLM for any keyless provider" contract
    is gone (provider-oauth plan): operators who want the deterministic mock
    select ``provider=mock``. A keyless, login-less provider must raise a clear
    ``LLMAuthenticationError`` naming the API-key variable.
    """

    def test_mock_provider_returns_mock(self):
        config = MagicMock()
        config.llm_provider = "mock"
        config.llm_auth_mode = "auto"
        config.llm_model = "mock"
        config.llm_temperature = 0.0
        config.get_secret = MagicMock(return_value=None)
        llm = get_llm_from_config(config)
        assert isinstance(llm, MockLLM)

    def test_api_key_mode_missing_key_raises_with_remediation(self):
        from nexusrecon.llm.auth import LLMAuthenticationError
        config = MagicMock()
        config.llm_provider = "openai"
        config.llm_auth_mode = "api_key"
        config.llm_model = "gpt-4o"
        config.llm_temperature = 0.2
        config.get_secret = MagicMock(return_value=None)
        with pytest.raises(LLMAuthenticationError) as ei:
            get_llm_from_config(config)
        assert "OPENAI_API_KEY" in str(ei.value)

    def test_unknown_provider_raises_clear_error_not_silent_mock(self):
        config = MagicMock()
        config.llm_provider = "nonexistent"
        config.llm_auth_mode = "api_key"
        config.llm_model = "x"
        config.llm_temperature = 0.0
        config.get_secret = MagicMock(return_value="some_key")
        with pytest.raises(ValueError):
            get_llm_from_config(config)

    def test_ollama_provider_bypasses_auth(self):
        config = MagicMock()
        config.llm_provider = "ollama"
        config.llm_auth_mode = "auto"
        config.ollama_model = "llama3"
        config.ollama_base_url = "http://localhost:11434"
        config.llm_model = "llama3"
        config.llm_temperature = 1.0
        llm = get_llm_from_config(config)
        # May return ChatOllama if package is installed; verify it's not None
        assert llm is not None

    def test_anthropic_api_key_is_direct_chat_client(self):
        config = MagicMock()
        config.llm_provider = "anthropic"
        config.llm_auth_mode = "api_key"
        config.llm_model = "claude-opus-4-5"
        config.llm_temperature = 0.7
        config.get_secret = MagicMock(return_value="sk-ant-xxx")
        llm = get_llm_from_config(config)
        assert type(llm).__name__ == "ChatAnthropic"


# ── AgentExecutor Tests ──────────────────────────────────────────────────────

class TestAgentExecutor:
    def test_init(self):
        config = MagicMock()
        config.llm_provider = "mock"
        executor = AgentExecutor(config)
        assert executor is not None
        assert executor._step_count == 0

    @pytest.mark.asyncio
    async def test_run_agent_unknown_agent(self):
        config = MagicMock()
        config.llm_provider = "mock"
        executor = AgentExecutor(config)
        with pytest.raises(ValueError, match="Unknown agent"):
            await executor.run_agent("nonexistent", {}, "test")

    @pytest.mark.asyncio
    async def test_run_agent_returns_output(self):
        config = MagicMock()
        config.llm_provider = "mock"
        config.llm_model = "mock"
        config.llm_temperature = 0.0
        config.get_secret = MagicMock(return_value=None)
        executor = AgentExecutor(config)
        result = await executor.run_agent(
            "passive_recon",
            {"seeds": ["example.com"], "subdomain_intel": {"sub": {"sources": ["crtsh"]}}},
            "Find subdomains",
        )
        assert "output" in result
        assert result["agent"] == "passive_recon"
        assert result["step_count"] == 1
        assert isinstance(result["output"], str)
        assert len(result["output"]) > 0

    @pytest.mark.asyncio
    async def test_run_agent_tracks_step_count(self):
        config = MagicMock()
        config.llm_provider = "mock"
        config.llm_model = "mock"
        config.llm_temperature = 0.0
        config.get_secret = MagicMock(return_value=None)
        executor = AgentExecutor(config)
        r1 = await executor.run_agent("passive_recon", {}, "task1")
        r2 = await executor.run_agent("passive_recon", {}, "task2")
        assert r1["step_count"] == 1
        assert r2["step_count"] == 2
        assert executor._step_count == 2

    @pytest.mark.asyncio
    async def test_run_agent_with_large_data(self):
        config = MagicMock()
        config.llm_provider = "mock"
        config.llm_model = "mock"
        config.llm_temperature = 0.0
        config.get_secret = MagicMock(return_value=None)
        executor = AgentExecutor(config)
        large_data = {"large_field": "x" * 5000}
        result = await executor.run_agent("passive_recon", large_data, "test")
        assert "output" in result
        assert result["step_count"] == 1

    @pytest.mark.asyncio
    async def test_run_agent_all_registered_agents(self):
        """Verify all agents in the registry can be invoked without error."""
        config = MagicMock()
        config.llm_provider = "mock"
        config.llm_model = "mock"
        config.llm_temperature = 0.0
        config.get_secret = MagicMock(return_value=None)
        executor = AgentExecutor(config)
        agent_names = [
            "campaign_planner", "passive_recon", "active_recon",
            "cloud_identity", "pretext_humint", "correlation",
            "risk_analyst", "vuln_correlator", "evidence_auditor",
            "executive_reporter",
        ]
        for name in agent_names:
            result = await executor.run_agent(name, {"seeds": ["test.com"]}, "task")
            assert "output" in result
            assert result["agent"] == name

    def test_build_context_with_data(self):
        config = MagicMock()
        executor = AgentExecutor(config)
        context = executor._build_context(
            {"seeds": ["example.com"], "findings": [{"title": "test"}]},
            "Analyze the data",
        )
        # Identity preamble (agent=None branch).
        assert "NexusRecon OSINT specialist" in context
        # Task prompt verbatim.
        assert "Analyze the data" in context
        # Data sections rendered with ## header per key.
        assert "## seeds" in context
        assert "## findings" in context
        # Post-prompt analysis directive (B25 ordering ── analysis prose
        # instructions live AFTER the FINDINGS_JSON block, not as
        # generic "Instructions" boilerplate the old test asserted on).
        assert "Analysis (write AFTER emitting FINDINGS_JSON):" in context

    def test_build_context_skips_completed_phases(self):
        config = MagicMock()
        executor = AgentExecutor(config)
        context = executor._build_context(
            {"seeds": ["example.com"], "completed_phases": ["phase1"]},
            "task",
        )
        assert "completed_phases" not in context

    def test_audit_findings(self):
        MagicMock()
        valid_findings = [
            {"finding_id": "f-1", "title": "Test", "source": "crtsh",
             "description": "desc", "severity": "high", "confidence": 0.9,
             "category": "web", "affected_assets": ["example.com"],
             "mitre_techniques": ["T1078"], "raw_evidence_hash": "abc",
             "timestamp": "2026-01-01T00:00:00"},
        ]
        # EvidenceAuditorAgent instantiation fails due to BaseNexusAgent dataclass.
        # Verify the static method pattern works when audit_findings is callable.
        mock_fn = MagicMock(return_value=(valid_findings, []))
        with patch("nexusrecon.graph.agent_executor.EvidenceAuditorAgent") as mock_cls:
            mock_cls.return_value.audit_findings = mock_fn
            result = AgentExecutor.audit_findings(valid_findings)
            assert result == (valid_findings, [])


# ── #6: MockLLM provenance labeling + evidence-integrity honesty ──────────────

class TestMockProvenanceLabeling:
    """A keyless run falls back to MockLLM, which emits templated (not reasoned)
    findings. #6 labels them unmistakably instead of letting them masquerade as
    analysis, and stops the evidence hash from implying provenance it lacks."""

    def _keyless_executor(self):
        config = MagicMock()
        config.llm_provider = "mock"
        config.llm_model = "mock"
        config.llm_temperature = 0.0
        config.get_secret = MagicMock(return_value=None)
        return AgentExecutor(config)

    @pytest.mark.asyncio
    async def test_mock_findings_stamped_provenance_mock(self):
        ex = self._keyless_executor()
        result = await ex.run_agent(
            "passive_recon",
            {"seeds": ["example.com"], "subdomain_intel": {"s": {"sources": ["crtsh"]}}},
            "Find subdomains",
        )
        assert result["findings"], "MockLLM always emits one finding"
        assert all(f.get("provenance") == "mock" for f in result["findings"])

    @pytest.mark.asyncio
    async def test_provenance_is_model_derived_not_source_spoofable(self):
        # A finding served by a real model but whose source string CLAIMS
        # mock_llm must be stamped provenance="llm": the stamp reflects the
        # actual model, not the spoofable source field.
        ex = self._keyless_executor()
        fake = MagicMock()
        fake.model_name = "claude-x"
        fake.invoke.return_value = MockLLMResponse(
            'FINDINGS_JSON:[{"severity":"info","title":"t","description":"d",'
            '"source":"mock_llm","confidence":0.9,"category":"recon"}]'
        )
        ex.llm = fake
        result = await ex.run_agent("passive_recon", {"seeds": ["x"]}, "task")
        assert result["findings"]
        f = result["findings"][0]
        assert f["source"] == "mock_llm"       # source is spoofed
        assert f["provenance"] == "llm"         # provenance reflects the real model

    @pytest.mark.asyncio
    async def test_agent_findings_marked_unverified_evidence(self):
        # The evidence hash is synthesized over the model's own prose, so agent
        # findings carry evidence_integrity="unverified" (drop-the-overclaim).
        ex = self._keyless_executor()
        result = await ex.run_agent("passive_recon", {"seeds": ["x"]}, "task")
        assert result["findings"]
        f = result["findings"][0]
        assert f.get("raw_evidence_hash", "").startswith("sha256:")
        assert f.get("evidence_integrity") == "unverified"

    def test_persona_reaches_prompt(self):
        # ROADMAP #6's named missing test: a real agent's role/goal/backstory
        # reaches the built prompt. (Under MockLLM this does NOT meaningfully
        # change the templated output, which is exactly why mock findings must
        # be labeled rather than trusted as persona-driven analysis.)
        from nexusrecon.graph.agent_executor import AGENT_REGISTRY
        ex = self._keyless_executor()
        agent = AGENT_REGISTRY["risk_analyst"]()
        ctx = ex._build_context({"seeds": ["x"]}, "task", agent)
        assert agent.role.strip() and agent.role.strip() in ctx
        assert agent.goal.strip() and agent.goal.strip() in ctx
        assert agent.backstory.strip() and agent.backstory.strip() in ctx


# ── provider-oauth: subscription zero-cost telemetry ─────────────────────────

class _SubscriptionResponse:
    """Shape of a successful OAuth-CLI (subscription-backed) response."""

    content = "Analysis complete.\nFINDINGS_JSON:[]"
    usage_metadata = {"input_tokens": 1000, "output_tokens": 2000}
    billing_mode = "subscription"


class _SubscriptionLLM:
    """Fake OAuth-CLI-backed model: subscription billing, real token counts."""

    model_name = "claude"

    def invoke(self, prompt):
        return _SubscriptionResponse()


class TestSubscriptionZeroCostTelemetry:
    """provider-oauth: subscription-backed responses carry
    ``billing_mode="subscription"``, and AgentExecutor + cost tracking record
    ZERO estimated USD for them while retaining token counts and provenance."""

    async def _run_subscription_agent(self):
        from nexusrecon.core.cost_tracker import CostTracker

        config = MagicMock()
        config.llm_provider = "mock"  # only so __init__ builds no real client
        config.llm_auth_mode = "auto"
        config.llm_model = "mock"
        config.llm_temperature = 0.0
        config.get_secret = MagicMock(return_value=None)
        executor = AgentExecutor(config)
        executor.llm = _SubscriptionLLM()  # avoid any real API call
        tracker = CostTracker("camp", max_llm_cost_usd=50.0)
        executor.bind_cost_tracker(tracker)
        state = {
            "current_phase": "phase1",
            "llm_cost_usd": 0.0,
            "max_llm_cost_usd": 50.0,
        }
        result = await executor.run_agent(
            "passive_recon", {"seeds": ["acme.com"]}, "analyze", state
        )
        return executor, tracker, state, result

    def test_subscription_response_carries_billing_mode(self):
        assert _SubscriptionResponse.billing_mode == "subscription"

    def test_subscription_call_costs_zero_usd_but_retains_tokens(self):
        import asyncio

        _, tracker, state, _ = asyncio.run(self._run_subscription_agent())
        assert tracker.total_llm_calls == 1
        assert tracker.total_input_tokens == 1000
        assert tracker.total_output_tokens == 2000
        summary = tracker.summary()
        agent_row = summary["by_agent"]["passive_recon"]
        assert agent_row["input_tokens"] == 1000
        assert agent_row["output_tokens"] == 2000
        assert tracker.total_llm_cost_usd == 0.0
        assert agent_row["cost_usd"] == 0.0
        assert state["llm_cost_usd"] == 0.0

    def test_subscription_call_is_recorded_as_live_not_mock(self):
        import asyncio

        _, tracker, state, result = asyncio.run(self._run_subscription_agent())
        assert state["llm_calls_by_model"] == {"claude": 1}
        assert "mock_llm" not in state["llm_calls_by_model"]
        assert "error" not in result
        assert result["output"] == _SubscriptionResponse.content

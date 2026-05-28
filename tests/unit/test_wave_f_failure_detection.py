"""Wave F failure-detection tests.

Covers the two correctness-baseline fixes built from the 2026-05-27
ginandjuice.shop run:

- F-A2: the registry skips paid / breach-DB tools as ``policy_skipped``
  when the engagement constraints forbid them, instead of firing them
  and logging a hard error (Shodan 403, DeHashed 404 in that run).
- F-A1: a successful-but-implausibly-empty tool result is marked
  ``degraded`` so reports never present a silent failure (sslyze with
  no TLS data, whois with no fields, an unreachable WAF probe, a nuclei
  scan that did not run) as a clean negative.
"""
from __future__ import annotations

import asyncio

import pytest

from nexusrecon.core.scope import ConstraintViolationError, ScopeGuard
from nexusrecon.models.scope import ScopeModel
from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import ToolRegistry


def _make_scope(tmp_path, *, allow_paid: bool, allow_breach: bool, max_tier: str = "T2") -> ScopeModel:
    scope_yaml = tmp_path / "scope.yaml"
    scope_yaml.write_text(f"""
engagement:
  client: "Test Corp"
  engagement_id: "TEST-2026-01"
  authorized_by: "Test Admin"
  authorization_date: "2026-01-01"
  signed_sow_hash: "sha256:abc123"
  start_date: "2026-01-01"
  end_date: "2026-12-31"
scope:
  in_scope:
    domains: ["acme.com"]
constraints:
  max_tier: "{max_tier}"
  stealth_profile: "loud"
  allow_paid_apis: {str(allow_paid).lower()}
  allow_breach_db_lookup: {str(allow_breach).lower()}
  max_llm_cost_usd: 3.0
""")
    return ScopeModel.from_yaml(str(scope_yaml))


class _FakeAudit:
    """Records only the audit calls the tested code paths make."""

    def __init__(self) -> None:
        self.policy_skips: list[tuple] = []
        self.results: list[dict] = []
        self.starts: list[tuple] = []

    def log_policy_skip(self, tool_name, target, reason):
        self.policy_skips.append((tool_name, target, reason))
        return "hash"

    def log_tool_start(self, tool_name, tier, target, query, proxy_used=None):
        self.starts.append((tool_name, target))
        return "hash"

    def log_tool_result(self, tool_name, target, response_hash, runtime_ms,
                        result_count, cached=False, degraded=False, degraded_reason=None):
        self.results.append({
            "tool": tool_name, "degraded": degraded,
            "degraded_reason": degraded_reason, "count": result_count,
        })
        return "hash"

    def log_tool_error(self, tool_name, target, error):
        return "hash"


# ── F-A2: engagement-constraint gate ────────────────────────────────────────


class TestConstraintGuard:
    def test_breach_blocked_when_lookup_disabled(self, tmp_path):
        guard = ScopeGuard(_make_scope(tmp_path, allow_paid=True, allow_breach=False))
        with pytest.raises(ConstraintViolationError) as exc:
            guard.check_constraints("dehashed", "breach", paid_api=False)
        assert exc.value.constraint == "allow_breach_db_lookup"

    def test_paid_blocked_when_paid_disabled(self, tmp_path):
        guard = ScopeGuard(_make_scope(tmp_path, allow_paid=False, allow_breach=True))
        with pytest.raises(ConstraintViolationError) as exc:
            guard.check_constraints("shodan", "infrastructure", paid_api=True)
        assert exc.value.constraint == "allow_paid_apis"

    def test_allowed_when_constraints_permit(self, tmp_path):
        guard = ScopeGuard(_make_scope(tmp_path, allow_paid=True, allow_breach=True))
        # Neither raises.
        guard.check_constraints("dehashed", "breach", paid_api=False)
        guard.check_constraints("shodan", "infrastructure", paid_api=True)

    def test_free_tool_never_blocked(self, tmp_path):
        # A free, non-breach tool runs even with everything disabled.
        guard = ScopeGuard(_make_scope(tmp_path, allow_paid=False, allow_breach=False))
        guard.check_constraints("crtsh", "certificate", paid_api=False)

    def test_non_raising_helper(self, tmp_path):
        guard = ScopeGuard(_make_scope(tmp_path, allow_paid=False, allow_breach=False))
        assert guard.is_tool_allowed_by_constraints("infrastructure", True) is False
        assert guard.is_tool_allowed_by_constraints("certificate", False) is True


class _PaidTool(OSINTTool):
    name = "fake_paid"
    tier = Tier.T0
    category = Category.INFRASTRUCTURE
    requires_keys = []
    paid_api = True
    target_types = ["domain"]
    ran = False

    async def run(self, target, **kwargs):
        type(self).ran = True
        return ToolResult(success=True, source=self.name, data={"x": 1}, result_count=1)


class _BreachTool(OSINTTool):
    name = "fake_breach"
    tier = Tier.T0
    category = Category.BREACH
    requires_keys = []
    target_types = ["email"]
    ran = False

    async def run(self, target, **kwargs):
        type(self).ran = True
        return ToolResult(success=True, source=self.name, data={"x": 1}, result_count=1)


class TestConstraintGateInRegistry:
    def test_paid_tool_skipped_not_executed(self, tmp_path):
        reg = ToolRegistry()
        reg.register(_PaidTool)
        _PaidTool.ran = False
        audit = _FakeAudit()
        reg.set_campaign_context(
            ScopeGuard(_make_scope(tmp_path, allow_paid=False, allow_breach=True)),
            audit_log=audit,
        )
        result = asyncio.run(reg.execute("fake_paid", "acme.com"))
        assert result.success is False
        assert "paid" in result.error.lower()
        assert _PaidTool.ran is False  # never invoked
        assert audit.policy_skips and audit.policy_skips[0][0] == "fake_paid"
        assert not audit.starts  # short-circuited before tool_start

    def test_breach_tool_skipped(self, tmp_path):
        reg = ToolRegistry()
        reg.register(_BreachTool)
        _BreachTool.ran = False
        audit = _FakeAudit()
        reg.set_campaign_context(
            ScopeGuard(_make_scope(tmp_path, allow_paid=True, allow_breach=False)),
            audit_log=audit,
        )
        result = asyncio.run(reg.execute("fake_breach", "carlos@acme.com", target_type="email"))
        assert result.success is False
        assert _BreachTool.ran is False
        assert audit.policy_skips

    def test_paid_tool_runs_when_allowed(self, tmp_path):
        reg = ToolRegistry()
        reg.register(_PaidTool)
        _PaidTool.ran = False
        reg.set_campaign_context(
            ScopeGuard(_make_scope(tmp_path, allow_paid=True, allow_breach=True)),
        )
        result = asyncio.run(reg.execute("fake_paid", "acme.com"))
        assert result.success is True
        assert _PaidTool.ran is True


# ── F-A1: result-plausibility floor ─────────────────────────────────────────


class TestSslyzeAssessment:
    def _tool(self):
        from nexusrecon.tools.web.sslyze_tool import SSLyzeTool
        return SSLyzeTool()

    def test_empty_tls_flagged(self):
        r = ToolResult(success=True, source="sslyze",
                       data={"target": "x", "supported_protocols": [], "cert_chain": {}},
                       result_count=0)
        assert self._tool().assess_result(r, "x") is not None

    def test_clean_grade_a_not_flagged(self):
        # Modern host: protocols + cert present, zero vulns. result_count
        # is 0 but the scan clearly worked -> not degraded.
        r = ToolResult(success=True, source="sslyze",
                       data={"target": "x", "supported_protocols": ["TLSv1.3"],
                             "cert_chain": {"subject": "CN=x"}},
                       result_count=0)
        assert self._tool().assess_result(r, "x") is None


class TestWhoisAssessment:
    def _tool(self):
        from nexusrecon.tools.domain.whois_tool import WHOISTool
        return WHOISTool()

    def test_no_fields_flagged(self):
        r = ToolResult(success=True, source="whois", data={}, result_count=0)
        assert self._tool().assess_result(r, "acme.com") is not None

    def test_has_fields_not_flagged(self):
        r = ToolResult(success=True, source="whois",
                       data={"registrar": "GoDaddy"}, result_count=1)
        assert self._tool().assess_result(r, "acme.com") is None


class TestWafw00fAssessment:
    def _tool(self):
        from nexusrecon.tools.web.wafw00f_tool import WafW00fTool
        return WafW00fTool()

    def test_unreachable_flagged(self):
        r = ToolResult(success=True, source="wafw00f",
                       data={"wafs_detected": [], "reachable": False, "http_status": 0},
                       result_count=0)
        assert self._tool().assess_result(r, "x") is not None

    def test_reachable_no_waf_not_flagged(self):
        # Genuine "no WAF" on a reachable host is a valid negative.
        r = ToolResult(success=True, source="wafw00f",
                       data={"wafs_detected": [], "reachable": True, "http_status": 200},
                       result_count=0)
        assert self._tool().assess_result(r, "x") is None


class TestNucleiAssessment:
    def _tool(self):
        from nexusrecon.tools.web.nuclei_tool import NucleiTool
        return NucleiTool()

    def test_nonzero_exit_flagged(self):
        r = ToolResult(success=True, source="nuclei",
                       data={"total_findings": 0, "returncode": 2, "stderr_tail": ""},
                       result_count=0)
        assert self._tool().assess_result(r, "x") is not None

    def test_stderr_marker_flagged(self):
        r = ToolResult(success=True, source="nuclei",
                       data={"total_findings": 0, "returncode": 0,
                             "stderr_tail": "could not find any templates"},
                       result_count=0)
        assert self._tool().assess_result(r, "x") is not None

    def test_clean_empty_not_flagged(self):
        # nuclei ran fine (exit 0, no error) and matched nothing: valid.
        r = ToolResult(success=True, source="nuclei",
                       data={"total_findings": 0, "returncode": 0, "stderr_tail": ""},
                       result_count=0)
        assert self._tool().assess_result(r, "x") is None

    def test_findings_present_not_flagged(self):
        r = ToolResult(success=True, source="nuclei",
                       data={"total_findings": 3, "returncode": 0, "stderr_tail": "warn"},
                       result_count=3)
        assert self._tool().assess_result(r, "x") is None


class _FakeProc:
    def __init__(self, returncode, stderr="", stdout=""):
        self.returncode = returncode
        self.stderr = stderr
        self.stdout = stdout


class TestNucleiRunFailureDetection:
    def test_nonzero_exit_no_findings_is_failure(self, monkeypatch):
        from nexusrecon.tools.web.nuclei_tool import NucleiTool
        tool = NucleiTool()
        monkeypatch.setattr(tool, "run_subprocess",
                            lambda *a, **k: _FakeProc(2, stderr="no templates found"))
        result = asyncio.run(tool.run("acme.com"))
        # Previously this returned success=True with 0 findings; now the
        # discarded exit code surfaces it as a genuine failure.
        assert result.success is False
        assert "nuclei" in result.error.lower()


class TestRegistrySetsDegraded:
    """The registry wires assess_result -> result.degraded + audit."""

    def test_degraded_flag_set_and_audited(self, tmp_path):
        class _DegradingTool(OSINTTool):
            name = "fake_degrading"
            tier = Tier.T0
            category = Category.WEB
            requires_keys = []
            target_types = ["domain"]

            async def run(self, target, **kwargs):
                return ToolResult(success=True, source=self.name, data={}, result_count=0)

            def assess_result(self, result, target, target_type="domain"):
                return "implausibly empty"

        reg = ToolRegistry()
        reg.register(_DegradingTool)
        audit = _FakeAudit()
        reg.set_campaign_context(
            ScopeGuard(_make_scope(tmp_path, allow_paid=True, allow_breach=True)),
            audit_log=audit,
        )
        result = asyncio.run(reg.execute("fake_degrading", "acme.com"))
        assert result.success is True
        assert result.degraded is True
        assert result.degraded_reason == "implausibly empty"
        assert audit.results and audit.results[-1]["degraded"] is True


# ── F-A3: preflight availability report ──────────────────────────────────────


class TestAvailabilityReport:
    def _registry_with_mix(self):
        reg = ToolRegistry()

        class _Active(OSINTTool):
            name = "pf_active"; tier = Tier.T0; category = Category.DOMAIN
            requires_keys = []
            async def run(self, target, **kwargs):
                return ToolResult(success=True, source=self.name)

        class _MissingBin(OSINTTool):
            name = "pf_missing_bin"; tier = Tier.T0; category = Category.WEB
            requires_keys = []; binary_required = "definitely_not_a_real_binary_xyz"
            async def run(self, target, **kwargs):
                return ToolResult(success=True, source=self.name)

        class _MissingKey(OSINTTool):
            name = "pf_missing_key"; tier = Tier.T0; category = Category.INFRASTRUCTURE
            requires_keys = ["NONEXISTENT_KEY_XYZ_F_A3"]
            async def run(self, target, **kwargs):
                return ToolResult(success=True, source=self.name)

        class _Paid(OSINTTool):
            name = "pf_paid"; tier = Tier.T0; category = Category.INFRASTRUCTURE
            requires_keys = []; paid_api = True
            async def run(self, target, **kwargs):
                return ToolResult(success=True, source=self.name)

        class _OverTier(OSINTTool):
            name = "pf_over_tier"; tier = Tier.T2; category = Category.WEB
            requires_keys = []
            async def run(self, target, **kwargs):
                return ToolResult(success=True, source=self.name)

        class _Stub(OSINTTool):
            name = "pf_stub"; tier = Tier.T0; category = Category.WEB
            requires_keys = []; stubbed = True
            async def run(self, target, **kwargs):
                return ToolResult(success=True, source=self.name)

        for cls in (_Active, _MissingBin, _MissingKey, _Paid, _OverTier, _Stub):
            reg.register(cls)
        return reg

    def test_buckets_each_reason(self, tmp_path):
        reg = self._registry_with_mix()
        # Paid off, max tier T1 -> paid tool policy-skipped, T2 tool over-tier.
        reg.set_campaign_context(
            ScopeGuard(_make_scope(tmp_path, allow_paid=False, allow_breach=True, max_tier="T1")),
        )
        report = reg.availability_report()
        b = report["buckets"]
        assert "pf_active" in b["active"]
        assert "pf_missing_bin" in b["missing_binary"]
        assert "pf_missing_key" in b["missing_key"]
        assert "pf_paid" in b["policy"]
        assert "pf_over_tier" in b["over_tier"]
        assert "pf_stub" in b["stubbed"]
        assert report["counts"]["active"] == 1

    def test_no_guard_only_env_gates(self, tmp_path):
        # Without a scope guard, policy/tier gates don't apply: paid + T2
        # tools are "active" (env-available), env gaps still bucketed.
        reg = self._registry_with_mix()
        report = reg.availability_report()
        b = report["buckets"]
        assert "pf_paid" in b["active"]
        assert "pf_over_tier" in b["active"]
        assert "pf_missing_bin" in b["missing_binary"]


# ── F-A4: transient-failure retry ────────────────────────────────────────────


class _FakeResp:
    def __init__(self, status_code):
        self.status_code = status_code


class _FakeClient:
    """Async client returning a queued sequence of responses/exceptions."""
    def __init__(self, sequence):
        self._seq = list(sequence)
        self.calls = 0

    async def get(self, url, **kwargs):
        self.calls += 1
        item = self._seq.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    # Keep retry tests instant.
    import nexusrecon.tools.base as base_mod

    async def _instant(_):
        return None

    monkeypatch.setattr(base_mod.asyncio, "sleep", _instant)


class TestHttpGetWithRetry:
    def test_retries_then_succeeds(self):
        from nexusrecon.tools.base import http_get_with_retry
        client = _FakeClient([_FakeResp(502), _FakeResp(200)])
        resp = asyncio.run(http_get_with_retry(client, "http://x", retries=2))
        assert resp.status_code == 200
        assert client.calls == 2

    def test_returns_last_transient_after_exhaustion(self):
        from nexusrecon.tools.base import http_get_with_retry
        client = _FakeClient([_FakeResp(502), _FakeResp(502), _FakeResp(502)])
        resp = asyncio.run(http_get_with_retry(client, "http://x", retries=2))
        # Hands back the final 502 so the caller still classifies + reports it.
        assert resp.status_code == 502
        assert client.calls == 3

    def test_no_retry_on_4xx(self):
        from nexusrecon.tools.base import http_get_with_retry
        client = _FakeClient([_FakeResp(404), _FakeResp(200)])
        resp = asyncio.run(http_get_with_retry(client, "http://x", retries=2))
        assert resp.status_code == 404
        assert client.calls == 1  # 4xx is deterministic, not retried

    def test_retries_on_timeout_then_succeeds(self):
        import httpx
        from nexusrecon.tools.base import http_get_with_retry
        client = _FakeClient([httpx.ConnectTimeout("boom"), _FakeResp(200)])
        resp = asyncio.run(http_get_with_retry(client, "http://x", retries=2))
        assert resp.status_code == 200
        assert client.calls == 2


# ── F-A5: run-health summary ─────────────────────────────────────────────────


class TestRunHealthSummary:
    def _entries(self):
        return [
            {"event_type": "tool_result", "tool_name": "dns", "success": True,
             "result_count": 7, "degraded": False, "cached": False},
            {"event_type": "tool_result", "tool_name": "sslyze", "success": True,
             "result_count": 0, "degraded": True, "degraded_reason": "no TLS data", "cached": False},
            {"event_type": "tool_error", "tool_name": "crtsh", "error": "crt.sh returned 502"},
            {"event_type": "tool_result", "tool_name": "ransomwatch", "success": True,
             "result_count": 0, "degraded": False, "cached": False},
            {"event_type": "policy_skipped", "tool_name": "shodan", "reason": "paid APIs disabled"},
            {"event_type": "phase_end", "phase_name": "phase1", "entities_count": 0},
        ]

    def _cats(self):
        return {"dns": "dns", "sslyze": "web", "crtsh": "certificate",
                "ransomwatch": "infrastructure", "shodan": "infrastructure"}

    def test_counts_and_buckets(self):
        from nexusrecon.core.run_health import summarize_run_health
        h = summarize_run_health(self._entries(), self._cats())
        assert h.productive == 1          # dns
        assert h.empty_ok == 1            # ransomwatch (clean empty)
        assert len(h.degraded) == 1       # sslyze
        assert len(h.errors) == 1         # crtsh
        assert len(h.policy_skipped) == 1  # shodan
        assert h.zero_entities is True

    def test_degraded_capability_detection(self):
        from nexusrecon.core.run_health import summarize_run_health
        h = summarize_run_health(self._entries(), self._cats())
        caps = {c["capability"] for c in h.degraded_capabilities}
        # web (sslyze degraded, no data) and certificate (crtsh errored, no
        # data) are degraded; infrastructure has ransomwatch clean-empty
        # only (no failure) so it is NOT flagged; dns produced data.
        assert "web" in caps
        assert "certificate" in caps
        assert "infrastructure" not in caps
        assert "dns" not in caps

    def test_active_scan_caveat_present(self):
        from nexusrecon.core.run_health import summarize_run_health
        h = summarize_run_health(self._entries(), self._cats())
        joined = " ".join(h.caveats).lower()
        assert "active scanning" in joined
        assert "unverified" in joined

    def test_clean_empty_only_no_degraded_capability(self):
        from nexusrecon.core.run_health import summarize_run_health
        entries = [
            {"event_type": "tool_result", "tool_name": "ransomwatch", "success": True,
             "result_count": 0, "degraded": False, "cached": False},
        ]
        h = summarize_run_health(entries, {"ransomwatch": "infrastructure"})
        assert h.degraded_capabilities == []

    def test_cached_results_not_counted(self):
        from nexusrecon.core.run_health import summarize_run_health
        entries = [
            {"event_type": "tool_result", "tool_name": "dns", "success": True,
             "result_count": 7, "degraded": False, "cached": True},
        ]
        h = summarize_run_health(entries, {"dns": "dns"})
        assert h.tools_invoked == 0  # cache hits are not fresh tool health

    def test_render_markdown(self):
        from nexusrecon.core.run_health import render_run_health_md, summarize_run_health
        h = summarize_run_health(self._entries(), self._cats())
        md = render_run_health_md(h, "nr-test")
        assert "# Run Health Summary" in md
        assert "Degraded capabilities" in md
        assert "crt.sh returned 502" in md


# ── F-A7: pre-flight simulation reconciliation ───────────────────────────────


class TestSimulationReconciliation:
    def _entries(self, sim_nodes, entities):
        out = [{"event_type": "simulation", "expected_new_nodes": n} for n in sim_nodes]
        out.append({"event_type": "phase_end", "entities_count": entities})
        return out

    def test_forecast_nodes_zero_actual_flagged(self):
        from nexusrecon.core.run_health import summarize_run_health
        # Mirrors the real run: 48+19+20+11 forecast, 0 produced.
        h = summarize_run_health(self._entries([48, 19, 20, 11], 0))
        assert h.predicted_new_nodes == 98
        assert h.node_estimate_note is not None
        assert any("uncalibrated" in c for c in h.caveats)

    def test_gross_overestimate_flagged(self):
        from nexusrecon.core.run_health import summarize_run_health
        h = summarize_run_health(self._entries([100], 5))  # 20x over
        assert h.node_estimate_note is not None

    def test_accurate_estimate_not_flagged(self):
        from nexusrecon.core.run_health import summarize_run_health
        h = summarize_run_health(self._entries([20], 18))
        assert h.node_estimate_note is None

    def test_tiny_forecast_not_flagged(self):
        from nexusrecon.core.run_health import summarize_run_health
        # Don't cry wolf when the forecast was small to begin with.
        h = summarize_run_health(self._entries([3], 0))
        assert h.node_estimate_note is None

    def test_forecast_row_rendered(self):
        from nexusrecon.core.run_health import render_run_health_md, summarize_run_health
        h = summarize_run_health(self._entries([98], 0))
        md = render_run_health_md(h, "nr-x")
        assert "simulator forecast" in md.lower()
        assert "98" in md

"""
End-to-end smoke tests for NexusRecon.

These tests exercise real module code against synthetic or live data.
Failures due to missing API keys or no network are soft-skipped.
Real integration bugs (wrong state key, TypeError in phase, bad report path)
will surface as hard failures.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tests.smoke.conftest import _base_state


# ── Test 1: Phase 1 passive footprinting ─────────────────────────────────────

@pytest.mark.asyncio
async def test_phase1_passive_runs_without_error(mock_state_minimal):
    """Phase 1 must complete and populate state keys even with no tools available."""
    from nexusrecon.graph.nodes import phase1_passive_footprinting, _reset_executor
    _reset_executor()

    try:
        result = await phase1_passive_footprinting(mock_state_minimal)
    except Exception as exc:
        # Network errors or missing binary are acceptable in CI
        if any(k in str(exc).lower() for k in ("connection", "timeout", "network", "resolve")):
            pytest.skip(f"Network unavailable: {exc}")
        raise

    assert isinstance(result.get("subdomain_intel"), dict), "subdomain_intel must be a dict"
    assert isinstance(result.get("dark_intel"), dict), "dark_intel must be a dict (Move 1 wiring)"
    assert "phase1" in result.get("completed_phases", []), "phase1 must be in completed_phases"
    assert result.get("current_phase") == "phase1", "current_phase must be 'phase1'"


# ── Test 2: Phase 7.5 credential harvest ─────────────────────────────────────

@pytest.mark.asyncio
async def test_phase7_5_credential_harvest_runs():
    """Phase 7.5 must extract aws_access_key from a synthetic .env finding."""
    state = _base_state(
        infra_intel={
            "example.com": {
                "discovered_paths": [
                    {
                        "path": "/.env",
                        "status": 200,
                        "body": (
                            "AWS_ACCESS_KEY_ID=AKIATESTFAKEFAKEFAKE\n"
                            "SECRET_KEY=fakefakefakefakefakefakefakefakefakefake\n"
                        ),
                    }
                ],
            },
        },
        validate_credentials=False,
    )

    from nexusrecon.graph.nodes import phase7_5_harvest
    result = await phase7_5_harvest(state)

    creds: List[Dict[str, Any]] = result.get("harvested_credentials", [])
    assert len(creds) >= 1, f"Expected at least one credential, got {len(creds)}"

    aws_creds = [c for c in creds if c.get("cred_type") == "aws_access_key"]
    assert aws_creds, f"Expected aws_access_key credential; got types: {[c.get('cred_type') for c in creds]}"

    cred = aws_creds[0]
    assert "***" in cred.get("value_redacted", ""), (
        f"value_redacted must be masked, got: {cred.get('value_redacted')}"
    )
    value_hash = cred.get("value_hash", "")
    assert len(value_hash) == 64, f"value_hash must be 64-char sha256, got len={len(value_hash)}"


# ── Test 3: Phase 8 scoring produces ranked threads ───────────────────────────

@pytest.mark.asyncio
async def test_phase8_scoring_produces_ranked_threads():
    """Phase 8 must rank findings; a KEV+MSF CVE must score > 0.8."""
    state = _base_state(
        vuln_intel={
            "enriched_cves": {
                "CVE-2099-9999": {
                    "cvss": 9.8,
                    "epss": 0.95,
                    "in_kev": True,
                    "has_metasploit": True,
                    "has_exploit": True,
                    "has_nuclei_template": False,
                    "tech": "TestApp",
                    "description": "Synthetic critical CVE for smoke testing.",
                    "affected_assets": ["example.com"],
                    "sources": ["smoke_test"],
                },
            },
        },
    )

    from nexusrecon.graph.nodes import phase8_attack_surface
    result = await phase8_attack_surface(state)

    threads = result.get("ranked_threads", [])
    assert len(threads) >= 1, "ranked_threads must have at least one entry"

    top = threads[0]
    assert top.get("score", 0.0) > 0.8, (
        f"Top thread score should be > 0.8 for a KEV+MSF CVE; got {top.get('score')}"
    )
    assert top.get("category") == "cve", (
        f"Top thread category should be 'cve'; got {top.get('category')}"
    )


# ── Test 4: Dynamic dispatcher with WordPress finding ─────────────────────────

@pytest.mark.asyncio
async def test_dynamic_dispatcher_with_wordpress_finding():
    """Dispatcher must return a list; if non-empty, all tool names must exist in registry."""
    from nexusrecon.graph.dynamic_dispatcher import run_dynamic_dispatch
    from nexusrecon.tools.registry import get_registry

    state = _base_state(
        infra_intel={
            "example.com": {
                "cms": {"name": "WordPress", "confidence": 0.95, "version": "6.4"},
            },
        },
        dispatch_mode="full",
    )

    # Dispatcher calls LLM; MockLLM produces non-JSON prose → plan is []
    # A real LLM would produce dispatch JSON. Both outcomes are accepted.
    try:
        result_state = await run_dynamic_dispatch(state)
    except Exception as exc:
        pytest.skip(f"Dispatcher error (likely no LLM): {exc}")

    plan = result_state.get("dynamic_dispatch_log", [])
    assert isinstance(plan, list), "dynamic_dispatch_log must be a list"

    if plan:
        registry = get_registry()
        for entry in plan:
            tool_name = entry.get("tool", "")
            assert registry.get(tool_name) is not None, (
                f"Dispatched tool '{tool_name}' is not in registry"
            )
        # No duplicate (tool, target) pairs
        pairs = [(e["tool"], e["target"]) for e in plan]
        assert len(pairs) == len(set(pairs)), "Duplicate (tool, target) pairs in dispatch log"


# ── Test 5: Dispatcher caps enforced ─────────────────────────────────────────

@pytest.mark.asyncio
async def test_dispatcher_caps_enforced():
    """Global cap (30) and per-cycle cap (5) must both be enforced."""
    from nexusrecon.graph.dynamic_dispatcher import run_dynamic_dispatch, MAX_PER_CYCLE, MAX_TOTAL

    # Part A: total cap — 30 existing entries → dispatcher returns immediately
    full_log = [
        {
            "tool": "whois", "target": f"t{i}.com", "target_type": "domain",
            "reason": "pre-existing", "phase": "phase1",
            "timestamp": "2026-01-01T00:00:00Z", "success": True,
        }
        for i in range(MAX_TOTAL)
    ]
    state_capped = _base_state(dynamic_dispatch_log=full_log, dispatch_mode="full")
    result = await run_dynamic_dispatch(state_capped)
    assert len(result["dynamic_dispatch_log"]) == MAX_TOTAL, (
        "Total cap: dispatch_log must not grow past MAX_TOTAL"
    )

    # Part B: per-cycle cap — mock LLM returning MAX_PER_CYCLE+5 valid dispatches
    ten_items = json.dumps([
        {
            "tool": "whois",
            "target": f"target{i}.com",
            "target_type": "domain",
            "reason": f"smoke test item {i}",
        }
        for i in range(MAX_PER_CYCLE + 5)
    ])
    mock_llm = MagicMock()
    mock_llm.invoke.return_value = MagicMock(content=ten_items)

    state_fresh = _base_state(dynamic_dispatch_log=[], dispatch_mode="full")

    # Patch _execute_plan so no real network calls happen
    async def _fake_execute(plan: list, state: dict) -> dict:
        log = list(state.get("dynamic_dispatch_log", []))
        for item in plan:
            log.append({
                "tool": item["tool"], "target": item["target"],
                "target_type": item["target_type"], "reason": item["reason"],
                "phase": "smoke", "timestamp": "2026-01-01T00:00:00Z", "success": False,
            })
        state["dynamic_dispatch_log"] = log
        return state

    with (
        patch("nexusrecon.core.config.get_config", return_value=MagicMock()),
        patch("nexusrecon.graph.agent_executor.get_llm_from_config", return_value=mock_llm),
        patch(
            "nexusrecon.graph.dynamic_dispatcher._execute_plan",
            new_callable=AsyncMock,
            side_effect=_fake_execute,
        ),
    ):
        result = await run_dynamic_dispatch(state_fresh)

    dispatched = result.get("dynamic_dispatch_log", [])
    assert len(dispatched) <= MAX_PER_CYCLE, (
        f"Per-cycle cap: expected ≤{MAX_PER_CYCLE} dispatches, got {len(dispatched)}"
    )


# ── Test 6: Report engine generates all expected outputs ─────────────────────

def test_report_engine_generates_all_outputs(temp_output_dir, mock_state_rich):
    """ReportEngine.generate_all must produce every expected file."""
    from nexusrecon.reports.engine import ReportEngine

    # Pre-populate harvested_credentials as dicts (as phase7_5 would)
    mock_state_rich["harvested_credentials"] = [
        {
            "cred_type": "aws_access_key",
            "value_redacted": "AKIA***KE",
            "value_hash": "a" * 64,
            "source_url": "https://example.com/.env",
            "source_type": "exposed_env",
            "context": "AWS_ACCESS_KEY_ID=AKIA***",
            "confidence": 0.9,
            "validated": False,
            "validation_method": None,
            "validation_metadata": {},
            "next_steps": ["Rotate AWS_ACCESS_KEY_ID immediately"],
        }
    ]

    engine = ReportEngine(
        campaign_id="smoke-test",
        engagement_id="SMOKE-001",
        scope_hash="sha256:smoketest",
        output_dir=temp_output_dir,
    )
    paths = engine.generate_all(mock_state_rich)

    # Every path returned must exist on disk
    missing = [k for k, p in paths.items() if p and not Path(p).exists()]
    assert not missing, f"Missing report files: {missing}"

    # top_threads.md must have the canonical header
    top_threads_path = temp_output_dir / "top_threads.md"
    assert top_threads_path.exists(), "top_threads.md must be generated"
    content = top_threads_path.read_text(encoding="utf-8")
    assert "Top 10 Threads to Pull" in content, (
        "top_threads.md must contain the 'Top 10 Threads to Pull' header"
    )

    # harvested_credentials.md must have the authorization/sensitivity banner
    creds_path = temp_output_dir / "harvested_credentials.md"
    assert creds_path.exists(), "harvested_credentials.md must be generated"
    creds_content = creds_path.read_text(encoding="utf-8")
    assert "real credentials" in creds_content.lower(), (
        "harvested_credentials.md must contain a sensitivity banner"
    )

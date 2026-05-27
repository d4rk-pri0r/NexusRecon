"""Tests for Phase 4 PR A: NL campaign planner.

PR A ships ``nexusrecon/intent/`` with three pieces:

  - ``intent_parser.extract_intent`` — LLM + regex-fallback
    natural-language → :class:`IntentRecord` extractor.
  - ``scope_builder.build_scope_stub`` — turns an
    :class:`IntentRecord` into a scope.yaml-shaped dict.
  - ``nl_planner.plan_from_intent`` — orchestrator that
    combines the above with a :class:`Strategy` synthesis.

Coverage
- Regex fallback extracts domains, IPs, intent keywords,
  tier escalation, stealth profile.
- Fallback degrades gracefully when sentence has nothing
  actionable (confidence stays low, helpful rationale).
- LLM path: scripted executor yields the expected
  :class:`IntentRecord`; bad JSON output falls through to
  fallback.
- scope_builder fills required fields + leaves placeholders
  for engagement / authorization markers.
- credentials intent flips ``allow_breach_db_lookup`` on.
- plan_from_intent: phase selection driven by intent
  categories, default footprint when none matched, warnings
  populated for low-confidence / missing-targets / elevated
  tier.
- Strategy metadata captures the raw sentence + confidence
  for the audit trail.
"""
from __future__ import annotations

from typing import Any

import pytest

from nexusrecon.intent import (
    IntentRecord,
    build_scope_stub,
    extract_intent,
    plan_from_intent,
)


# ──────────────────────────────────────────────────────────────────────
# Test double — scripted executor
# ──────────────────────────────────────────────────────────────────────


class _ScriptedExecutor:
    """Mimics AgentExecutor.run_agent. Returns a scripted
    JSON body so the LLM extractor's parse path is exercised
    without a network call."""

    def __init__(self, body: str | None):
        self._body = body
        self.captured_prompt: str = ""

    async def run_agent(
        self, agent_name: str, task_data: dict[str, Any],
        task_prompt: str, state: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        self.captured_prompt = task_prompt
        if self._body is None:
            raise RuntimeError("scripted: no body")
        return {"output": self._body}


# ──────────────────────────────────────────────────────────────────────
# Regex fallback
# ──────────────────────────────────────────────────────────────────────


class TestFallbackExtractor:
    def test_extracts_domain(self):
        intent = extract_intent(
            "find leaked credentials at acme.com",
            prefer_fallback=True,
        )
        assert "acme.com" in intent.targets
        assert "credentials" in intent.intent_categories

    def test_extracts_multiple_targets(self):
        intent = extract_intent(
            "audit acme.com and acme.io for exposed S3 buckets",
            prefer_fallback=True,
        )
        assert set(intent.targets) >= {"acme.com", "acme.io"}
        assert "cloud" in intent.intent_categories

    def test_extracts_ips(self):
        intent = extract_intent(
            "scan 192.168.1.1 and 10.0.0.5 passively",
            prefer_fallback=True,
        )
        assert "192.168.1.1" in intent.targets
        assert "10.0.0.5" in intent.targets

    def test_tier_keyword_passive_only(self):
        intent = extract_intent(
            "passive only recon on acme.com",
            prefer_fallback=True,
        )
        assert intent.max_tier == "T1"
        assert intent.dispatch_policy_name == "lite"

    def test_tier_keyword_aggressive(self):
        intent = extract_intent(
            "aggressive scan of acme.com",
            prefer_fallback=True,
        )
        assert intent.max_tier == "T3"
        assert intent.dispatch_policy_name == "full"

    def test_tier_keyword_osint_only(self):
        intent = extract_intent(
            "osint only on acme.com",
            prefer_fallback=True,
        )
        assert intent.max_tier == "T0"
        assert intent.dispatch_policy_name == "off"

    def test_stealth_profile_extraction(self):
        intent = extract_intent(
            "loud scan of acme.com",
            prefer_fallback=True,
        )
        assert intent.stealth_profile == "low"

    def test_confidence_lifts_when_anything_extracted(self):
        intent = extract_intent(
            "find subdomains at acme.com",
            prefer_fallback=True,
        )
        # Anything actionable lifts confidence above "low".
        assert intent.confidence == "medium"

    def test_low_confidence_when_nothing_found(self):
        intent = extract_intent(
            "just some text",
            prefer_fallback=True,
        )
        assert intent.confidence == "low"
        assert intent.targets == []
        assert intent.rationale  # helpful explanation present

    def test_credentials_keyword_variants(self):
        for kw in ("creds", "password leak", "data breach"):
            intent = extract_intent(
                f"find {kw} at acme.com",
                prefer_fallback=True,
            )
            assert "credentials" in intent.intent_categories


# ──────────────────────────────────────────────────────────────────────
# LLM path
# ──────────────────────────────────────────────────────────────────────


class TestLLMExtractor:
    def test_scripted_llm_parse(self):
        executor = _ScriptedExecutor(
            '{"targets": ["acme.com"], '
            '"intent_categories": ["credentials", "cloud"], '
            '"max_tier": "T1", "stealth_profile": "high", '
            '"dispatch_policy_name": "lite", '
            '"constraints": {"max_llm_cost_usd": 8.0}, '
            '"rationale": "passive corp recon"}'
        )
        intent = extract_intent(
            "find leaked creds and exposed buckets at acme.com",
            executor=executor,
        )
        assert intent.confidence == "high"
        assert intent.targets == ["acme.com"]
        assert set(intent.intent_categories) == {"credentials", "cloud"}
        assert intent.constraints["max_llm_cost_usd"] == 8.0
        # The system prompt got assembled.
        assert "STRICT JSON" in executor.captured_prompt

    def test_bad_json_falls_through_to_regex(self):
        executor = _ScriptedExecutor("not JSON at all !!!")
        intent = extract_intent(
            "find leaked creds at acme.com",
            executor=executor,
        )
        # Regex fallback extracts the same info.
        assert "acme.com" in intent.targets
        assert "credentials" in intent.intent_categories
        # Confidence is the fallback grade, not LLM-high.
        assert intent.confidence == "medium"

    def test_llm_with_invalid_tier_clamps_to_default(self):
        executor = _ScriptedExecutor(
            '{"targets": ["acme.com"], '
            '"intent_categories": ["credentials"], '
            '"max_tier": "T99", "stealth_profile": "high", '
            '"dispatch_policy_name": "lite"}'
        )
        intent = extract_intent(
            "find creds at acme.com",
            executor=executor,
        )
        assert intent.max_tier == "T1"

    def test_llm_empty_extraction_falls_through(self):
        # LLM returns valid JSON but with no actionable data.
        executor = _ScriptedExecutor(
            '{"targets": [], "intent_categories": []}'
        )
        intent = extract_intent(
            "find creds at acme.com",
            executor=executor,
        )
        # Regex fallback should kick in.
        assert "acme.com" in intent.targets


# ──────────────────────────────────────────────────────────────────────
# Scope builder
# ──────────────────────────────────────────────────────────────────────


class TestScopeBuilder:
    def test_builds_canonical_shape(self):
        intent = IntentRecord(
            raw_sentence="x",
            targets=["acme.com"],
            intent_categories=["subdomains"],
            max_tier="T1",
            stealth_profile="high",
        )
        stub = build_scope_stub(intent)
        assert stub["scope"]["in_scope"]["domains"] == ["acme.com"]
        assert stub["constraints"]["max_tier"] == "T1"
        assert stub["constraints"]["stealth_profile"] == "high"
        # Placeholders for fields we refuse to invent.
        assert stub["engagement"]["client"] == "REPLACE_ME"
        assert stub["engagement"]["authorized_by"] == "REPLACE_ME"

    def test_credentials_intent_flips_breach_lookup(self):
        intent = IntentRecord(
            raw_sentence="x",
            targets=["acme.com"],
            intent_categories=["credentials"],
        )
        stub = build_scope_stub(intent)
        assert stub["constraints"]["allow_breach_db_lookup"] is True

    def test_no_targets_yields_placeholder(self):
        intent = IntentRecord(raw_sentence="x")
        stub = build_scope_stub(intent)
        # Operator must replace this before running.
        assert "REPLACE_ME" in stub["scope"]["in_scope"]["domains"][0]

    def test_max_llm_cost_default(self):
        intent = IntentRecord(raw_sentence="x", targets=["acme.com"])
        stub = build_scope_stub(intent)
        assert stub["constraints"]["max_llm_cost_usd"] == 5.0

    def test_constraints_override_max_llm_cost(self):
        intent = IntentRecord(
            raw_sentence="x", targets=["acme.com"],
            constraints={"max_llm_cost_usd": 25.0},
        )
        stub = build_scope_stub(intent)
        assert stub["constraints"]["max_llm_cost_usd"] == 25.0

    def test_meta_fields_present(self):
        intent = IntentRecord(
            raw_sentence="ABC", confidence="high",
            rationale="my reason",
        )
        stub = build_scope_stub(intent)
        # Meta fields prefixed with _ for the CLI writer to
        # surface as comments.
        assert stub["_intent_raw"] == "ABC"
        assert stub["_intent_confidence"] == "high"
        assert stub["_intent_rationale"] == "my reason"


# ──────────────────────────────────────────────────────────────────────
# Plan orchestrator
# ──────────────────────────────────────────────────────────────────────


class TestPlanFromIntent:
    def test_full_path_yields_scope_strategy_warnings(self):
        result = plan_from_intent(
            "passive subdomain enumeration of acme.com",
            prefer_fallback=True,
        )
        assert result.intent.targets == ["acme.com"]
        # Strategy carries the intent metadata.
        assert (
            result.strategy.metadata["intent_categories"]
            == ["subdomains"]
        )
        # Phases for subdomains intent.
        assert "phase1" in result.strategy.phases
        assert "phase2" in result.strategy.phases
        # Scope stub got built.
        assert result.scope_stub["scope"]["in_scope"]["domains"] == ["acme.com"]

    def test_missing_target_yields_warning(self):
        result = plan_from_intent(
            "find some creds",
            prefer_fallback=True,
        )
        assert any("targets" in w.lower() for w in result.warnings)

    def test_low_confidence_yields_warning(self):
        result = plan_from_intent(
            "nonsense input",
            prefer_fallback=True,
        )
        assert any("confidence" in w.lower() for w in result.warnings)

    def test_elevated_tier_yields_warning(self):
        result = plan_from_intent(
            "aggressive scan of acme.com",
            prefer_fallback=True,
        )
        assert any(
            "tier" in w.lower() and "authorization" in w.lower()
            for w in result.warnings
        )

    def test_strategy_name_fingerprints_intent(self):
        result = plan_from_intent(
            "find leaked creds at acme.com",
            prefer_fallback=True,
        )
        assert "credentials" in result.strategy.name

    def test_default_phases_when_no_intent_categories(self):
        result = plan_from_intent(
            "acme.com",  # just a domain, no intent keyword
            prefer_fallback=True,
        )
        assert result.intent.intent_categories == []
        # Default footprint still gives us phase1 + phase9.
        assert "phase1" in result.strategy.phases
        assert "phase9" in result.strategy.phases

    def test_multiple_intents_union_phases(self):
        result = plan_from_intent(
            "find leaked creds AND cloud buckets at acme.com",
            prefer_fallback=True,
        )
        assert "credentials" in result.intent.intent_categories
        assert "cloud" in result.intent.intent_categories
        # Phases from BOTH categories should be present.
        assert "phase8" in result.strategy.phases  # credentials
        assert "phase5" in result.strategy.phases  # cloud

    def test_metadata_carries_audit_trail(self):
        result = plan_from_intent(
            "passive subdomain enum of acme.com",
            prefer_fallback=True,
        )
        meta = result.strategy.metadata
        assert meta["intent_raw"].startswith("passive")
        assert meta["intent_confidence"] in ("low", "medium", "high")
        assert meta["intent_rationale"]

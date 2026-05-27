"""Tests for Phase 1 PR A: Strategy + DispatchPolicy.

The scaffold for the strategic reasoning engine described in
``IMPLEMENTATION_PLAN_METASPLOIT_OSINT.md§Phase 1``. PR A
introduces the ``nexusrecon.strategy`` package without
changing campaign behavior; this file pins what the new
surface promises.

Coverage
- ``DispatchPolicy`` ABC + the three bundled policies
  (``LitePolicy`` / ``FullPolicy`` / ``OffPolicy``) carry the
  caps + phase-eligibility rules that previously lived as
  module-level constants in ``dynamic_dispatcher.py``.
- ``get_policy(name)`` resolves bundled policies + falls back
  to lite on unknowns (same posture as the pre-existing
  dispatch_mode handling).
- ``Strategy`` dataclass round-trips through ``to_dict`` /
  ``from_dict`` with default values restored on missing keys.
- ``Strategy.default()`` matches today's hardcoded behavior
  (lite dispatch, all phases enabled).
- The dispatcher's ``_resolve_policy`` honors the precedence
  documented in its docstring.
"""
from __future__ import annotations

import pytest

from nexusrecon.strategy import (
    DispatchPolicy,
    FullPolicy,
    LitePolicy,
    OffPolicy,
    Strategy,
    get_policy,
)
from nexusrecon.strategy.plan import KillCriterion, SuccessCriterion


# ──────────────────────────────────────────────────────────────────────
# Policy bundle
# ──────────────────────────────────────────────────────────────────────


class TestLitePolicy:
    """LitePolicy preserves the previous module-level constant
    values byte-for-byte. If these drift the operator-facing
    behavior of ``--dispatch-mode lite`` quietly changes."""

    def test_name(self):
        assert LitePolicy().name == "lite"

    def test_caps_match_previous_constants(self):
        p = LitePolicy()
        assert p.max_per_cycle == 5
        assert p.max_total == 30

    def test_eligible_phases_match_previous_constant(self):
        p = LitePolicy()
        assert p.eligible_phases == frozenset({"phase1", "phase4", "phase7"})

    def test_should_dispatch_only_for_eligible_phases(self):
        p = LitePolicy()
        assert p.should_dispatch_for_phase("phase1")
        assert p.should_dispatch_for_phase("phase4")
        assert p.should_dispatch_for_phase("phase7")
        assert not p.should_dispatch_for_phase("phase2")
        assert not p.should_dispatch_for_phase("phase8")


class TestFullPolicy:
    def test_name(self):
        assert FullPolicy().name == "full"

    def test_caps(self):
        p = FullPolicy()
        assert p.max_per_cycle == 5
        assert p.max_total == 50  # higher than lite — more reflections

    def test_dispatches_for_every_phase(self):
        p = FullPolicy()
        for phase in ("phase1", "phase2", "phase5", "phase7_5", "phase9"):
            assert p.should_dispatch_for_phase(phase), phase


class TestOffPolicy:
    def test_name(self):
        assert OffPolicy().name == "off"

    def test_zero_caps(self):
        p = OffPolicy()
        assert p.max_per_cycle == 0
        assert p.max_total == 0

    def test_never_dispatches(self):
        p = OffPolicy()
        for phase in ("phase1", "phase4", "phase7", "phase9"):
            assert not p.should_dispatch_for_phase(phase), phase


# ──────────────────────────────────────────────────────────────────────
# Policy resolution
# ──────────────────────────────────────────────────────────────────────


class TestGetPolicy:
    @pytest.mark.parametrize(
        "name,cls",
        [
            ("lite", LitePolicy),
            ("full", FullPolicy),
            ("off",  OffPolicy),
        ],
    )
    def test_bundled_names_resolve(self, name: str, cls: type):
        assert isinstance(get_policy(name), cls)

    def test_case_insensitive(self):
        assert isinstance(get_policy("LITE"), LitePolicy)
        assert isinstance(get_policy("Full"), FullPolicy)

    def test_unknown_name_falls_back_to_lite(self):
        """Same posture as the pre-existing dispatch_mode
        handling: a typo doesn't break the campaign, it just
        runs in lite mode. The dispatcher's audit log
        records the resolved policy name so the fallback is
        observable."""
        assert isinstance(get_policy("nonexistent"), LitePolicy)
        assert isinstance(get_policy(""), LitePolicy)


class TestRegisterPolicy:
    def test_plugin_registers_custom_policy(self):
        from dataclasses import dataclass

        from nexusrecon.strategy.policy import register_policy

        @dataclass
        class AggressivePolicy(LitePolicy):
            name: str = "aggressive"
            max_per_cycle: int = 10
            max_total: int = 100

        register_policy("aggressive", AggressivePolicy)
        try:
            policy = get_policy("aggressive")
            assert policy.name == "aggressive"
            assert policy.max_total == 100
        finally:
            # Clean up so other tests don't see the leftover.
            from nexusrecon.strategy.policy import _BUNDLED_POLICIES
            _BUNDLED_POLICIES.pop("aggressive", None)


# ──────────────────────────────────────────────────────────────────────
# Strategy
# ──────────────────────────────────────────────────────────────────────


class TestStrategy:
    def test_default_strategy_matches_legacy_behavior(self):
        """``Strategy.default()`` is what a campaign gets when
        the operator hasn't authored one. Must match today's
        hardcoded behavior so launching without explicit
        strategy stays a no-op compared to pre-Phase-1."""
        s = Strategy.default()
        assert s.name == "default"
        assert s.dispatch_policy_name == "lite"
        # Default phase order covers every phase the existing
        # workflow runs.
        for phase in (
            "phase1", "phase2", "phase2_5", "phase3", "phase4",
            "phase5", "phase6", "phase7", "phase7_5", "phase7_7",
            "phase8", "phase9",
        ):
            assert phase in s.phases, f"missing phase {phase}"

    def test_to_dict_carries_every_field(self):
        s = Strategy(
            name="corp_recon",
            phases=["phase1", "phase4"],
            dispatch_policy_name="full",
            tool_budgets={"shodan": 10},
            success_criteria=[
                SuccessCriterion(metric="confirmed_leads",
                                 op=">=", threshold=5),
            ],
            kill_criteria=[
                KillCriterion(metric="llm_cost_usd",
                              op=">", threshold=20.0, action="abort"),
            ],
            metadata={"notes": "internal red team Q4"},
        )
        d = s.to_dict()
        assert d["name"] == "corp_recon"
        assert d["phases"] == ["phase1", "phase4"]
        assert d["dispatch_policy_name"] == "full"
        assert d["tool_budgets"] == {"shodan": 10}
        assert d["success_criteria"][0]["metric"] == "confirmed_leads"
        assert d["kill_criteria"][0]["action"] == "abort"
        assert d["metadata"] == {"notes": "internal red team Q4"}

    def test_from_dict_restores(self):
        original = Strategy(
            name="x", phases=["phase1"],
            dispatch_policy_name="off",
            tool_budgets={"crtsh": 2},
            success_criteria=[
                SuccessCriterion(metric="findings", op=">", threshold=0),
            ],
        )
        restored = Strategy.from_dict(original.to_dict())
        assert restored.name == original.name
        assert restored.phases == original.phases
        assert restored.dispatch_policy_name == original.dispatch_policy_name
        assert restored.tool_budgets == original.tool_budgets
        assert len(restored.success_criteria) == 1
        assert restored.success_criteria[0].metric == "findings"

    def test_from_dict_tolerates_missing_keys(self):
        """Old strategies missing new optional fields must
        restore with dataclass defaults rather than raising."""
        partial = {"name": "minimal"}
        s = Strategy.from_dict(partial)
        assert s.name == "minimal"
        assert s.dispatch_policy_name == "lite"  # default
        assert s.kill_criteria == []
        assert s.success_criteria == []

    def test_empty_phases_in_dict_use_default(self):
        """Defensive: a strategy dict with ``phases: []`` should
        get the default phase order, not literally run zero
        phases (which would skip the whole campaign)."""
        s = Strategy.from_dict({"phases": []})
        assert "phase1" in s.phases
        assert "phase9" in s.phases


# ──────────────────────────────────────────────────────────────────────
# Dispatcher integration
# ──────────────────────────────────────────────────────────────────────


class TestDispatcherPolicyResolution:
    """``_resolve_policy(state)`` is the bridge between the
    LangGraph state and the new policy interface. Verify the
    precedence documented in its docstring."""

    def test_explicit_dispatch_policy_name_wins(self):
        from nexusrecon.graph.dynamic_dispatcher import _resolve_policy
        state = {
            "dispatch_policy_name": "full",
            "dispatch_mode": "lite",  # would lose precedence
        }
        policy = _resolve_policy(state)
        assert policy.name == "full"

    def test_falls_back_to_dispatch_mode_when_no_policy_name(self):
        from nexusrecon.graph.dynamic_dispatcher import _resolve_policy
        state = {"dispatch_mode": "off"}
        policy = _resolve_policy(state)
        assert policy.name == "off"

    def test_falls_back_to_lite_when_nothing_set(self):
        from nexusrecon.graph.dynamic_dispatcher import _resolve_policy
        policy = _resolve_policy({})
        assert policy.name == "lite"

    def test_legacy_constants_match_lite_policy(self):
        """The module-level constants on ``dynamic_dispatcher``
        survive as documentation. Verify they still match the
        LitePolicy values so any silent drift is caught."""
        from nexusrecon.graph import dynamic_dispatcher as dd
        lite = LitePolicy()
        assert dd.MAX_PER_CYCLE == lite.max_per_cycle
        assert dd.MAX_TOTAL == lite.max_total
        assert dd.LITE_DISPATCH_PHASES == lite.eligible_phases

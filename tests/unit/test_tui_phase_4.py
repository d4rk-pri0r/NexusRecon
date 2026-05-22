"""Tests for TUI-4: wizard depth (validators, preset loader, cost
estimator, summary pane, sticky pane integration).

The wizard helpers in ``nexusrecon.tui.wizard_helpers`` are pure
Python and unit-testable in isolation; the screen wires them in
through Textual's ``on_select_changed`` and ``_render_step`` hooks
and is exercised via the headless pilot harness.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import yaml

# ──────────────────────────────────────────────────────────────────────
# Validators
# ──────────────────────────────────────────────────────────────────────


class TestValidators:
    def test_required_text(self):
        from nexusrecon.tui.wizard_helpers import validate_required_text
        # Empty + whitespace → pending (not red)
        assert not validate_required_text("", label="x").valid
        assert validate_required_text("", label="x").icon == "…"
        assert not validate_required_text("   ", label="x").valid
        # Real input → ok
        assert validate_required_text("Acme", label="x").valid

    def test_domain(self):
        from nexusrecon.tui.wizard_helpers import validate_domain
        assert validate_domain("example.com").valid
        assert validate_domain("sub.example.co.uk").valid
        # Empty → pending
        assert validate_domain("").icon == "…"
        # Garbage → bad
        assert validate_domain("not a domain").icon == "✗"
        assert validate_domain("example").icon == "✗"

    def test_domain_list(self):
        from nexusrecon.tui.wizard_helpers import validate_domain_list
        assert validate_domain_list("").valid  # empty is ok (optional)
        assert validate_domain_list("a.com, b.org").valid
        assert validate_domain_list("a.com, garbage").icon == "✗"

    def test_wildcard_list(self):
        from nexusrecon.tui.wizard_helpers import validate_wildcard_list
        assert validate_wildcard_list("").valid
        assert validate_wildcard_list("*.aws.amazon.com, *.cdn.com").valid
        assert validate_wildcard_list("example.com").valid  # bare FQDN also ok
        assert validate_wildcard_list("*not_a_domain").icon == "✗"

    def test_iso_date(self):
        from nexusrecon.tui.wizard_helpers import validate_iso_date
        assert validate_iso_date("2026-05-21").valid
        assert validate_iso_date("").icon == "…"
        assert validate_iso_date("2026/05/21").icon == "✗"
        assert validate_iso_date("not-a-date").icon == "✗"

    def test_sow_hash(self):
        from nexusrecon.tui.wizard_helpers import validate_sow_hash
        # Placeholder accepted (test mode)
        assert validate_sow_hash("placeholder").valid
        assert validate_sow_hash("PLACEHOLDER").valid
        # 64-hex valid
        assert validate_sow_hash("a" * 64).valid
        # Length mismatch
        assert validate_sow_hash("a" * 32).icon == "✗"
        # Non-hex
        assert validate_sow_hash("z" * 64).icon == "✗"
        # Empty → pending
        assert validate_sow_hash("").icon == "…"

    def test_positive_float(self):
        from nexusrecon.tui.wizard_helpers import validate_positive_float
        assert validate_positive_float("5", label="x").valid
        assert validate_positive_float("5.25", label="x").valid
        assert validate_positive_float("0", label="x").icon == "✗"
        assert validate_positive_float("-1", label="x").icon == "✗"
        assert validate_positive_float("xyz", label="x").icon == "✗"
        assert validate_positive_float("", label="x").icon == "…"


# ──────────────────────────────────────────────────────────────────────
# Preset loader
# ──────────────────────────────────────────────────────────────────────


class TestPresets:
    def test_builtin_presets_loaded(self):
        from nexusrecon.tui.wizard_helpers import BUILTIN_PRESETS, load_presets
        presets = load_presets()
        builtin_ids = {p.id for p in BUILTIN_PRESETS}
        loaded_ids = {p.id for p in presets}
        # All built-ins surface (any user overrides preserve the id).
        assert builtin_ids.issubset(loaded_ids)

    def test_preset_by_id_returns_known(self):
        from nexusrecon.tui.wizard_helpers import preset_by_id
        p = preset_by_id("oss-recon")
        assert p is not None
        assert p.id == "oss-recon"
        assert p.fields.get("max_tier") == "T1"

    def test_preset_by_id_returns_none_for_unknown(self):
        from nexusrecon.tui.wizard_helpers import preset_by_id
        assert preset_by_id("does-not-exist") is None

    def test_user_preset_overrides_builtin(self, tmp_path: Path, monkeypatch):
        from nexusrecon.tui.wizard_helpers import load_presets
        # Redirect $HOME so we don't touch real user presets.
        monkeypatch.setenv("HOME", str(tmp_path))
        preset_dir = tmp_path / ".nexusrecon" / "scope-presets"
        preset_dir.mkdir(parents=True)
        # User preset with same id as built-in "oss-recon".
        (preset_dir / "oss-override.yaml").write_text(yaml.safe_dump({
            "id": "oss-recon",
            "name": "Operator's custom OSS recon",
            "description": "Overridden",
            "fields": {"max_tier": "T3", "max_cost_usd": "999"},
        }))
        presets = {p.id: p for p in load_presets()}
        assert presets["oss-recon"].name == "Operator's custom OSS recon"
        assert presets["oss-recon"].fields["max_tier"] == "T3"

    def test_malformed_user_preset_skipped(self, tmp_path: Path, monkeypatch):
        from nexusrecon.tui.wizard_helpers import BUILTIN_PRESETS, load_presets
        monkeypatch.setenv("HOME", str(tmp_path))
        preset_dir = tmp_path / ".nexusrecon" / "scope-presets"
        preset_dir.mkdir(parents=True)
        (preset_dir / "broken.yaml").write_text("not: valid: yaml: [")
        # The malformed file is skipped; built-ins still load.
        presets = load_presets()
        assert len(presets) >= len(BUILTIN_PRESETS)

    def test_apply_preset_overlays_fields(self):
        from nexusrecon.tui.wizard_helpers import apply_preset, preset_by_id
        data = {
            "client": "Acme", "seed_domain": "x.com",
            "max_tier": "T2", "max_cost_usd": "20",
        }
        preset = preset_by_id("oss-recon")
        apply_preset(data, preset)
        # Preset-supplied fields overwrite.
        assert data["max_tier"] == "T1"
        # Operator-entered fields the preset doesn't touch survive.
        assert data["client"] == "Acme"
        assert data["seed_domain"] == "x.com"


# ──────────────────────────────────────────────────────────────────────
# Cost estimator
# ──────────────────────────────────────────────────────────────────────


class TestCostEstimator:
    def test_low_mid_high_ordered(self):
        from nexusrecon.tui.wizard_helpers import estimate_campaign_cost
        p = estimate_campaign_cost(
            mode="medium", dispatch_mode="lite", max_tier="T2",
            stealth="high", seed_count=1,
        )
        assert p.low_usd < p.mid_usd < p.high_usd

    def test_deep_mode_costs_more_than_light(self):
        from nexusrecon.tui.wizard_helpers import estimate_campaign_cost
        light = estimate_campaign_cost(
            mode="light", dispatch_mode="lite", max_tier="T2",
            stealth="high", seed_count=1,
        )
        deep = estimate_campaign_cost(
            mode="deep", dispatch_mode="lite", max_tier="T2",
            stealth="high", seed_count=1,
        )
        assert deep.mid_usd > light.mid_usd

    def test_full_dispatch_costs_more(self):
        from nexusrecon.tui.wizard_helpers import estimate_campaign_cost
        lite = estimate_campaign_cost(
            mode="medium", dispatch_mode="lite", max_tier="T2",
            stealth="high", seed_count=1,
        )
        full = estimate_campaign_cost(
            mode="medium", dispatch_mode="full", max_tier="T2",
            stealth="high", seed_count=1,
        )
        assert full.mid_usd > lite.mid_usd

    def test_phishing_drafts_increase_cost(self):
        from nexusrecon.tui.wizard_helpers import estimate_campaign_cost
        without = estimate_campaign_cost(
            mode="medium", dispatch_mode="lite", max_tier="T2",
            stealth="high", seed_count=1, generate_phishing=False,
        )
        with_ = estimate_campaign_cost(
            mode="medium", dispatch_mode="lite", max_tier="T2",
            stealth="high", seed_count=1, generate_phishing=True,
        )
        assert with_.mid_usd > without.mid_usd

    def test_additional_domains_scale_cost(self):
        from nexusrecon.tui.wizard_helpers import estimate_campaign_cost
        one = estimate_campaign_cost(
            mode="medium", dispatch_mode="lite", max_tier="T2",
            stealth="high", seed_count=1, additional_count=0,
        )
        many = estimate_campaign_cost(
            mode="medium", dispatch_mode="lite", max_tier="T2",
            stealth="high", seed_count=1, additional_count=5,
        )
        assert many.mid_usd > one.mid_usd

    def test_fits_budget(self):
        from nexusrecon.tui.wizard_helpers import CostPreview
        p = CostPreview(low_usd=1.0, mid_usd=2.0, high_usd=5.0)
        assert p.fits_budget(10.0) is True
        assert p.fits_budget(4.0) is False

    def test_rationale_mentions_inputs(self):
        from nexusrecon.tui.wizard_helpers import estimate_campaign_cost
        p = estimate_campaign_cost(
            mode="deep", dispatch_mode="full", max_tier="T2",
            stealth="high", seed_count=1, additional_count=3,
            generate_phishing=True,
        )
        assert "deep" in p.rationale
        assert "phishing" in p.rationale.lower() or "draft" in p.rationale.lower()


# ──────────────────────────────────────────────────────────────────────
# Summary rendering
# ──────────────────────────────────────────────────────────────────────


class TestRenderSummary:
    def test_empty_summary_shows_not_set(self):
        from nexusrecon.tui.wizard_helpers import render_summary
        out = render_summary({})
        assert "Engagement" in out
        assert "Scope" in out
        assert "Constraints" in out
        assert "Run" in out
        assert "(not set)" in out

    def test_populated_summary_shows_values(self):
        from nexusrecon.tui.wizard_helpers import render_summary
        out = render_summary({
            "client": "Acme",
            "engagement_id": "ENG-001",
            "seed_domain": "example.com",
            "max_tier": "T2",
            "stealth": "high",
        })
        assert "Acme" in out
        assert "ENG-001" in out
        assert "example.com" in out
        assert "T2" in out
        assert "high" in out

    def test_long_values_shortened(self):
        from nexusrecon.tui.wizard_helpers import render_summary
        out = render_summary({
            "additional_domains": ",".join([f"sub{i}.example.com" for i in range(30)]),
        })
        # Should be truncated with an ellipsis at ~22 chars
        assert "…" in out


# ──────────────────────────────────────────────────────────────────────
# Wizard integration (pilot)
# ──────────────────────────────────────────────────────────────────────


class TestWizardPilot:
    def test_wizard_mounts_with_summary_pane(self):
        from nexusrecon.tui.app import NexusReconApp
        from nexusrecon.tui.screens.wizard import WizardScreen

        async def _drive():
            app = NexusReconApp()
            async with app.run_test(headless=True) as pilot:
                await pilot.pause(0.8)
                await pilot.press("n")
                await pilot.pause(0.5)
                assert isinstance(app.screen, WizardScreen)
                # Summary pane widgets present
                summary = app.screen.query_one("#wizard-summary-body")
                assert summary is not None
                app.exit()
                await pilot.pause(0.1)

        asyncio.run(_drive())

    def test_preset_select_present_on_step_2(self):
        from nexusrecon.tui.app import NexusReconApp

        async def _drive():
            app = NexusReconApp()
            async with app.run_test(headless=True) as pilot:
                await pilot.pause(0.8)
                await pilot.press("n")
                await pilot.pause(0.5)
                # Set step to 2 directly so we don't have to fill step 1.
                app.screen.step = 2
                await app.screen._render_step()
                await pilot.pause(0.2)
                preset_select = app.screen.query_one("#f-preset")
                assert preset_select is not None
                app.exit()
                await pilot.pause(0.1)

        asyncio.run(_drive())

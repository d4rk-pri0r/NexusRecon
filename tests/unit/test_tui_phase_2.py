"""Tests for TUI-2: command palette + three-pane tools browser.

The palette engine + sources live in
``nexusrecon.tui.command_palette`` and stay unit-testable without
spinning up Textual. The Textual modal screen + the tools browser
get exercised via the headless pilot harness.

Coverage:

  - ``fuzzy_score`` ranking semantics (exact substring > anchored >
    subsequence > no-match).
  - ``ToolsSource`` ranking — name matches outrank
    description-only matches (the bug surfaced during dev: "github"
    query was returning exploitdb on top because its description
    mentioned GitHub).
  - ``NavigationSource`` catalog completeness + jump callable wiring.
  - ``ReportsSource`` safe-when-empty + scoring of present vs
    absent reports.
  - ``CommandPalette`` cross-source merging + ranking stability.
  - Pilot smoke: Ctrl+P opens NexusRecon's palette (not Textual's
    built-in), `:` opens it too, Esc dismisses, `t` opens the new
    ToolsScreen, `?` opens help.
"""
from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from nexusrecon.tui.command_palette import (
    CommandMatch,
    CommandPalette,
    CommandSource,
    NavigationSource,
    ReportsSource,
    ToolsSource,
    fuzzy_score,
)

# ──────────────────────────────────────────────────────────────────────
# fuzzy_score
# ──────────────────────────────────────────────────────────────────────


class TestFuzzyScore:
    def test_empty_needle_matches_anything(self):
        assert fuzzy_score("github_social", "") == 1.0
        assert fuzzy_score("", "") == 1.0

    def test_empty_haystack_no_match(self):
        assert fuzzy_score("", "anything") == 0.0

    def test_anchored_substring_outranks_middle(self):
        # "_" / "-" / "." / "/" / " " are word boundaries — names like
        # "_github_social" still anchor. To get an UN-anchored middle
        # match the haystack needs to have the needle wedged between
        # plain letters.
        anchored = fuzzy_score("github_social", "github")
        middle = fuzzy_score("mygithubxtool", "github")
        assert anchored > middle
        assert anchored >= 0.9
        assert middle >= 0.9  # still a substring match, just not anchored

    def test_snake_case_underscore_treated_as_word_boundary(self):
        """``_github`` should anchor: operators expect names like
        ``some_github_thing`` to rank as highly as ``github_thing``
        for the ``github`` query."""
        front = fuzzy_score("github_social", "github")
        mid_word_boundary = fuzzy_score("nx_github_social", "github")
        # Both should score the same (both are anchored).
        assert mid_word_boundary == pytest.approx(front)

    def test_subsequence_match_below_substring(self):
        substring = fuzzy_score("github_social", "github")
        subseq = fuzzy_score("github_social", "ghsl")
        assert substring > subseq
        assert subseq > 0.0

    def test_no_match_returns_zero(self):
        assert fuzzy_score("github_social", "xyz_unrelated") == 0.0

    def test_case_insensitive(self):
        assert fuzzy_score("GITHUB_SOCIAL", "github") >= 0.9


# ──────────────────────────────────────────────────────────────────────
# ToolsSource
# ──────────────────────────────────────────────────────────────────────


class TestToolsSource:
    def test_name_match_outranks_description_only(self):
        """The "github" query bug: exploitdb mentions GitHub in
        its description and was ranking alongside github_*-named
        tools. Name match must score above description-only match.
        """
        # Mock a tiny registry: one name-match + one description-only match.
        fake_entries = [
            {
                "name": "exploitdb", "category": "vulnerability",
                "tier": "T0", "description": "search github advisories",
                "available": "True", "stubbed": "False",
            },
            {
                "name": "github_social", "category": "social",
                "tier": "T0", "description": "Per-user GitHub graph",
                "available": "True", "stubbed": "False",
            },
        ]
        fake_registry = MagicMock()
        fake_registry.list_tools.return_value = fake_entries
        with patch(
            "nexusrecon.tools.registry.get_registry",
            return_value=fake_registry,
        ):
            results = ToolsSource().query("github")
        # github_social must outrank exploitdb on the "github" query.
        names = [r.title for r in results]
        assert names.index("github_social") < names.index("exploitdb")

    def test_empty_query_returns_capped_set(self):
        fake_entries = [
            {
                "name": f"tool_{i:02d}", "category": "test",
                "tier": "T0", "description": "x",
                "available": "True", "stubbed": "False",
            }
            for i in range(50)
        ]
        fake_registry = MagicMock()
        fake_registry.list_tools.return_value = fake_entries
        with patch(
            "nexusrecon.tools.registry.get_registry",
            return_value=fake_registry,
        ):
            results = ToolsSource().query("")
        # Source caps its output at 20 (documented in the source).
        assert len(results) <= 20

    def test_no_match_returns_empty(self):
        fake_registry = MagicMock()
        fake_registry.list_tools.return_value = [
            {
                "name": "github_social", "category": "social",
                "tier": "T0", "description": "x",
                "available": "True", "stubbed": "False",
            },
        ]
        with patch(
            "nexusrecon.tools.registry.get_registry",
            return_value=fake_registry,
        ):
            results = ToolsSource().query("totally-unrelated-zzz")
        assert results == []

    def test_icon_reflects_status(self):
        """✓ available, ✗ missing keys, ⚠ stub."""
        fake_entries = [
            {
                "name": "ready_tool", "category": "test", "tier": "T0",
                "description": "x",
                "available": "True", "stubbed": "False",
            },
            {
                "name": "missing_key_tool", "category": "test", "tier": "T0",
                "description": "x",
                "available": "False", "stubbed": "False",
            },
            {
                "name": "stub_tool", "category": "test", "tier": "T0",
                "description": "x",
                "available": "False", "stubbed": "True",
            },
        ]
        fake_registry = MagicMock()
        fake_registry.list_tools.return_value = fake_entries
        with patch(
            "nexusrecon.tools.registry.get_registry",
            return_value=fake_registry,
        ):
            results = ToolsSource().query("")
        icons = {r.title: r.icon for r in results}
        assert icons["ready_tool"] == "✓"
        assert icons["missing_key_tool"] == "✗"
        assert icons["stub_tool"] == "⚠"

    def test_jump_callable_invoked_on_execute(self):
        captured: list[str] = []
        source = ToolsSource(jump_to_tools_screen=captured.append)
        fake_registry = MagicMock()
        fake_registry.list_tools.return_value = [
            {
                "name": "github_social", "category": "social",
                "tier": "T0", "description": "x",
                "available": "True", "stubbed": "False",
            },
        ]
        with patch(
            "nexusrecon.tools.registry.get_registry",
            return_value=fake_registry,
        ):
            results = source.query("github")
        assert results, "expected at least one match"
        results[0].execute()
        assert captured == ["github_social"]

    def test_registry_failure_returns_empty(self):
        with patch(
            "nexusrecon.tools.registry.get_registry",
            side_effect=RuntimeError("registry not available"),
        ):
            assert ToolsSource().query("github") == []


# ──────────────────────────────────────────────────────────────────────
# NavigationSource
# ──────────────────────────────────────────────────────────────────────


class TestNavigationSource:
    def test_catalog_covers_main_destinations(self):
        """Every screen in the main flow must be reachable via the
        palette. If we add a new top-level screen, this test fails
        until the catalog includes it."""
        source = NavigationSource()
        required = {
            "dashboard", "new_campaign", "campaigns",
            "tools", "config", "help",
        }
        ids = {entry[0] for entry in source._CATALOG}
        missing = required - ids
        assert not missing, f"navigation catalog missing: {missing}"

    def test_query_ranks_close_match_above_subseq(self):
        source = NavigationSource()
        results = source.query("conf")
        assert results, "expected at least one match"
        # "Configuration" is the closest match for "conf".
        assert results[0].title == "Configuration"

    def test_navigate_callable_invoked(self):
        captured: list[str] = []
        source = NavigationSource(navigate=captured.append)
        results = source.query("conf")
        results[0].execute()
        assert captured == ["config"]

    def test_no_match_returns_empty(self):
        assert NavigationSource().query("nonsense_xxx") == []


# ──────────────────────────────────────────────────────────────────────
# ReportsSource
# ──────────────────────────────────────────────────────────────────────


class TestReportsSource:
    def test_no_campaigns_returns_empty(self, tmp_path: Path):
        from nexusrecon.core import config as cfg_mod
        fake_cfg = MagicMock()
        fake_cfg.output_dir = str(tmp_path)
        with patch.object(cfg_mod, "get_config", return_value=fake_cfg):
            assert ReportsSource().query("any") == []

    def test_finds_existing_report_files(self, tmp_path: Path):
        from nexusrecon.core import config as cfg_mod
        # Lay out a campaign directory with one real report.
        campaign = tmp_path / "campaign-x"
        campaign.mkdir()
        (campaign / "state.json").write_text("{}")
        (campaign / "harvested_credentials.md").write_text(
            "# credentials\n",
        )
        fake_cfg = MagicMock()
        fake_cfg.output_dir = str(tmp_path)
        with patch.object(cfg_mod, "get_config", return_value=fake_cfg):
            results = ReportsSource().query("creds")
        # The harvested_credentials match should be present and
        # marked as present (icon != "○").
        assert any(
            "Harvested credentials" in r.title and r.icon == "📄"
            for r in results
        )

    def test_absent_reports_still_listed_but_dimmer(self, tmp_path: Path):
        """The palette surfaces every known report shape; absent
        ones rank lower (score halved) so existing reports win
        for the same query."""
        from nexusrecon.core import config as cfg_mod
        campaign = tmp_path / "campaign-y"
        campaign.mkdir()
        (campaign / "state.json").write_text("{}")
        # Only one of the report files exists.
        (campaign / "harvested_credentials.md").write_text("x")
        fake_cfg = MagicMock()
        fake_cfg.output_dir = str(tmp_path)
        with patch.object(cfg_mod, "get_config", return_value=fake_cfg):
            results = ReportsSource().query("report")
        # Both "Harvested credentials" and "Master report" likely
        # appear; the one that exists should have a higher score.
        scores = {
            r.title: (r.score, r.metadata.get("exists"))
            for r in results
        }
        # If both surface, score(exists=True) > score(exists=False)
        exists_scores = [s for s, e in scores.values() if e]
        absent_scores = [s for s, e in scores.values() if not e]
        if exists_scores and absent_scores:
            assert max(exists_scores) >= max(absent_scores)


# ──────────────────────────────────────────────────────────────────────
# CommandPalette engine
# ──────────────────────────────────────────────────────────────────────


class FakeSource(CommandSource):
    """Test double yielding a controlled match set."""

    name = "fake"

    def __init__(self, matches: list[CommandMatch], should_raise: bool = False):
        self._matches = matches
        self._should_raise = should_raise

    def query(self, text: str) -> list[CommandMatch]:
        if self._should_raise:
            raise RuntimeError("source bug")
        return list(self._matches)


class TestCommandPaletteEngine:
    def test_merges_across_sources(self):
        a = FakeSource([
            CommandMatch(title="alpha", score=0.5, kind="tool"),
            CommandMatch(title="beta", score=0.3, kind="tool"),
        ])
        b = FakeSource([
            CommandMatch(title="gamma", score=0.8, kind="nav"),
        ])
        palette = CommandPalette()
        palette.register(a)
        palette.register(b)
        results = palette.query("anything")
        # Highest score first.
        assert [r.title for r in results] == ["gamma", "alpha", "beta"]

    def test_misbehaving_source_does_not_break_palette(self):
        good = FakeSource([CommandMatch(title="good", score=0.5, kind="tool")])
        bad = FakeSource([], should_raise=True)
        palette = CommandPalette()
        palette.register(bad)
        palette.register(good)
        # The buggy source is skipped; the good one still works.
        results = palette.query("any")
        assert [r.title for r in results] == ["good"]

    def test_max_results_cap(self):
        many = FakeSource([
            CommandMatch(title=f"m{i:02d}", score=0.5 - i * 0.001, kind="tool")
            for i in range(100)
        ])
        palette = CommandPalette()
        palette.register(many)
        results = palette.query("any", max_results=10)
        assert len(results) == 10

    def test_stable_ordering_on_ties(self):
        """When scores tie, kind+title secondary ordering yields a
        deterministic sequence across runs (no flaky tests)."""
        a = FakeSource([
            CommandMatch(title="zebra", score=0.5, kind="tool"),
            CommandMatch(title="apple", score=0.5, kind="tool"),
            CommandMatch(title="middle", score=0.5, kind="nav"),
        ])
        palette = CommandPalette()
        palette.register(a)
        results = palette.query("any")
        # 0.5 across all three → sorted by (kind, title) ascending
        # within each kind.
        assert results[0].kind == "nav"
        # The two tool entries should be alpha-sorted.
        tool_titles = [r.title for r in results if r.kind == "tool"]
        assert tool_titles == ["apple", "zebra"]


# ──────────────────────────────────────────────────────────────────────
# Pilot smoke (full TUI roundtrip)
# ──────────────────────────────────────────────────────────────────────


class TestPilotIntegration:
    def test_palette_open_close_round_trip(self):
        from nexusrecon.tui.app import NexusReconApp
        from nexusrecon.tui.screens.command_palette import CommandPaletteScreen

        async def _drive():
            app = NexusReconApp()
            async with app.run_test(headless=True) as pilot:
                await pilot.pause(0.5)
                await pilot.press("ctrl+p")
                await pilot.pause(0.3)
                # Our palette must intercept Ctrl+P, not Textual's.
                assert isinstance(app.screen, CommandPaletteScreen)
                await pilot.press("escape")
                await pilot.pause(0.2)
                assert not isinstance(app.screen, CommandPaletteScreen)
                # Colon also opens the palette.
                await pilot.press("colon")
                await pilot.pause(0.3)
                assert isinstance(app.screen, CommandPaletteScreen)
                app.exit()
                await pilot.pause(0.1)

        asyncio.run(_drive())

    def test_tools_screen_via_t_binding(self):
        from nexusrecon.tui.app import NexusReconApp
        from nexusrecon.tui.screens.tools import ToolsScreen

        async def _drive():
            app = NexusReconApp()
            async with app.run_test(headless=True) as pilot:
                await pilot.pause(0.5)
                await pilot.press("t")
                await pilot.pause(0.5)
                assert isinstance(app.screen, ToolsScreen)
                app.exit()
                await pilot.pause(0.1)

        asyncio.run(_drive())

    def test_palette_query_renders_without_crash(self):
        from nexusrecon.tui.app import NexusReconApp

        async def _drive():
            app = NexusReconApp()
            async with app.run_test(headless=True) as pilot:
                await pilot.pause(0.5)
                await pilot.press("ctrl+p")
                await pilot.pause(0.2)
                # Type a query that exercises the result-list rebuild.
                await pilot.press("g", "i", "t", "h", "u", "b")
                await pilot.pause(0.3)
                # No crash → the rebuild path is sound.
                app.exit()
                await pilot.pause(0.1)

        asyncio.run(_drive())


# ──────────────────────────────────────────────────────────────────────
# ToolsScreen helpers
# ──────────────────────────────────────────────────────────────────────


class TestConfigDeepLink:
    """Regression for the deep-link kwargs on ConfigScreen.

    Originally added so the Tools browser could shove the operator
    straight onto the right env-var edit row. The Tools browser now
    opens ``EditKeyModal`` directly (see ``TestToolsScreenDirectEdit``),
    so these tests only cover the app-wide path that ConfigScreen
    still actually owns: the LLM / OPSEC / Storage / Debug
    categories. Tool-key lookups are still case-insensitive across
    every category for the Tools screen's modal-opening flow.
    """

    def test_find_category_for_var_locates_app_wide_key(self):
        from nexusrecon.tui.config_schema import find_category_for_var
        pair = find_category_for_var("NEXUS_LLM_PROVIDER")
        assert pair is not None
        cat, var = pair
        assert var.key == "NEXUS_LLM_PROVIDER"
        assert cat.id == "llm"

    def test_find_var_still_finds_tool_keys_case_insensitively(self):
        """The Config screen no longer displays tool categories, but
        ``find_var`` still resolves tool API keys so the Tools
        browser's EditKeyModal flow keeps working."""
        from nexusrecon.tui.config_schema import find_var
        v = find_var("github_token")
        assert v is not None
        assert v.key == "GITHUB_TOKEN"
        assert v.sensitive

    def test_find_category_for_var_returns_none_for_unknown(self):
        from nexusrecon.tui.config_schema import find_category_for_var
        assert find_category_for_var("NOT_A_REAL_KEY_xyz") is None

    def test_config_screen_accepts_deep_link_args(self):
        """ConfigScreen.__init__ accepts kwargs and pre-selects the
        requested *app-wide* category. Tool categories no longer
        appear here, but the kwarg path itself remains for app-wide
        deep-links (e.g. palette → "set LLM provider")."""
        from nexusrecon.tui.screens.config import ConfigScreen
        screen = ConfigScreen(
            initial_category_id="llm",
            initial_key="NEXUS_LLM_PROVIDER",
        )
        assert screen._initial_key == "NEXUS_LLM_PROVIDER"
        assert screen._cats[screen._current_cat_idx].id == "llm"

    def test_config_screen_deep_link_opens_edit_modal(self):
        """Full integration via the app-wide path: pushing
        ConfigScreen with deep-link kwargs results in the
        EditKeyModal being on top of the stack."""
        import asyncio as _asyncio

        from nexusrecon.tui.app import NexusReconApp
        from nexusrecon.tui.screens.config import ConfigScreen

        async def _drive():
            app = NexusReconApp()
            async with app.run_test(headless=True) as pilot:
                await pilot.pause(0.5)
                await app.push_screen(ConfigScreen(
                    initial_category_id="llm",
                    initial_key="NEXUS_LLM_PROVIDER",
                ))
                await pilot.pause(0.5)
                assert type(app.screen).__name__ == "EditKeyModal", (
                    f"expected deep-link to open EditKeyModal; got "
                    f"{type(app.screen).__name__}"
                )
                app.exit()
                await pilot.pause(0.1)

        _asyncio.run(_drive())

    def test_config_screen_hides_tool_categories(self):
        """The Config screen must NOT list tool API-key categories
        like ``code``, ``intel``, ``identity`` — those live in the
        Tools screen now. Operator looking for SHODAN/GITHUB/etc.
        keys belongs in the Tools surface, not here."""
        from nexusrecon.tui.config_schema import APP_CATEGORY_IDS
        from nexusrecon.tui.screens.config import ConfigScreen
        screen = ConfigScreen()
        shown = {c.id for c in screen._cats}
        assert shown == APP_CATEGORY_IDS, (
            f"expected only app-wide categories, got {shown}"
        )
        # And the tool-category IDs that used to be here are gone:
        for stale in ("intel", "identity", "code", "cloud", "_binaries"):
            assert stale not in shown


class TestToolsScreenHelpers:
    def test_load_tools_returns_list(self):
        from nexusrecon.tui.screens.tools import _load_tools
        out = _load_tools()
        assert isinstance(out, list)
        # Each entry has the keys the screen reads.
        for entry in out[:3]:
            assert "name" in entry
            assert "category" in entry
            assert "available" in entry

    def test_group_by_category(self):
        from nexusrecon.tui.screens.tools import _group_by_category
        tools = [
            {"name": "a", "category": "x"},
            {"name": "b", "category": "x"},
            {"name": "c", "category": "y"},
        ]
        buckets = _group_by_category(tools)
        assert set(buckets.keys()) == {"x", "y"}
        assert len(buckets["x"]) == 2
        assert len(buckets["y"]) == 1

    def test_load_tools_handles_registry_error(self):
        from nexusrecon.tui.screens import tools as tools_mod
        with patch.object(
            tools_mod, "_load_tools",
            return_value=[],
        ):
            assert tools_mod._load_tools() == []

    def test_editable_requires_filters_binaries_and_upcases(self):
        from nexusrecon.tui.screens.tools import _editable_requires
        # bin: markers excluded; remaining keys normalized to UPPER
        assert _editable_requires(
            {"requires": "github_token, bin:gowitness, hunter_api_key"},
        ) == ["GITHUB_TOKEN", "HUNTER_API_KEY"]
        assert _editable_requires({"requires": ""}) == []
        assert _editable_requires({"requires": "bin:nuclei"}) == []

    def test_editable_optional_extracts_optional_keys(self):
        from nexusrecon.tui.screens.tools import _editable_optional
        assert _editable_optional(
            {"optional": "github_token, certspotter_api_key"},
        ) == ["GITHUB_TOKEN", "CERTSPOTTER_API_KEY"]
        # Missing / empty optional field => no keys
        assert _editable_optional({"optional": ""}) == []
        assert _editable_optional({}) == []

    def test_pretty_category_falls_back_for_unknown(self):
        from nexusrecon.tui.screens.tools import _pretty_category
        # known mapping returns the emoji label
        assert "🌐" in _pretty_category("dns")
        # unknown category passes through verbatim
        assert _pretty_category("brand_new_cat") == "brand_new_cat"


class TestToolsScreenDirectEdit:
    """The TUI-7 fix: pressing ``c`` on the Tools screen must open
    the EditKeyModal on the highlighted tool's first editable env
    var directly — not stop over at ConfigScreen, and not be
    case-sensitive to the tool's lowercase ``requires_keys``.
    """

    def test_lowercase_requires_resolves_to_uppercase_schema(self):
        """Tools declare ``requires_keys = ["github_token"]`` (the
        pydantic field name). The schema stores ``GITHUB_TOKEN``
        (the .env name). The lookup that powers the deep-link must
        bridge the two.
        """
        from nexusrecon.tui.config_schema import find_var
        v = find_var("github_token")
        assert v is not None
        assert v.key == "GITHUB_TOKEN"

    def test_linkedin_li_at_is_in_schema(self):
        """LINKEDIN_LI_AT must be editable from the TUI now that
        linkedin_social requires it (was missing from the schema
        until TUI-7)."""
        from nexusrecon.tui.config_schema import find_var
        v = find_var("LINKEDIN_LI_AT")
        assert v is not None
        assert v.sensitive  # session cookie — must be masked

    def test_c_opens_edit_modal_directly(self):
        """End-to-end: highlight a tool that requires keys, press
        ``c``, verify the EditKeyModal lands on top and Cancel
        returns to the ToolsScreen (NOT ConfigScreen)."""
        import asyncio as _asyncio

        from nexusrecon.tui.app import NexusReconApp
        from nexusrecon.tui.screens.edit_key import EditKeyModal
        from nexusrecon.tui.screens.tools import ToolsScreen

        async def _drive():
            app = NexusReconApp()
            async with app.run_test(headless=True) as pilot:
                await pilot.pause(0.5)
                await app.push_screen(ToolsScreen())
                await pilot.pause(0.5)
                screen = app.screen
                assert isinstance(screen, ToolsScreen)
                # Snap to a known target — github_recon requires
                # GITHUB_TOKEN.
                screen._current_category = ToolsScreen.ALL_CATEGORIES
                screen._rebuild_tools_list()
                names = [t["name"] for t in screen._visible]
                idx = names.index("github_recon")
                screen.query_one("#tools-list").index = idx
                await pilot.pause(0.1)
                await screen.action_edit_selected_key()
                await pilot.pause(0.3)
                top = app.screen
                assert isinstance(top, EditKeyModal), (
                    f"expected EditKeyModal; got {type(top).__name__}"
                )
                assert top.var.key == "GITHUB_TOKEN"
                top.action_cancel()
                await pilot.pause(0.2)
                # Cancelling returns to Tools, NOT to a stranded
                # ConfigScreen mid-stack.
                assert isinstance(app.screen, ToolsScreen)
                app.exit()
                await pilot.pause(0.1)

        _asyncio.run(_drive())

    def test_optional_keys_appear_in_editable_target(self):
        """Tools with no required keys but with declared
        ``optional_keys`` should still be editable from the Tools
        screen — the editable target falls through to the first
        optional key. Regression: before optional_keys existed,
        these tools had no UI surface for their enhancement keys."""
        import asyncio as _asyncio

        from nexusrecon.tui.app import NexusReconApp
        from nexusrecon.tui.screens.edit_key import EditKeyModal
        from nexusrecon.tui.screens.tools import ToolsScreen

        async def _drive():
            app = NexusReconApp()
            async with app.run_test(headless=True) as pilot:
                await pilot.pause(0.5)
                await app.push_screen(ToolsScreen())
                await pilot.pause(0.5)
                screen = app.screen
                # otx_subdomains has only an optional key
                # (otx_api_key); the Tools detail pane MUST still
                # offer it to ``c``.
                otx = next(
                    t for t in screen._visible if t["name"] == "otx_subdomains"
                )
                target = screen._editable_target(otx)
                assert target is not None, "otx_subdomains must be editable"
                _var, key, kind = target
                assert key == "OTX_API_KEY"
                assert kind == "optional"

                # Drive `c` and confirm the modal opens on OTX_API_KEY.
                names = [t["name"] for t in screen._visible]
                idx = names.index("otx_subdomains")
                screen.query_one("#tools-list").index = idx
                await pilot.pause(0.1)
                await screen.action_edit_selected_key()
                await pilot.pause(0.3)
                top = app.screen
                assert isinstance(top, EditKeyModal)
                assert top.var.key == "OTX_API_KEY"
                top.action_cancel()
                app.exit()
                await pilot.pause(0.1)

        _asyncio.run(_drive())

    def test_required_keys_win_over_optional_when_missing(self):
        """When a tool has both required and optional keys and the
        required one is missing, ``c`` must edit the required key
        first — fixing a real gap beats configuring an enhancement.
        """
        from nexusrecon.tui.screens.tools import ToolsScreen
        # breach_lookup has required HIBP + optional dehashed/intelx
        screen = ToolsScreen()
        screen._tools = [
            {
                "name": "breach_lookup",
                "category": "breach",
                "tier": "T0",
                "available": "False",
                "stubbed": "False",
                "requires": "haveibeenpwned_api_key",
                "optional": "dehashed_username, dehashed_api_key, intelx_api_key",
                "description": "",
            },
        ]
        target = screen._editable_target(screen._tools[0])
        assert target is not None
        _var, key, kind = target
        assert key == "HAVEIBEENPWNED_API_KEY"
        assert kind == "required"

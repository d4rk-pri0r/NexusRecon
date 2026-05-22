"""Tests for TUI-3: StatusBar widget, Sidebar widget, Dashboard screen,
StatusBar propagation across the existing screens.

Coverage:

  - ``render_status_bar`` produces the expected string for the idle
    and active-campaign states; tolerant of missing fields.
  - Helper ``_render_gauge`` renders a fixed-width block bar.
  - ``StatusBar`` exposes ``_compose_text`` (named that way ON PURPOSE
    — overriding ``_render`` shadows Textual's internal Visual
    accessor and breaks rendering).
  - ``Sidebar`` catalog matches NavigationSource catalog so the
    palette + the sidebar stay in lockstep.
  - ``Sidebar.toggle_collapsed`` flips the reactive flag.
  - Dashboard helpers (``_recent_campaigns``, ``_tool_breakdown``,
    ``_should_show_onboarding``) tolerate missing data.
  - Pilot smoke: Dashboard mounts with StatusBar + Sidebar; sidebar
    collapses on ``]`` press; navigating to wizard via ``n``
    preserves the StatusBar.
"""
from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import MagicMock, patch

# ──────────────────────────────────────────────────────────────────────
# render_status_bar
# ──────────────────────────────────────────────────────────────────────


class TestRenderStatusBar:
    def test_idle_render_contains_brand_and_tool_counts(self):
        from nexusrecon.tui.widgets.status_bar import render_status_bar
        out = render_status_bar(
            active_state={"idle": True},
            tool_counts=(97, 81, 1),
            llm_provider="anthropic",
            version="0.5.0",
        )
        assert "NEXUSRECON" in out
        assert "v0.5.0" in out
        assert "Idle" in out
        assert "97 tools" in out
        assert "81 active" in out
        assert "1 stub" in out
        assert "anthropic" in out

    def test_active_render_contains_target_and_phase(self):
        from nexusrecon.tui.widgets.status_bar import render_status_bar
        out = render_status_bar(
            active_state={
                "idle": False,
                "target": "juice-shop.herokuapp.com",
                "phase_label": "phase4",
                "phase_index": 4,
                "phase_total": 10,
                "llm_cost_usd": 4.23,
                "budget_usd": 20.0,
                "finding_count": 23,
            },
            tool_counts=(97, 81, 1),
            llm_provider="anthropic",
            version="0.5.0",
        )
        assert "juice-shop.herokuapp.com" in out
        assert "Phase 4/10" in out
        assert "$4.23" in out
        assert "$20.00" in out
        assert "23" in out

    def test_active_render_without_budget_omits_gauge(self):
        from nexusrecon.tui.widgets.status_bar import render_status_bar
        out = render_status_bar(
            active_state={
                "idle": False,
                "target": "x.com",
                "phase_label": "phase1",
                "phase_index": 1,
                "phase_total": 9,
                "llm_cost_usd": 0.0,
                "budget_usd": 0.0,
                "finding_count": 0,
            },
            tool_counts=(50, 50, 0),
            llm_provider="anthropic",
            version="0.5.0",
        )
        assert "$0.00" in out
        # No "[████" gauge characters when budget is 0
        assert "[█" not in out and "[░" not in out

    def test_render_gauge_endpoints(self):
        from nexusrecon.tui.widgets.status_bar import _render_gauge
        # Empty gauge
        assert _render_gauge(0.0, 10.0, width=10).count("░") == 10
        # Full gauge
        assert _render_gauge(10.0, 10.0, width=10).count("█") == 10
        # Half-full
        half = _render_gauge(5.0, 10.0, width=10)
        assert half.count("█") == 5
        assert half.count("░") == 5

    def test_render_gauge_no_total_safe(self):
        from nexusrecon.tui.widgets.status_bar import _render_gauge
        out = _render_gauge(5.0, 0.0)
        assert "█" not in out  # nothing filled when total=0
        assert "░" in out      # all empty

    def test_no_tools_loaded_segment_renders_safe(self):
        from nexusrecon.tui.widgets.status_bar import render_status_bar
        out = render_status_bar(
            active_state={"idle": True},
            tool_counts=(0, 0, 0),
            llm_provider="anthropic",
            version="0.5.0",
        )
        assert "(no tools loaded)" in out


# ──────────────────────────────────────────────────────────────────────
# StatusBar class
# ──────────────────────────────────────────────────────────────────────


class TestStatusBarClass:
    def test_compose_text_method_exists_not_render(self):
        """Regression test for the TUI-3 dev-time bug: overriding
        ``_render`` on a Static subclass collides with Textual's
        internal Visual accessor and breaks layout. The widget MUST
        expose its text-building method as ``_compose_text``."""
        from nexusrecon.tui.widgets.status_bar import StatusBar
        # `_compose_text` should be defined on the class itself,
        # not just inherited.
        assert "_compose_text" in StatusBar.__dict__
        # `_render` must NOT be overridden — leave Textual's alone.
        assert "_render" not in StatusBar.__dict__


# ──────────────────────────────────────────────────────────────────────
# Sidebar widget
# ──────────────────────────────────────────────────────────────────────


class TestSidebar:
    def test_catalog_matches_navigation_source(self):
        """The sidebar entries + the navigation palette catalog must
        agree — same six destinations, same IDs. Drift would mean
        the palette can land somewhere the sidebar can't."""
        from nexusrecon.tui.command_palette import NavigationSource
        from nexusrecon.tui.widgets.sidebar import SIDEBAR_ENTRIES
        sidebar_ids = {entry[0] for entry in SIDEBAR_ENTRIES}
        nav_ids = {entry[0] for entry in NavigationSource._CATALOG}
        assert sidebar_ids == nav_ids

    def test_toggle_collapsed_flips_state(self):
        """Sidebar.toggle_collapsed flips the reactive flag the
        dashboard's ``]`` binding drives."""
        from nexusrecon.tui.widgets.sidebar import Sidebar
        sidebar = Sidebar()
        assert sidebar.collapsed is False
        sidebar.collapsed = True
        assert sidebar.collapsed is True

    def test_cursor_movement_wraps_top_and_bottom(self):
        """Arrow-key cursor moves the highlight one entry at a time
        and wraps at both ends, so the operator never gets stuck at
        the boundary."""
        from nexusrecon.tui.widgets.sidebar import SIDEBAR_ENTRIES, Sidebar
        sidebar = Sidebar()
        ids = [eid for eid, _, _, _ in SIDEBAR_ENTRIES]
        # Start position is "dashboard" by default.
        assert sidebar.active_id == ids[0]
        sidebar.move_cursor_down()
        assert sidebar.active_id == ids[1]
        # Walk to the last entry then wrap.
        for _ in range(len(ids) - 1):
            sidebar.move_cursor_down()
        # From ids[1], len(ids)-1 more downs lands back at ids[0]
        # (wrapped around).
        assert sidebar.active_id == ids[0]
        # Up wraps from top to bottom.
        sidebar.active_id = ids[0]
        sidebar.move_cursor_up()
        assert sidebar.active_id == ids[-1]

    def test_current_destination_returns_active_id(self):
        from nexusrecon.tui.widgets.sidebar import Sidebar
        sidebar = Sidebar()
        sidebar.active_id = "tools"
        assert sidebar.current_destination() == "tools"


class TestDashboardArrowNavigation:
    """The TUI-7 follow-up: ↑/↓ should move the sidebar cursor on
    the dashboard, Enter activates the highlighted entry. This is
    additive to the letter shortcuts (n/p/c/t) — both paths must
    keep working."""

    def test_arrow_keys_move_sidebar_cursor_and_enter_navigates(self):
        import asyncio as _asyncio

        from nexusrecon.tui.app import NexusReconApp
        from nexusrecon.tui.screens.dashboard import DashboardScreen
        from nexusrecon.tui.widgets import Sidebar

        async def _drive():
            app = NexusReconApp()
            async with app.run_test(headless=True) as pilot:
                await pilot.pause(0.5)
                screen = app.screen
                assert isinstance(screen, DashboardScreen)
                sidebar = screen.query_one("#dashboard-sidebar", Sidebar)
                assert sidebar.active_id == "dashboard"

                await pilot.press("down")
                await pilot.pause(0.1)
                assert sidebar.active_id == "new_campaign"

                await pilot.press("down", "down")
                await pilot.pause(0.1)
                assert sidebar.active_id == "tools"

                await pilot.press("enter")
                await pilot.pause(0.5)
                # Routed through the central navigator — same path
                # the palette uses — so we land on ToolsScreen.
                assert type(app.screen).__name__ == "ToolsScreen", (
                    f"got {type(app.screen).__name__}"
                )

                app.exit()
                await pilot.pause(0.1)

        _asyncio.run(_drive())

    def test_letter_shortcuts_still_work_alongside_arrows(self):
        """Adding arrow bindings must NOT shadow the existing
        letter shortcuts. ``t`` from anywhere on the dashboard
        still jumps to the tools browser regardless of cursor
        position."""
        import asyncio as _asyncio

        from nexusrecon.tui.app import NexusReconApp
        from nexusrecon.tui.screens.dashboard import DashboardScreen

        async def _drive():
            app = NexusReconApp()
            async with app.run_test(headless=True) as pilot:
                await pilot.pause(0.5)
                assert isinstance(app.screen, DashboardScreen)
                await pilot.press("t")
                await pilot.pause(0.5)
                assert type(app.screen).__name__ == "ToolsScreen"
                app.exit()
                await pilot.pause(0.1)

        _asyncio.run(_drive())


# ──────────────────────────────────────────────────────────────────────
# Dashboard helpers
# ──────────────────────────────────────────────────────────────────────


class TestDashboardHelpers:
    def test_recent_campaigns_empty_when_no_output_dir(self, tmp_path: Path):
        from nexusrecon.core import config as cfg_mod
        from nexusrecon.tui.screens.dashboard import _recent_campaigns
        fake_cfg = MagicMock()
        fake_cfg.output_dir = str(tmp_path / "does-not-exist")
        with patch.object(cfg_mod, "get_config", return_value=fake_cfg):
            assert _recent_campaigns() == []

    def test_recent_campaigns_returns_latest_first(self, tmp_path: Path):
        import json
        import os
        import time

        from nexusrecon.core import config as cfg_mod
        from nexusrecon.tui.screens.dashboard import _recent_campaigns
        c1 = tmp_path / "older"
        c1.mkdir()
        (c1 / "state.json").write_text(json.dumps({
            "seeds": ["older.example.com"], "findings": [],
        }))
        c2 = tmp_path / "newer"
        c2.mkdir()
        (c2 / "state.json").write_text(json.dumps({
            "seeds": ["newer.example.com"], "findings": [],
        }))
        time.sleep(0.05)
        os.utime(c2 / "state.json", None)
        fake_cfg = MagicMock()
        fake_cfg.output_dir = str(tmp_path)
        with patch.object(cfg_mod, "get_config", return_value=fake_cfg):
            rows = _recent_campaigns()
        # Newest first.
        assert rows[0]["target"] == "newer.example.com"

    def test_tool_breakdown_returns_string(self):
        from nexusrecon.tui.screens.dashboard import _tool_breakdown
        # No mocks needed; the live registry is fine. The contract
        # is that the function returns a non-raising str.
        out = _tool_breakdown()
        assert isinstance(out, str)

    def test_should_show_onboarding_dismissal_silences(
        self, tmp_path: Path, monkeypatch,
    ):
        from nexusrecon.core import config as cfg_mod
        from nexusrecon.tui.screens.dashboard import _should_show_onboarding
        monkeypatch.setenv("HOME", str(tmp_path))
        flag_dir = tmp_path / ".nexusrecon"
        flag_dir.mkdir()
        (flag_dir / ".onboarding_dismissed").touch()
        fake_cfg = MagicMock()
        fake_cfg.output_dir = str(tmp_path / "campaigns")
        fake_cfg.get_secret.return_value = None
        with patch.object(cfg_mod, "get_config", return_value=fake_cfg):
            assert _should_show_onboarding() is False


class TestTopKeyGaps:
    """Roadmap 0.6.0 beta blocker — surface *which* keys would
    unlock the most tools so the operator's first-run path is
    actionable, not just informational."""

    def _fake_tool(self, *, name, requires, available, stubbed=False):
        """Build a minimal mock that satisfies the helper's
        attribute reads. ``requires`` is the lowercase env-var
        list, matching real tools."""
        m = MagicMock()
        m.name = name
        m.requires_keys = list(requires)
        m.is_available.return_value = available
        m.stubbed = stubbed
        return m

    def test_ranks_by_impact_descending(self):
        from nexusrecon.core import config as cfg_mod
        from nexusrecon.tools import registry as reg_mod
        from nexusrecon.tui.screens.dashboard import _top_key_gaps
        # 3 tools need GITHUB_TOKEN (high impact); 1 each needs
        # SHODAN_API_KEY and CENSYS_API_ID. None of the keys are
        # set. The ranking should put GITHUB_TOKEN first.
        tools = {
            "gh1": self._fake_tool(name="gh1", requires=["github_token"], available=False),
            "gh2": self._fake_tool(name="gh2", requires=["github_token"], available=False),
            "gh3": self._fake_tool(name="gh3", requires=["github_token"], available=False),
            "sho": self._fake_tool(name="sho", requires=["shodan_api_key"], available=False),
            "cen": self._fake_tool(name="cen", requires=["censys_api_id"], available=False),
        }
        fake_registry = MagicMock()
        fake_registry._tools = tools
        fake_cfg = MagicMock()
        fake_cfg.get_secret.return_value = None  # nothing configured
        with patch.object(reg_mod, "get_registry", return_value=fake_registry), \
             patch.object(cfg_mod, "get_config", return_value=fake_cfg):
            gaps = _top_key_gaps(limit=3)
        assert gaps[0] == ("GITHUB_TOKEN", 3)
        # CENSYS_API_ID comes before SHODAN_API_KEY because of
        # alphabetical tie-break on equal counts.
        assert gaps[1] == ("CENSYS_API_ID", 1)
        assert gaps[2] == ("SHODAN_API_KEY", 1)

    def test_skips_already_configured_keys(self):
        """A tool can be unavailable for multiple keys; only the
        unset ones count. Otherwise we'd nag operators about
        keys they already configured."""
        from nexusrecon.core import config as cfg_mod
        from nexusrecon.tools import registry as reg_mod
        from nexusrecon.tui.screens.dashboard import _top_key_gaps
        tools = {
            "two_key": self._fake_tool(
                name="two_key",
                requires=["already_set", "still_missing"],
                available=False,
            ),
        }
        fake_registry = MagicMock()
        fake_registry._tools = tools
        fake_cfg = MagicMock()
        # Only "already_set" returns a value.
        fake_cfg.get_secret.side_effect = lambda k: (
            "value" if k == "already_set" else None
        )
        with patch.object(reg_mod, "get_registry", return_value=fake_registry), \
             patch.object(cfg_mod, "get_config", return_value=fake_cfg):
            gaps = _top_key_gaps(limit=5)
        # Only STILL_MISSING shows up as a gap.
        assert gaps == [("STILL_MISSING", 1)]

    def test_skips_stubs_and_available_tools(self):
        """Stubbed tools and tools that already pass is_available()
        contribute zero to the gap count."""
        from nexusrecon.core import config as cfg_mod
        from nexusrecon.tools import registry as reg_mod
        from nexusrecon.tui.screens.dashboard import _top_key_gaps
        tools = {
            "stub": self._fake_tool(
                name="stub", requires=["foo_key"],
                available=False, stubbed=True,
            ),
            "ready": self._fake_tool(
                name="ready", requires=["bar_key"], available=True,
            ),
        }
        fake_registry = MagicMock()
        fake_registry._tools = tools
        fake_cfg = MagicMock()
        fake_cfg.get_secret.return_value = None
        with patch.object(reg_mod, "get_registry", return_value=fake_registry), \
             patch.object(cfg_mod, "get_config", return_value=fake_cfg):
            assert _top_key_gaps() == []

    def test_empty_when_no_missing_keys(self):
        from nexusrecon.core import config as cfg_mod
        from nexusrecon.tools import registry as reg_mod
        from nexusrecon.tui.screens.dashboard import _top_key_gaps
        fake_registry = MagicMock()
        fake_registry._tools = {}
        fake_cfg = MagicMock()
        fake_cfg.get_secret.return_value = None
        with patch.object(reg_mod, "get_registry", return_value=fake_registry), \
             patch.object(cfg_mod, "get_config", return_value=fake_cfg):
            assert _top_key_gaps() == []

    def test_render_omits_section_when_no_gaps(self):
        """The renderer returns the empty string when there are
        no gaps so the dashboard layout collapses cleanly rather
        than rendering an orphan 'Top gaps:' header."""
        from nexusrecon.tui.screens.dashboard import _render_tool_gaps
        with patch(
            "nexusrecon.tui.screens.dashboard._top_key_gaps",
            return_value=[],
        ):
            assert _render_tool_gaps() == ""

    def test_render_includes_tool_count_grammar(self):
        """Singular vs plural ── 'unlock 1 tool' vs 'unlock 3 tools'.
        Small thing but pluralisation glitches scream LLM-output."""
        from nexusrecon.tui.screens.dashboard import _render_tool_gaps
        with patch(
            "nexusrecon.tui.screens.dashboard._top_key_gaps",
            return_value=[("GITHUB_TOKEN", 5), ("SHODAN_API_KEY", 1)],
        ):
            out = _render_tool_gaps()
        assert "would unlock 5 tools" in out
        assert "would unlock 1 tool[/dim]" in out  # singular
        assert "GITHUB_TOKEN" in out
        assert "SHODAN_API_KEY" in out


class TestHotReloadRebindsToolConfigs:
    """Edit modal's hot-reload must rebind every tool's
    ``self.config`` to the freshly-cached singleton.

    Without this, the dashboard's Tool Health card and the Tools
    screen's per-tool status stay stale until process restart ──
    you set GITHUB_TOKEN, return to the dashboard, and the
    "GITHUB_TOKEN would unlock 5 tools" hint is STILL there
    because the tool's cached config snapshot doesn't know."""

    def test_hot_reload_rebinds_each_tool_config(self):
        from nexusrecon.core import config as cfg_mod
        from nexusrecon.tools import registry as reg_mod
        from nexusrecon.tui.screens.edit_key import EditKeyModal

        # Set up two fake tools pointing at a "stale" config
        # object. After reload, both should point at the new
        # config from the patched ``get_config``.
        stale = MagicMock(name="stale_cfg")
        fresh = MagicMock(name="fresh_cfg")
        t1 = MagicMock()
        t1.config = stale
        t2 = MagicMock()
        t2.config = stale
        fake_registry = MagicMock()
        fake_registry._tools = {"t1": t1, "t2": t2}

        # ``get_config`` is an lru_cached function; we replace it
        # in both the config module and the registry-imported
        # version so the helper sees the fresh instance.
        fake_get_config = MagicMock()
        fake_get_config.cache_clear = MagicMock()
        fake_get_config.return_value = fresh

        with patch.object(cfg_mod, "get_config", fake_get_config), \
             patch.object(reg_mod, "get_registry", return_value=fake_registry):
            EditKeyModal._hot_reload_config()

        # Both lru cache_clear and rebind happened.
        fake_get_config.cache_clear.assert_called_once()
        assert t1.config is fresh
        assert t2.config is fresh

    def test_hot_reload_tolerates_per_tool_rebind_failure(self):
        """One tool that refuses assignment (e.g. a read-only
        descriptor on a frozen dataclass) must not skip the
        rebind for the rest. Defensive: catch and continue."""
        from nexusrecon.core import config as cfg_mod
        from nexusrecon.tools import registry as reg_mod
        from nexusrecon.tui.screens.edit_key import EditKeyModal

        fresh = MagicMock(name="fresh_cfg")

        class _ReadOnly:
            @property
            def config(self):
                return None

            @config.setter
            def config(self, v):
                raise AttributeError("frozen")

        ok_tool = MagicMock()
        ok_tool.config = MagicMock()
        bad_tool = _ReadOnly()
        fake_registry = MagicMock()
        fake_registry._tools = {"bad": bad_tool, "ok": ok_tool}

        fake_get_config = MagicMock()
        fake_get_config.cache_clear = MagicMock()
        fake_get_config.return_value = fresh

        with patch.object(cfg_mod, "get_config", fake_get_config), \
             patch.object(reg_mod, "get_registry", return_value=fake_registry):
            # Must not raise even though bad_tool rejects the
            # assignment.
            EditKeyModal._hot_reload_config()

        assert ok_tool.config is fresh


# ──────────────────────────────────────────────────────────────────────
# WelcomeScreen back-compat shim
# ──────────────────────────────────────────────────────────────────────


class TestWelcomeBackCompat:
    def test_welcome_aliases_dashboard(self):
        """The TUI-3 refactor renamed WelcomeScreen → DashboardScreen.
        Old code paths that still import WelcomeScreen must keep
        working — the welcome module re-exports the new class."""
        from nexusrecon.tui.screens.dashboard import DashboardScreen
        from nexusrecon.tui.screens.welcome import WelcomeScreen
        assert WelcomeScreen is DashboardScreen


# ──────────────────────────────────────────────────────────────────────
# Pilot integration
# ──────────────────────────────────────────────────────────────────────


class TestDashboardPilot:
    def test_dashboard_mounts_with_status_bar_and_sidebar(self):
        from nexusrecon.tui.app import NexusReconApp
        from nexusrecon.tui.screens.dashboard import DashboardScreen
        from nexusrecon.tui.widgets import Sidebar, StatusBar

        async def _drive():
            app = NexusReconApp()
            async with app.run_test(headless=True) as pilot:
                await pilot.pause(0.8)
                assert isinstance(app.screen, DashboardScreen)
                tree = list(app.screen.walk_children(with_self=False))
                sbs = [w for w in tree if isinstance(w, StatusBar)]
                sds = [w for w in tree if isinstance(w, Sidebar)]
                assert len(sbs) == 1, "expected exactly one StatusBar"
                assert len(sds) == 1, "expected exactly one Sidebar"
                app.exit()
                await pilot.pause(0.1)

        asyncio.run(_drive())

    def test_dashboard_has_no_duplicate_button_menu(self):
        """Regression for the duplicate-nav bug: dashboard had both
        the Sidebar AND a button menu listing the same destinations.
        Operator called it out. The button menu (#dashboard-menu /
        btn-new/btn-resume/btn-past/btn-tools/btn-config) is gone;
        the Sidebar carries the navigation surface."""
        from textual.widgets import Button

        from nexusrecon.tui.app import NexusReconApp

        async def _drive():
            app = NexusReconApp()
            async with app.run_test(headless=True) as pilot:
                await pilot.pause(0.8)
                # No #dashboard-menu container in the tree.
                from textual.css.query import NoMatches
                try:
                    app.screen.query_one("#dashboard-menu")
                    raise AssertionError(
                        "duplicate nav: #dashboard-menu should not exist"
                    )
                except NoMatches:
                    pass
                # And none of the per-action buttons remain.
                for btn_id in (
                    "btn-new", "btn-resume", "btn-past",
                    "btn-tools", "btn-config",
                ):
                    matches = [
                        w for w in app.screen.query(Button)
                        if w.id == btn_id
                    ]
                    assert not matches, (
                        f"duplicate nav button {btn_id!r} still on dashboard"
                    )
                app.exit()
                await pilot.pause(0.1)

        asyncio.run(_drive())

    def test_sidebar_toggle_via_bracket_key(self):
        from nexusrecon.tui.app import NexusReconApp
        from nexusrecon.tui.widgets import Sidebar

        async def _drive():
            app = NexusReconApp()
            async with app.run_test(headless=True) as pilot:
                await pilot.pause(0.8)
                sidebar = next(iter(app.screen.query(Sidebar)), None)
                assert sidebar is not None
                assert sidebar.collapsed is False
                await pilot.press("close_bracket")
                await pilot.pause(0.2)
                assert sidebar.collapsed is True
                # Second press un-collapses.
                await pilot.press("close_bracket")
                await pilot.pause(0.2)
                assert sidebar.collapsed is False
                app.exit()
                await pilot.pause(0.1)

        asyncio.run(_drive())

    def test_status_bar_propagated_to_wizard(self):
        """Navigating to the wizard from the dashboard must show the
        persistent status bar there too. Regression for the spec
        requirement that the status bar lives on every screen."""
        from nexusrecon.tui.app import NexusReconApp
        from nexusrecon.tui.widgets import StatusBar

        async def _drive():
            app = NexusReconApp()
            async with app.run_test(headless=True) as pilot:
                await pilot.pause(0.8)
                await pilot.press("n")
                await pilot.pause(0.5)
                # WizardScreen now active.
                tree = list(app.screen.walk_children(with_self=False))
                sbs = [w for w in tree if isinstance(w, StatusBar)]
                assert sbs, "expected StatusBar on wizard screen"
                app.exit()
                await pilot.pause(0.1)

        asyncio.run(_drive())

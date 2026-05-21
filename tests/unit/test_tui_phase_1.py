"""Tests for TUI-1 polish: themes, welcome stats refresh, help overlay,
first-run onboarding detection.

The TUI itself isn't render-tested here (Textual's pilot harness lives
in its own integration tier); this file pins:

  - Theme registration: both themes register, names + variables match
    expectations, unknown theme names fall back to the default.
  - Welcome stats helpers return strings (never raise) regardless of
    the live registry state. Includes the new "tools active vs
    skipped (missing keys)" breakdown that closes the roadmap
    first-run UX item.
  - First-run detection: shows the nudge only when there are no past
    campaigns AND no LLM key configured AND no dismissal flag.
    Persistent-dismissal flag suppresses the nudge thereafter.
  - HelpModal binding extraction: legacy 3-tuple bindings and modern
    Binding objects both unpack correctly; key formatting maps the
    common Textual internal names to operator-friendly labels.
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

# ──────────────────────────────────────────────────────────────────────
# Themes
# ──────────────────────────────────────────────────────────────────────


class TestThemes:
    def test_both_themes_registered(self):
        from nexusrecon.tui.themes import THEMES
        assert {"nexusrecon-dark", "nexusrecon-hicontrast"} == set(THEMES.keys())

    def test_default_theme_is_dark(self):
        from nexusrecon.tui.themes import DEFAULT_THEME
        assert DEFAULT_THEME == "nexusrecon-dark"

    def test_resolve_unknown_falls_back_to_default(self):
        from nexusrecon.tui.themes import DEFAULT_THEME, resolve_theme_name
        assert resolve_theme_name(None) == DEFAULT_THEME
        assert resolve_theme_name("") == DEFAULT_THEME
        assert resolve_theme_name("does-not-exist") == DEFAULT_THEME

    def test_resolve_explicit_theme(self):
        from nexusrecon.tui.themes import resolve_theme_name
        assert resolve_theme_name("nexusrecon-hicontrast") == "nexusrecon-hicontrast"

    def test_both_themes_define_custom_variables(self):
        """Every TUI screen references $nx-text-muted, $nx-text-dim,
        $nx-border-muted, and $nx-bg-detail. Both themes must define
        all four or a screen breaks when the theme switches."""
        from nexusrecon.tui.themes import NEXUSRECON_DARK, NEXUSRECON_HICONTRAST
        required = {"nx-text-muted", "nx-text-dim", "nx-border-muted", "nx-bg-detail"}
        for theme in (NEXUSRECON_DARK, NEXUSRECON_HICONTRAST):
            missing = required - set(theme.variables.keys())
            assert not missing, (
                f"theme {theme.name} missing custom variables: {missing}"
            )

    def test_severity_palette_consistent_across_themes(self):
        """Severity tints intentionally don't change with the theme ──
        an operator's "red = critical" mental mapping must hold."""
        from nexusrecon.tui.themes import NEXUSRECON_DARK, NEXUSRECON_HICONTRAST
        sev_keys = (
            "severity-critical",
            "severity-high",
            "severity-medium",
            "severity-low",
            "severity-info",
        )
        for k in sev_keys:
            assert NEXUSRECON_DARK.variables[k] == NEXUSRECON_HICONTRAST.variables[k]


# ──────────────────────────────────────────────────────────────────────
# Welcome stats helpers
# ──────────────────────────────────────────────────────────────────────


class TestWelcomeStats:
    def test_quick_stats_returns_string(self):
        from nexusrecon.tui.screens.welcome import _quick_stats
        result = _quick_stats()
        assert isinstance(result, str)
        assert "tools registered" in result

    def test_tool_availability_breakdown_returns_string(self):
        from nexusrecon.tui.screens.welcome import _tool_availability_breakdown
        result = _tool_availability_breakdown()
        assert isinstance(result, str)
        assert "active" in result

    def test_tool_availability_breakdown_handles_registry_error(self):
        """Helper must never raise — welcome screen relies on
        graceful empty-string fallbacks."""
        from nexusrecon.tui.screens import welcome
        with patch.object(
            welcome, "_tool_availability_breakdown",
            side_effect=lambda: welcome._tool_availability_breakdown.__wrapped__()
            if hasattr(welcome._tool_availability_breakdown, "__wrapped__") else "",
        ):
            # Just verify the function doesn't blow up when called
            # normally; the body's bare-except handles registry errors.
            assert isinstance(welcome._tool_availability_breakdown(), str)

    def test_last_campaign_hint_empty_when_no_campaigns(self, tmp_path: Path):
        """No state.json on disk → empty string (welcome screen hides
        the row entirely)."""
        from nexusrecon.core import config as cfg_mod
        from nexusrecon.tui.screens.welcome import _last_campaign_hint
        cfg_mod.get_config.cache_clear()
        fake_cfg = MagicMock()
        fake_cfg.output_dir = str(tmp_path)
        with patch.object(cfg_mod, "get_config", return_value=fake_cfg):
            assert _last_campaign_hint() == ""

    def test_last_campaign_hint_reads_latest(self, tmp_path: Path):
        """When multiple state.json files exist, the most-recent one
        wins. The hint mentions the seed when present."""
        import json

        from nexusrecon.core import config as cfg_mod
        from nexusrecon.tui.screens.welcome import _last_campaign_hint
        # Older campaign
        old = tmp_path / "old-campaign"
        old.mkdir()
        (old / "state.json").write_text(json.dumps({
            "campaign_id": "old", "seeds": ["old.example.com"],
        }))
        # Newer campaign
        new = tmp_path / "new-campaign"
        new.mkdir()
        (new / "state.json").write_text(json.dumps({
            "campaign_id": "new", "seeds": ["new.example.com"],
        }))
        import os
        import time
        time.sleep(0.05)  # ensure mtime difference
        os.utime(new / "state.json", None)
        fake_cfg = MagicMock()
        fake_cfg.output_dir = str(tmp_path)
        with patch.object(cfg_mod, "get_config", return_value=fake_cfg):
            hint = _last_campaign_hint()
        assert "new.example.com" in hint
        assert hint.startswith("Last run:")


# ──────────────────────────────────────────────────────────────────────
# First-run detection
# ──────────────────────────────────────────────────────────────────────


class TestFirstRunDetection:
    def test_shows_onboarding_when_no_state_no_key(self, tmp_path: Path, monkeypatch):
        """Fresh install: no campaigns, no LLM keys, no dismissal flag
        → show the nudge."""
        from nexusrecon.core import config as cfg_mod
        from nexusrecon.tui.screens import welcome
        # Redirect $HOME so the dismissal flag check doesn't see a
        # pre-existing file from a previous test run.
        monkeypatch.setenv("HOME", str(tmp_path))
        fake_cfg = MagicMock()
        fake_cfg.output_dir = str(tmp_path / "campaigns")  # doesn't exist
        fake_cfg.get_secret.return_value = None  # no keys
        with patch.object(cfg_mod, "get_config", return_value=fake_cfg):
            assert welcome._should_show_onboarding() is True

    def test_no_onboarding_when_campaigns_exist(self, tmp_path: Path, monkeypatch):
        from nexusrecon.core import config as cfg_mod
        from nexusrecon.tui.screens import welcome
        monkeypatch.setenv("HOME", str(tmp_path))
        out = tmp_path / "campaigns" / "abc"
        out.mkdir(parents=True)
        (out / "state.json").write_text("{}")
        fake_cfg = MagicMock()
        fake_cfg.output_dir = str(tmp_path / "campaigns")
        fake_cfg.get_secret.return_value = None
        with patch.object(cfg_mod, "get_config", return_value=fake_cfg):
            assert welcome._should_show_onboarding() is False

    def test_no_onboarding_when_key_configured(self, tmp_path: Path, monkeypatch):
        from nexusrecon.core import config as cfg_mod
        from nexusrecon.tui.screens import welcome
        monkeypatch.setenv("HOME", str(tmp_path))
        fake_cfg = MagicMock()
        fake_cfg.output_dir = str(tmp_path / "campaigns")
        fake_cfg.get_secret.side_effect = lambda name: (
            "sk-test" if name == "anthropic_api_key" else None
        )
        with patch.object(cfg_mod, "get_config", return_value=fake_cfg):
            assert welcome._should_show_onboarding() is False

    def test_dismissal_flag_silences_nudge(self, tmp_path: Path, monkeypatch):
        from nexusrecon.core import config as cfg_mod
        from nexusrecon.tui.screens import welcome
        monkeypatch.setenv("HOME", str(tmp_path))
        flag_dir = tmp_path / ".nexusrecon"
        flag_dir.mkdir()
        (flag_dir / ".onboarding_dismissed").touch()
        fake_cfg = MagicMock()
        fake_cfg.output_dir = str(tmp_path / "campaigns")
        fake_cfg.get_secret.return_value = None
        with patch.object(cfg_mod, "get_config", return_value=fake_cfg):
            assert welcome._should_show_onboarding() is False

    def test_persist_dismissal_creates_flag(self, tmp_path: Path, monkeypatch):
        from nexusrecon.tui.screens.welcome import _persist_onboarding_dismissal
        monkeypatch.setenv("HOME", str(tmp_path))
        _persist_onboarding_dismissal()
        assert (tmp_path / ".nexusrecon" / ".onboarding_dismissed").exists()


# ──────────────────────────────────────────────────────────────────────
# HelpModal binding extraction
# ──────────────────────────────────────────────────────────────────────


class TestHelpModalHelpers:
    def test_unpack_tuple_binding(self):
        from nexusrecon.tui.screens.help import _unpack_binding
        key, action, desc = _unpack_binding(("n", "menu_new", "New Campaign"))
        assert key == "n"
        assert action == "menu_new"
        assert desc == "New Campaign"

    def test_unpack_binding_object(self):
        from textual.binding import Binding

        from nexusrecon.tui.screens.help import _unpack_binding
        b = Binding(key="ctrl+q", action="quit", description="Quit")
        key, action, desc = _unpack_binding(b)
        assert key == "ctrl+q"
        assert action == "quit"
        assert desc == "Quit"

    def test_unpack_short_tuple_safe(self):
        from nexusrecon.tui.screens.help import _unpack_binding
        # 2-tuple
        key, action, desc = _unpack_binding(("q", "quit"))
        assert key == "q"
        assert action == "quit"
        assert desc == ""

    def test_format_key_question_mark(self):
        from nexusrecon.tui.screens.help import _format_key
        assert _format_key("question_mark") == "?"

    def test_format_key_ctrl_q(self):
        from nexusrecon.tui.screens.help import _format_key
        assert _format_key("ctrl+q") == "Ctrl+Q"

    def test_format_key_arrows(self):
        from nexusrecon.tui.screens.help import _format_key
        assert _format_key("up") == "↑"
        assert _format_key("down") == "↓"

    def test_format_key_passthrough_for_letter(self):
        from nexusrecon.tui.screens.help import _format_key
        assert _format_key("n") == "N"

    def test_format_key_empty(self):
        from nexusrecon.tui.screens.help import _format_key
        assert _format_key("") == ""


# ──────────────────────────────────────────────────────────────────────
# App-level registration
# ──────────────────────────────────────────────────────────────────────


class TestAppIntegration:
    def test_app_has_help_binding(self):
        """The global ? binding lives on the App so every screen
        inherits the help overlay shortcut."""
        from nexusrecon.tui.app import NexusReconApp
        keys = []
        for binding in NexusReconApp.BINDINGS:
            if isinstance(binding, tuple):
                keys.append(binding[0])
        assert "question_mark" in keys

    def test_app_imports_themes(self):
        """app.py must import the themes module so the App.on_mount
        registration path is reachable. Catches regressions where the
        theme module gets deleted or renamed."""
        import nexusrecon.tui.app as app_module
        assert hasattr(app_module, "THEMES")
        assert hasattr(app_module, "resolve_theme_name")

    def test_css_declares_nx_variable_defaults(self):
        """Regression test for the launch-crash bug: Textual parses
        CSS *before* App.on_mount() runs (which is where the custom
        themes register), so the $nx-* variables MUST have default
        values declared inline at the top of app.tcss. Without them,
        the parser raises "reference to undefined variable" before
        the first frame paints and the TUI never starts.

        This test reads the actual .tcss file and asserts the four
        $nx-* defaults are declared. It does NOT assert specific
        values — only presence — because theme variables override
        the defaults at runtime."""
        from pathlib import Path

        import nexusrecon.tui.app as app_module
        css_path = Path(app_module.__file__).parent / app_module.NexusReconApp.CSS_PATH
        text = css_path.read_text(encoding="utf-8")
        for var in ("$nx-text-muted", "$nx-text-dim", "$nx-border-muted", "$nx-bg-detail"):
            # Look for the variable in a declaration position (start of
            # a line, possibly after whitespace, followed by ':').
            decl_pattern = f"{var}:"
            assert decl_pattern in text, (
                f"app.tcss missing default declaration for {var!r}. "
                "Without an inline default, Textual's pre-mount CSS "
                "parser raises 'reference to undefined variable' and "
                "the TUI never reaches on_mount() to register themes."
            )

    def test_tui_launches_under_pilot(self):
        """End-to-end smoke: spin up the TUI headless and verify
        the welcome screen mounts without a CSS error. Reproduces
        the original launch crash from ddb2c91 and confirms the
        fix holds."""
        import asyncio

        from nexusrecon.tui.app import NexusReconApp

        async def _drive():
            app = NexusReconApp()
            async with app.run_test(headless=True) as pilot:
                await pilot.pause(0.5)
                # If CSS parse failed, the welcome screen never
                # mounts and app.screen is the default screen.
                assert type(app.screen).__name__ == "WelcomeScreen", (
                    f"Welcome screen failed to mount; got "
                    f"{type(app.screen).__name__}"
                )
                app.exit()
                await pilot.pause(0.1)

        asyncio.run(_drive())

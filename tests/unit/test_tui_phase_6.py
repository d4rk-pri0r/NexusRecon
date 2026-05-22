"""Tests for TUI-6 polish: light theme registration + notification
wiring.

The light theme is the third member of the THEMES registry; it
ships with the same semantic colour tokens as the other two so
every CSS rule that references the existing ``$primary`` etc.
re-themes automatically.

Notification wiring is exercised via the headless pilot harness:
saving / clearing a config key triggers ``App.notify(...)``, which
queues a toast on the live screen. We can't inspect the toast's
on-screen render without a real terminal driver, but we can verify
the call lands by patching ``App.notify`` and asserting the call
shape.
"""
from __future__ import annotations

import asyncio
from unittest.mock import patch

# ──────────────────────────────────────────────────────────────────────
# Light theme
# ──────────────────────────────────────────────────────────────────────


class TestLightTheme:
    def test_light_theme_registered(self):
        from nexusrecon.tui.themes import THEMES
        assert "nexusrecon-light" in THEMES

    def test_light_resolve(self):
        from nexusrecon.tui.themes import resolve_theme_name
        assert resolve_theme_name("nexusrecon-light") == "nexusrecon-light"

    def test_light_is_not_dark(self):
        """The whole point of the light theme is dark=False so
        Textual treats it as a light variant for its built-in
        widgets (Header, Footer, system command palette, …)."""
        from nexusrecon.tui.themes import NEXUSRECON_LIGHT
        assert NEXUSRECON_LIGHT.dark is False

    def test_light_has_all_required_nx_vars(self):
        from nexusrecon.tui.themes import NEXUSRECON_LIGHT
        required = {
            "nx-text-muted", "nx-text-dim",
            "nx-border-muted", "nx-bg-detail",
        }
        assert required.issubset(NEXUSRECON_LIGHT.variables.keys())

    def test_light_severity_palette_consistent(self):
        """Severity tints must not flip when the operator switches
        themes — ``red = critical`` is muscle memory."""
        from nexusrecon.tui.themes import NEXUSRECON_DARK, NEXUSRECON_LIGHT
        for k in ("severity-critical", "severity-high",
                  "severity-medium", "severity-low", "severity-info"):
            assert NEXUSRECON_DARK.variables[k] == NEXUSRECON_LIGHT.variables[k]

    def test_app_can_activate_light_theme(self, monkeypatch):
        from nexusrecon.tui.app import NexusReconApp

        async def _drive():
            monkeypatch.setenv("NEXUSRECON_TUI_THEME", "nexusrecon-light")
            app = NexusReconApp()
            async with app.run_test(headless=True) as pilot:
                await pilot.pause(0.5)
                assert app.theme == "nexusrecon-light"
                app.exit()
                await pilot.pause(0.1)

        asyncio.run(_drive())


# ──────────────────────────────────────────────────────────────────────
# Notification wiring
# ──────────────────────────────────────────────────────────────────────


class TestNotificationsFired:
    def test_edit_key_save_notifies(self, tmp_path):
        """Saving a key through EditKeyModal must surface a toast
        via App.notify so the operator gets concrete feedback."""
        import asyncio as _asyncio

        from nexusrecon.tui.app import NexusReconApp
        from nexusrecon.tui.config_schema import ConfigVar
        from nexusrecon.tui.screens.edit_key import EditKeyModal

        env_path = tmp_path / ".env"
        env_path.write_text("")
        var = ConfigVar(
            key="TEST_KEY",
            help="for tests",
            sensitive=False,
        )

        captured: list[tuple[str, str | None]] = []

        async def _drive():
            app = NexusReconApp()

            async with app.run_test(headless=True) as pilot:
                await pilot.pause(0.5)
                # Push the modal directly.
                modal = EditKeyModal(env_path=str(env_path), var=var)
                await app.push_screen(modal)
                await pilot.pause(0.3)
                # Patch notify so we can capture the call.
                with patch.object(
                    NexusReconApp, "notify",
                    side_effect=lambda message, **kwargs: captured.append(
                        (message, kwargs.get("severity")),
                    ),
                ):
                    # Simulate writing a value via the input + saving.
                    inp = modal.query_one("#edit-input")
                    inp.value = "hello"
                    modal.action_save()
                    await pilot.pause(0.2)
                app.exit()
                await pilot.pause(0.1)

        _asyncio.run(_drive())
        # At least one notify call with our key name should land.
        assert any(
            "TEST_KEY" in msg for msg, _ in captured
        ), f"expected TEST_KEY notify; got {captured}"

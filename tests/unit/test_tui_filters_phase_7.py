"""Tests for the TUI-7 cross-screen ``/`` filter pattern.

TUI-7 added k9s-style substring filters to the Campaigns and
Reports list views, plus a cross-screen vocabulary section in
the Help modal. These tests pin the wire-level contracts.

The implementation is similar across screens (hidden Input
revealed by ``/``, ``on_input_changed`` rebuilds the visible
list, ``Esc`` clears + hides). We assert against each screen
independently because the filter-target shape (list of dicts
for Campaigns, list of ``ReportEntry`` for Reports) differs.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest
from unittest.mock import patch

from nexusrecon.tui.app import NexusReconApp
from nexusrecon.tui.screens.campaigns import CampaignsScreen
from nexusrecon.tui.screens.help import HelpModal
from nexusrecon.tui.screens.reports_browser import (
    ReportEntry,
    ReportsBrowserScreen,
)


# ──────────────────────────────────────────────────────────────────────
# Campaigns filter
# ──────────────────────────────────────────────────────────────────────


def _campaign(cid: str, client: str, status: str = "DONE") -> dict[str, Any]:
    """Build a minimal campaign dict — same shape ``on_mount``
    builds when reading state.json. Letting tests construct
    directly avoids the disk-walking dependency."""
    return {
        "campaign_id": cid,
        "client": client,
        "engagement_id": f"ENG-{cid}",
        "campaign_dir": f"/fake/{cid}",
        "state_file": f"/fake/{cid}/state.json",
        "state": {"scope_hash": "sha256:abc", "findings": [], "seeds": ["x.com"]},
        "completed_phases": ["phase1", "phase2"] if status != "PARTIAL"
                            else ["phase1"],
        "findings_count": 5,
        "errors_count": 0,
        "status": status,
        "mtime": 1700000000.0,
    }


class TestCampaignsFilterLogic:
    """``_filtered_campaigns`` is the engine behind the ``/``
    filter on the Campaigns screen. Test it directly — no
    Textual app needed."""

    def test_empty_filter_returns_all(self):
        screen = CampaignsScreen()
        screen._campaigns = [_campaign("a", "acme"), _campaign("b", "globex")]
        screen._filter_text = ""
        assert len(screen._filtered_campaigns()) == 2

    def test_substring_matches_campaign_id(self):
        screen = CampaignsScreen()
        screen._campaigns = [
            _campaign("alpha-2026-01", "acme"),
            _campaign("beta-2026-02", "globex"),
        ]
        screen._filter_text = "alpha"
        out = screen._filtered_campaigns()
        assert len(out) == 1
        assert out[0]["campaign_id"] == "alpha-2026-01"

    def test_substring_matches_client(self):
        """Operator filters on client name without remembering
        the engagement id."""
        screen = CampaignsScreen()
        screen._campaigns = [
            _campaign("c1", "ACME"),
            _campaign("c2", "Globex"),
            _campaign("c3", "acme"),
        ]
        screen._filter_text = "acme"
        out = screen._filtered_campaigns()
        assert len(out) == 2  # case-insensitive: ACME + acme

    def test_substring_matches_status(self):
        screen = CampaignsScreen()
        screen._campaigns = [
            _campaign("c1", "x", status="DONE"),
            _campaign("c2", "x", status="PARTIAL"),
            _campaign("c3", "x", status="ERROR"),
        ]
        screen._filter_text = "partial"
        out = screen._filtered_campaigns()
        assert len(out) == 1
        assert out[0]["campaign_id"] == "c2"

    def test_no_match_returns_empty(self):
        screen = CampaignsScreen()
        screen._campaigns = [_campaign("a", "acme")]
        screen._filter_text = "nonexistent"
        assert screen._filtered_campaigns() == []


class TestCampaignsFilterPilot:
    """End-to-end: pushing the screen mounts a hidden filter
    Input, ``/`` reveals it, the input rebuilds the table on
    keystrokes, Esc clears."""

    def test_filter_input_starts_hidden(self, tmp_path: Path):
        async def _drive():
            app = NexusReconApp()
            async with app.run_test(headless=True) as pilot:
                await pilot.pause(0.3)
                await app.push_screen(CampaignsScreen())
                await pilot.pause(0.3)
                from textual.widgets import Input
                inp = app.screen.query_one("#campaigns-filter", Input)
                assert "campaigns-filter-hidden" in inp.classes
                app.exit()

        asyncio.run(_drive())

    def test_action_focus_filter_reveals_input(self, tmp_path: Path):
        async def _drive():
            app = NexusReconApp()
            async with app.run_test(headless=True) as pilot:
                await pilot.pause(0.3)
                await app.push_screen(CampaignsScreen())
                await pilot.pause(0.3)
                screen = app.screen
                screen.action_focus_filter()
                await pilot.pause(0.1)
                from textual.widgets import Input
                inp = screen.query_one("#campaigns-filter", Input)
                assert "campaigns-filter-hidden" not in inp.classes
                app.exit()

        asyncio.run(_drive())

    def test_clear_filter_hides_input(self):
        async def _drive():
            app = NexusReconApp()
            async with app.run_test(headless=True) as pilot:
                await pilot.pause(0.3)
                await app.push_screen(CampaignsScreen())
                await pilot.pause(0.3)
                screen = app.screen
                screen.action_focus_filter()
                await pilot.pause(0.1)
                screen._filter_text = "anything"
                screen.action_clear_filter()
                from textual.widgets import Input
                inp = screen.query_one("#campaigns-filter", Input)
                assert "campaigns-filter-hidden" in inp.classes
                assert inp.value == ""
                assert screen._filter_text == ""
                app.exit()

        asyncio.run(_drive())

    def test_preview_strip_present(self):
        async def _drive():
            app = NexusReconApp()
            async with app.run_test(headless=True) as pilot:
                await pilot.pause(0.3)
                await app.push_screen(CampaignsScreen())
                await pilot.pause(0.3)
                from textual.widgets import Static
                preview = app.screen.query_one(
                    "#campaigns-preview", Static,
                )
                assert preview is not None
                app.exit()

        asyncio.run(_drive())


# ──────────────────────────────────────────────────────────────────────
# Reports filter
# ──────────────────────────────────────────────────────────────────────


def _entry(filename: str, label: str, exists: bool = True) -> ReportEntry:
    """Build a fake ReportEntry sidestepping the disk-walking
    that ``discover_reports`` would otherwise perform."""
    return ReportEntry(
        filename=filename,
        label=label,
        path=Path(f"/fake/{filename}"),
        exists=exists,
        renderable=filename.endswith(".md"),
        reviewed=False,
    )


class TestReportsFilterLogic:
    def test_empty_filter_returns_all(self):
        screen = ReportsBrowserScreen(campaign_dir="/fake")
        screen._entries = [
            _entry("master_report.md", "Master report"),
            _entry("asset_inventory.md", "Asset inventory"),
        ]
        screen._filter_text = ""
        assert len(screen._filtered_entries()) == 2

    def test_substring_matches_label(self):
        screen = ReportsBrowserScreen(campaign_dir="/fake")
        screen._entries = [
            _entry("master_report.md", "Master report"),
            _entry("asset_inventory.md", "Asset inventory"),
            _entry("phishing_package.md", "Phishing package"),
        ]
        screen._filter_text = "phishing"
        out = screen._filtered_entries()
        assert len(out) == 1
        assert out[0].filename == "phishing_package.md"

    def test_substring_matches_filename(self):
        """Power user filtering on the technical name rather than
        the human-readable label."""
        screen = ReportsBrowserScreen(campaign_dir="/fake")
        screen._entries = [
            _entry("master_report.md", "Narrative"),
            _entry("credential_exposure_paths.md", "Credentials"),
        ]
        screen._filter_text = "credential_exposure"
        out = screen._filtered_entries()
        assert len(out) == 1
        assert out[0].filename == "credential_exposure_paths.md"

    def test_case_insensitive(self):
        screen = ReportsBrowserScreen(campaign_dir="/fake")
        screen._entries = [
            _entry("master_report.md", "Master Report"),
        ]
        screen._filter_text = "MASTER"
        assert len(screen._filtered_entries()) == 1


# ──────────────────────────────────────────────────────────────────────
# Help modal vocabulary
# ──────────────────────────────────────────────────────────────────────


class TestHelpModalVocabulary:
    """The cross-screen vocabulary section in the Help modal
    must list the keys that have the same meaning everywhere.
    Pin the rows so a future edit that drops the section is
    loud."""

    def test_vocabulary_table_lists_canonical_keys(self):
        async def _drive():
            app = NexusReconApp()
            async with app.run_test(headless=True) as pilot:
                await pilot.pause(0.3)
                await app.push_screen(HelpModal())
                await pilot.pause(0.3)
                from textual.widgets import DataTable
                table = app.screen.query_one(
                    "#help-vocabulary-table", DataTable,
                )
                # Pull every (key, meaning) row out of the table
                # so we can assert specific keys are documented.
                keys_documented = set()
                for row in range(table.row_count):
                    key_cell = table.get_cell_at((row, 0))
                    keys_documented.add(str(key_cell))
                # The canonical keys we PROMISE are consistent
                # across screens. A future refactor that breaks
                # the promise should break this test before it
                # ships.
                for canonical in ("/", "Enter", "Esc", "Tab", "?"):
                    assert canonical in keys_documented, (
                        f"vocabulary table missing canonical key {canonical!r}"
                    )
                app.exit()

        asyncio.run(_drive())

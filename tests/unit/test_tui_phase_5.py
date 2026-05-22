"""Tests for TUI-5: in-TUI markdown report browser.

The catalog + flag-file persistence + rendering helpers are pure
Python; the screen is exercised via the headless pilot harness.
"""
from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

# ──────────────────────────────────────────────────────────────────────
# Catalog + discovery
# ──────────────────────────────────────────────────────────────────────


class TestDiscovery:
    def test_catalog_has_canonical_deliverables(self):
        """Spec lists 17 deliverables NexusRecon can emit; the
        catalog must enumerate every one so the browser doesn't
        silently drop new reports."""
        from nexusrecon.tui.screens.reports_browser import REPORT_CATALOG
        ids = {row[0] for row in REPORT_CATALOG}
        expected = {
            "master_report.md", "executive_summary.md",
            "top_threads.md", "attack_surface.md",
            "phishing_package.md", "vuln_correlation.md",
            "harvested_credentials.md", "credential_exposure_paths.md",
            "spear_phishing_intelligence.md", "pretext_candidates.json",
            "asset_inventory.md", "people_map.md",
            "vendor_supply_chain.md", "jira_tracker.md",
            "entity_graph.html", "findings.json",
            "campaign_meta.json",
        }
        assert expected.issubset(ids)

    def test_discover_returns_full_catalog(self, tmp_path: Path):
        from nexusrecon.tui.screens.reports_browser import (
            REPORT_CATALOG,
            discover_reports,
        )
        (tmp_path / "reports").mkdir()
        entries = discover_reports(tmp_path)
        # Browser always surfaces every catalog row, even absent ones.
        assert len(entries) == len(REPORT_CATALOG)

    def test_discover_marks_exists_correctly(self, tmp_path: Path):
        from nexusrecon.tui.screens.reports_browser import discover_reports
        (tmp_path / "reports").mkdir()
        (tmp_path / "reports" / "master_report.md").write_text("# m\n")
        entries = discover_reports(tmp_path)
        by_name = {e.filename: e for e in entries}
        assert by_name["master_report.md"].exists is True
        assert by_name["executive_summary.md"].exists is False

    def test_discover_accepts_reports_dir_directly(self, tmp_path: Path):
        """When the caller passes the ``reports/`` directory itself
        (not the campaign root), discovery should still work."""
        from nexusrecon.tui.screens.reports_browser import discover_reports
        reports = tmp_path / "reports"
        reports.mkdir()
        (reports / "master_report.md").write_text("# m\n")
        entries = discover_reports(reports)
        by_name = {e.filename: e for e in entries}
        assert by_name["master_report.md"].exists is True

    def test_renderable_only_markdown(self):
        """JSON / HTML deliverables flagged as not-renderable so the
        browser shows the "open external" prompt instead of trying
        to render them in MarkdownViewer."""
        from nexusrecon.tui.screens.reports_browser import discover_reports
        with tempfile.TemporaryDirectory() as td:
            campaign = Path(td)
            (campaign / "reports").mkdir()
            entries = discover_reports(campaign)
            for entry in entries:
                if entry.filename.endswith(".md"):
                    assert entry.renderable
                elif entry.filename.endswith((".json", ".html")):
                    assert not entry.renderable


# ──────────────────────────────────────────────────────────────────────
# Mark reviewed persistence
# ──────────────────────────────────────────────────────────────────────


class TestMarkReviewed:
    def test_toggle_creates_flag(self, tmp_path: Path):
        from nexusrecon.tui.screens.reports_browser import mark_reviewed
        report = tmp_path / "master_report.md"
        report.write_text("# m\n")
        assert mark_reviewed(report) is True
        flag = report.with_suffix(report.suffix + ".reviewed")
        assert flag.exists()

    def test_toggle_removes_flag_on_second_call(self, tmp_path: Path):
        from nexusrecon.tui.screens.reports_browser import mark_reviewed
        report = tmp_path / "master_report.md"
        report.write_text("# m\n")
        mark_reviewed(report)
        # Second toggle unmarks.
        assert mark_reviewed(report) is False
        flag = report.with_suffix(report.suffix + ".reviewed")
        assert not flag.exists()

    def test_toggle_noop_when_report_missing(self, tmp_path: Path):
        from nexusrecon.tui.screens.reports_browser import mark_reviewed
        # Path doesn't exist — should not raise + should not create
        # a flag file.
        assert mark_reviewed(tmp_path / "nonexistent.md") is False
        assert not (tmp_path / "nonexistent.md.reviewed").exists()

    def test_discover_reads_existing_reviewed_flag(self, tmp_path: Path):
        from nexusrecon.tui.screens.reports_browser import discover_reports
        reports = tmp_path / "reports"
        reports.mkdir()
        report = reports / "master_report.md"
        report.write_text("# m\n")
        flag = report.with_suffix(report.suffix + ".reviewed")
        flag.touch()
        entries = discover_reports(tmp_path)
        master = next(e for e in entries if e.filename == "master_report.md")
        assert master.reviewed is True


# ──────────────────────────────────────────────────────────────────────
# Row rendering
# ──────────────────────────────────────────────────────────────────────


class TestRenderRow:
    def test_absent_row_dim_and_not_generated(self, tmp_path: Path):
        from nexusrecon.tui.screens.reports_browser import (
            ReportEntry,
            render_row,
        )
        entry = ReportEntry(
            filename="x.md", label="X", path=tmp_path / "x.md",
            exists=False, reviewed=False, renderable=True,
        )
        out = render_row(entry)
        assert "○" in out
        assert "not generated" in out

    def test_reviewed_row_has_check_and_reviewed_label(self, tmp_path: Path):
        from nexusrecon.tui.screens.reports_browser import (
            ReportEntry,
            render_row,
        )
        entry = ReportEntry(
            filename="x.md", label="X", path=tmp_path / "x.md",
            exists=True, reviewed=True, renderable=True,
        )
        out = render_row(entry)
        assert "✓" in out
        assert "reviewed" in out

    def test_present_unreviewed_has_dot(self, tmp_path: Path):
        from nexusrecon.tui.screens.reports_browser import (
            ReportEntry,
            render_row,
        )
        entry = ReportEntry(
            filename="x.md", label="X", path=tmp_path / "x.md",
            exists=True, reviewed=False, renderable=True,
        )
        out = render_row(entry)
        assert "●" in out


# ──────────────────────────────────────────────────────────────────────
# visible_reports filter
# ──────────────────────────────────────────────────────────────────────


class TestVisibleReports:
    def test_filters_to_existing_only(self, tmp_path: Path):
        from nexusrecon.tui.screens.reports_browser import (
            discover_reports,
            visible_reports,
        )
        reports = tmp_path / "reports"
        reports.mkdir()
        (reports / "master_report.md").write_text("x")
        entries = discover_reports(tmp_path)
        visible = visible_reports(entries)
        # Only the one we created should show.
        assert len(visible) == 1
        assert visible[0].filename == "master_report.md"


# ──────────────────────────────────────────────────────────────────────
# Screen integration (pilot)
# ──────────────────────────────────────────────────────────────────────


class TestReportsBrowserPilot:
    def test_browser_mounts_and_lists_catalog(self):
        from nexusrecon.tui.app import NexusReconApp
        from nexusrecon.tui.screens.reports_browser import (
            REPORT_CATALOG,
            ReportsBrowserScreen,
        )

        async def _drive():
            with tempfile.TemporaryDirectory() as td:
                campaign = Path(td)
                (campaign / "reports").mkdir()
                (campaign / "reports" / "master_report.md").write_text(
                    "# Master\nHello.\n",
                )
                app = NexusReconApp()
                async with app.run_test(headless=True) as pilot:
                    await pilot.pause(0.5)
                    await app.push_screen(
                        ReportsBrowserScreen(str(campaign)),
                    )
                    await pilot.pause(0.5)
                    assert isinstance(app.screen, ReportsBrowserScreen)
                    list_view = app.screen.query_one("#reports-list")
                    assert len(list_view.children) == len(REPORT_CATALOG)
                    app.exit()
                    await pilot.pause(0.1)

        asyncio.run(_drive())

    def test_browser_m_binding_toggles_review(self):
        from nexusrecon.tui.app import NexusReconApp
        from nexusrecon.tui.screens.reports_browser import (
            ReportsBrowserScreen,
        )

        async def _drive():
            with tempfile.TemporaryDirectory() as td:
                campaign = Path(td)
                reports = campaign / "reports"
                reports.mkdir()
                report = reports / "master_report.md"
                report.write_text("# Master\n")
                flag = report.with_suffix(report.suffix + ".reviewed")
                assert not flag.exists()

                app = NexusReconApp()
                async with app.run_test(headless=True) as pilot:
                    await pilot.pause(0.5)
                    await app.push_screen(
                        ReportsBrowserScreen(str(campaign)),
                    )
                    await pilot.pause(0.5)
                    # Default selection should be the first generated report
                    # (master_report.md in this case). Press m.
                    await pilot.press("m")
                    await pilot.pause(0.2)
                    # Flag file should now exist on disk.
                    assert flag.exists()
                    app.exit()
                    await pilot.pause(0.1)

        asyncio.run(_drive())

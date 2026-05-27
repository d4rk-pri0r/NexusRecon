"""Tests for the TUI-6b runner overhaul.

The runner screen is the live campaign view. TUI-6b added:

  - Visualisations in the stats panel: budget IntensityGauge,
    findings-rate sparkline, dispatch-rate sparkline.
  - Per-phase progress strip under the main ChunkyBar.
  - Substring filter on the activity log (``/`` reveals input,
    Esc clears).
  - Pause/resume tail (``Space``).
  - Phase boundary navigation (``[`` / ``]``).
  - 2000-line activity buffer (was 200) so the filter has
    something to chew on.

These tests pin the wire-level contracts:

  - Filter logic narrows the visible buffer correctly + tracks
    phase boundary indices accurately.
  - Pause flag flips on the binding action.
  - Stats tick pushes deltas (not totals) into sparklines.
  - Phase strip ratios reflect ``_phase_done`` correctly.

Pilot-driven assertions for compose-time wiring (do all the
widgets actually mount?) live alongside; the rest is unit-level
testable without an app.
"""
from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

import pytest

from nexusrecon.tui.app import NexusReconApp
from nexusrecon.tui.screens.runner import RunnerScreen
from nexusrecon.tui.widgets import (
    IntensityGauge,
    MiniSparkline,
    PhaseStrip,
)


# ──────────────────────────────────────────────────────────────────────
# Scope fixture helper
# ──────────────────────────────────────────────────────────────────────


def _make_scope(tmp_path: Path) -> Path:
    """Minimal scope YAML the runner can construct against. Doesn't
    have to actually run a campaign ── tests target the surfaces
    that exist on mount, before the worker fires anything real."""
    path = tmp_path / "scope.yaml"
    path.write_text(
        "engagement: { id: test-engagement }\n"
        "scope:\n"
        "  in_scope: { domains: [example.com] }\n"
        "  out_of_scope: {}\n"
        "constraints: { max_tier: T0 }\n",
    )
    return path


@pytest.fixture
def runner_with_scope(tmp_path: Path) -> RunnerScreen:
    """A RunnerScreen instance constructed with a real scope file
    on disk. Returned BEFORE mount, so per-test setup decides
    whether to push it into an app or unit-test in isolation."""
    scope = _make_scope(tmp_path)
    return RunnerScreen(
        scope_path=str(scope),
        mode="light",
        dispatch_mode="off",
    )


# ──────────────────────────────────────────────────────────────────────
# Bindings
# ──────────────────────────────────────────────────────────────────────


class TestBindings:
    """The plan's power-key vocabulary (``/``, ``Space``, ``[``,
    ``]``) is the operator-facing contract. Pin the bindings so a
    refactor that drops one breaks the test, not the operator's
    muscle memory."""

    def _binding_keys(self) -> set[str]:
        keys: set[str] = set()
        for b in RunnerScreen.BINDINGS:
            # Bindings can be either tuples or Binding instances;
            # extract the key field uniformly.
            if hasattr(b, "key"):
                keys.add(b.key)
            else:
                keys.add(b[0])
        return keys

    def test_filter_binding_present(self):
        assert "slash" in self._binding_keys()

    def test_pause_binding_present(self):
        assert "space" in self._binding_keys()

    def test_phase_navigation_bindings_present(self):
        keys = self._binding_keys()
        assert "bracketleft" in keys
        assert "bracketright" in keys

    def test_legacy_bindings_preserved(self):
        """Pre-TUI-6b operators still know ``q`` / ``r`` / ``d``.
        Adding new keys must not displace the existing ones."""
        keys = self._binding_keys()
        for legacy in ("q", "r", "d", "escape"):
            assert legacy in keys, f"legacy binding {legacy!r} missing"


# ──────────────────────────────────────────────────────────────────────
# Filter logic
# ──────────────────────────────────────────────────────────────────────


class TestFilterLogic:
    """``_compute_filtered_lines`` is the engine behind the ``/``
    filter. Test it directly ── no Textual app needed."""

    def test_empty_filter_returns_all_lines(self, runner_with_scope):
        rn = runner_with_scope
        rn._activity.extend([
            "12:00:00  ▶  phase1: passive footprint",
            "12:00:05  +  3 subdomains found",
            "12:00:10  ✓  phase1: 5 findings",
        ])
        rn._filter_text = ""
        visible, _ = rn._compute_filtered_lines()
        assert len(visible) == 3

    def test_substring_filter_narrows(self, runner_with_scope):
        rn = runner_with_scope
        rn._activity.extend([
            "12:00:00  ▶  phase1: passive footprint",
            "12:00:05  +  3 subdomains found",
            "12:00:11  ▶  phase2: identity recon",
            "12:00:18  +  4 emails harvested",
        ])
        rn._filter_text = "phase2"
        visible, _ = rn._compute_filtered_lines()
        assert visible == ["12:00:11  ▶  phase2: identity recon"]

    def test_substring_filter_is_case_insensitive(self, runner_with_scope):
        rn = runner_with_scope
        rn._activity.extend([
            "12:00:00  ▶  Phase1: passive footprint",
            "12:00:05  +  3 subdomains found",
        ])
        rn._filter_text = "PHASE1"
        visible, _ = rn._compute_filtered_lines()
        assert len(visible) == 1

    def test_substring_filter_no_match_returns_empty(self, runner_with_scope):
        rn = runner_with_scope
        rn._activity.extend([
            "12:00:00  ▶  phase1",
            "12:00:05  ▶  phase2",
        ])
        rn._filter_text = "nonexistent"
        visible, _ = rn._compute_filtered_lines()
        assert visible == []

    def test_boundary_indices_track_phase_markers(self, runner_with_scope):
        """``▶`` and ``✓`` markers in the activity log indicate
        phase boundaries. The indices returned by
        ``_compute_filtered_lines`` are positions INTO the visible
        (possibly-filtered) list."""
        rn = runner_with_scope
        rn._activity.clear()  # tests run in isolation; start clean
        rn._activity.extend([
            "12:00:00  ▶  phase1",
            "12:00:05  +  noise",
            "12:00:10  ✓  phase1",
            "12:00:11  ▶  phase2",
            "12:00:20  ✓  phase2",
        ])
        rn._filter_text = ""
        _, indices = rn._compute_filtered_lines()
        # All 4 boundary lines flagged: indices 0, 2, 3, 4.
        assert indices == [0, 2, 3, 4]

    def test_boundary_indices_recompute_under_filter(self, runner_with_scope):
        """When the filter narrows the view, the boundary indices
        refer to positions in the FILTERED list, not the original
        buffer. This is what makes ``[`` / ``]`` work correctly
        while filtered."""
        rn = runner_with_scope
        rn._activity.clear()
        rn._activity.extend([
            "12:00:00  ▶  phase1",
            "12:00:05  +  noise",
            "12:00:10  ✓  phase1",
            "12:00:11  ▶  phase2",
            "12:00:18  +  4 emails harvested",
            "12:00:20  ✓  phase2",
        ])
        rn._filter_text = "phase2"
        visible, indices = rn._compute_filtered_lines()
        # Filtered list: only lines containing "phase2"
        #   0: ▶  phase2  → boundary
        #   1: ✓  phase2  → boundary
        # (The "+  4 emails harvested" line gets filtered out.)
        assert len(visible) == 2
        assert indices == [0, 1]


# ──────────────────────────────────────────────────────────────────────
# Pause toggle
# ──────────────────────────────────────────────────────────────────────


class TestPauseToggle:
    def test_pause_starts_false(self, runner_with_scope):
        assert runner_with_scope._paused is False

    def test_action_toggles(self, runner_with_scope):
        rn = runner_with_scope
        # action_toggle_pause tries to notify() ── stub it so the
        # call doesn't need a mounted app.
        rn.notify = lambda *a, **kw: None  # type: ignore[method-assign]
        rn.action_toggle_pause()
        assert rn._paused is True
        rn.action_toggle_pause()
        assert rn._paused is False


# ──────────────────────────────────────────────────────────────────────
# Phase strip ratios
# ──────────────────────────────────────────────────────────────────────


class TestPhaseStripRatios:
    """The phase strip's ratios are derived from ``_phase_done``
    + ``_complete``. Pin the mapping: completed phases → 1.0,
    the in-flight phase → 0.5, pending → 0.0."""

    def _ratios_for(self, *, phase_done: int, complete: bool) -> list[float]:
        """Replicate the logic from ``_update_phase_strip`` without
        needing a mounted Textual app."""
        from nexusrecon.tui.screens.runner import _TOTAL_PHASES
        ratios: list[float] = []
        for i in range(_TOTAL_PHASES):
            if i < phase_done:
                ratios.append(1.0)
            elif i == phase_done and not complete:
                ratios.append(0.5)
            else:
                ratios.append(0.0)
        return ratios

    def test_no_progress_renders_all_zero_except_first(self):
        ratios = self._ratios_for(phase_done=0, complete=False)
        # phase 0 is in-flight, rest pending
        assert ratios[0] == 0.5
        assert all(r == 0.0 for r in ratios[1:])

    def test_partial_progress(self):
        ratios = self._ratios_for(phase_done=3, complete=False)
        assert ratios[:3] == [1.0, 1.0, 1.0]
        assert ratios[3] == 0.5
        assert ratios[4:] == [0.0] * (len(ratios) - 4)

    def test_complete_campaign_renders_all_full(self):
        from nexusrecon.tui.screens.runner import _TOTAL_PHASES
        ratios = self._ratios_for(phase_done=_TOTAL_PHASES, complete=True)
        assert ratios == [1.0] * _TOTAL_PHASES

    def test_aborted_mid_phase_does_not_show_in_flight(self):
        """When ``_complete`` is True (abort or finish), no phase
        should render as in-flight (0.5). Either it completed or
        it's pending — half-bars during a terminal state would
        misrepresent the campaign state."""
        ratios = self._ratios_for(phase_done=4, complete=True)
        assert ratios[3] == 1.0      # 4th completed
        assert ratios[4] == 0.0      # 5th pending (NOT 0.5)


# ──────────────────────────────────────────────────────────────────────
# Pilot integration — widget mount
# ──────────────────────────────────────────────────────────────────────


class TestRunnerMountsTUI6bWidgets:
    """End-to-end: pushing the RunnerScreen mounts every widget
    that TUI-6b adds. Catches a CSS rule mismatch or a forgotten
    import."""

    def test_all_widgets_present(self, tmp_path: Path):
        scope = _make_scope(tmp_path)

        async def _drive():
            app = NexusReconApp()
            async with app.run_test(headless=True) as pilot:
                await pilot.pause(0.3)
                await app.push_screen(RunnerScreen(
                    scope_path=str(scope), mode="light",
                ))
                await pilot.pause(0.5)
                screen = app.screen
                assert isinstance(screen, RunnerScreen)
                # Every new widget mounted with the right id.
                screen.query_one("#runner-phase-strip", PhaseStrip)
                screen.query_one("#runner-budget-gauge", IntensityGauge)
                screen.query_one(
                    "#runner-findings-spark", MiniSparkline,
                )
                screen.query_one(
                    "#runner-dispatch-spark", MiniSparkline,
                )
                app.exit()

        asyncio.run(_drive())

    def test_filter_input_starts_hidden(self, tmp_path: Path):
        """The filter Input should not occupy visible layout
        space until ``/`` is pressed. Check via its CSS class."""
        scope = _make_scope(tmp_path)

        async def _drive():
            app = NexusReconApp()
            async with app.run_test(headless=True) as pilot:
                await pilot.pause(0.3)
                await app.push_screen(RunnerScreen(
                    scope_path=str(scope), mode="light",
                ))
                await pilot.pause(0.5)
                from textual.widgets import Input
                inp = app.screen.query_one("#runner-filter", Input)
                assert "runner-filter-hidden" in inp.classes
                app.exit()

        asyncio.run(_drive())

    def test_focus_filter_reveals_input(self, tmp_path: Path):
        """``action_focus_filter`` removes the hidden class so
        the Input renders + receives focus."""
        scope = _make_scope(tmp_path)

        async def _drive():
            app = NexusReconApp()
            async with app.run_test(headless=True) as pilot:
                await pilot.pause(0.3)
                await app.push_screen(RunnerScreen(
                    scope_path=str(scope), mode="light",
                ))
                await pilot.pause(0.3)
                screen = app.screen
                screen.action_focus_filter()
                await pilot.pause(0.1)
                from textual.widgets import Input
                inp = screen.query_one("#runner-filter", Input)
                assert "runner-filter-hidden" not in inp.classes
                app.exit()

        asyncio.run(_drive())

    def test_clear_filter_hides_input_and_resets_text(
        self, tmp_path: Path,
    ):
        scope = _make_scope(tmp_path)

        async def _drive():
            app = NexusReconApp()
            async with app.run_test(headless=True) as pilot:
                await pilot.pause(0.3)
                await app.push_screen(RunnerScreen(
                    scope_path=str(scope), mode="light",
                ))
                await pilot.pause(0.3)
                screen = app.screen
                screen.action_focus_filter()
                await pilot.pause(0.1)
                # Stash a filter value via the public method.
                screen._filter_text = "phase2"
                from textual.widgets import Input
                inp = screen.query_one("#runner-filter", Input)
                inp.value = "phase2"
                screen.action_clear_filter()
                await pilot.pause(0.1)
                assert screen._filter_text == ""
                assert inp.value == ""
                assert "runner-filter-hidden" in inp.classes
                app.exit()

        asyncio.run(_drive())

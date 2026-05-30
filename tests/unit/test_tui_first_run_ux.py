"""First-run UX polish: the launch screen must tell the operator how many
tools are active vs. skipped, and *why* a tool is skipped.

Roadmap reference: ``ROADMAP.md`` beta blocker "First-run UX polish" --
"TUI tells the operator on launch how many tools are active vs.
Skipped-for-missing-keys."

The dashboard already showed a tool-health line, but it computed
``skipped = total - active - stubbed`` and labelled all of it "missing
keys". That mislabels a tool skipped for a missing *binary* (maigret,
amass, theHarvester not on PATH) as a missing *key*, sending a
fresh-install operator hunting for an API key when the real fix is a
package install. These tests pin the honest, F-A3 ``availability_report``
backed breakdown: missing binaries are reported distinctly from missing
keys, zero buckets are omitted, and the helpers never raise.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest


def _fake_registry(counts: dict, buckets: dict | None = None) -> MagicMock:
    """A registry stand-in whose ``availability_report`` returns crafted
    bucket counts, so the breakdown formatting is tested independently of
    whatever happens to be installed on the test host."""
    reg = MagicMock()
    reg.availability_report.return_value = {
        "counts": counts,
        "buckets": buckets or {},
    }
    return reg


_BALANCED_COUNTS = {
    "active": 80, "missing_binary": 6, "missing_key": 10,
    "policy": 0, "over_tier": 0, "stubbed": 1,
}


class TestToolBreakdownHonesty:
    def test_breakdown_distinguishes_keys_from_binaries(self):
        from nexusrecon.tui.screens import dashboard
        with patch(
            "nexusrecon.tools.registry.get_registry",
            return_value=_fake_registry(_BALANCED_COUNTS),
        ):
            out = dashboard._tool_breakdown()
        assert "97 tools" in out          # sum of every bucket
        assert "80 active" in out
        assert "10 need keys" in out
        assert "6 need install" in out    # the binaries, named as installs
        assert "1 stub" in out
        # The old lump label must be gone: a missing binary is not a key.
        assert "skipped (missing keys)" not in out

    def test_breakdown_omits_zero_buckets(self):
        from nexusrecon.tui.screens import dashboard
        counts = {
            "active": 50, "missing_binary": 0, "missing_key": 0,
            "policy": 0, "over_tier": 0, "stubbed": 0,
        }
        with patch(
            "nexusrecon.tools.registry.get_registry",
            return_value=_fake_registry(counts),
        ):
            out = dashboard._tool_breakdown()
        assert out == "50 tools · 50 active"

    def test_breakdown_returns_empty_string_on_error(self):
        from nexusrecon.tui.screens import dashboard
        with patch(
            "nexusrecon.tools.registry.get_registry",
            side_effect=RuntimeError("registry exploded"),
        ):
            assert dashboard._tool_breakdown() == ""

    def test_breakdown_against_live_registry_is_a_string(self):
        """Contract guard against the live registry (no mocks): the launch
        screen must never raise while rendering tool health."""
        from nexusrecon.tui.screens import dashboard
        out = dashboard._tool_breakdown()
        assert isinstance(out, str)
        assert "active" in out


class TestMissingBinariesHint:
    def test_lists_missing_binaries(self):
        from nexusrecon.tui.screens import dashboard
        buckets = {"missing_binary": {
            "maigret": "binary 'maigret' not on PATH",
            "amass": "binary 'amass' not on PATH",
            "nuclei": "binary 'nuclei' not on PATH",
        }}
        with patch(
            "nexusrecon.tools.registry.get_registry",
            return_value=_fake_registry({}, buckets),
        ):
            out = dashboard._render_missing_binaries(limit=4)
        assert "Needs install" in out
        for name in ("amass", "maigret", "nuclei"):
            assert name in out

    def test_truncates_with_more_suffix(self):
        from nexusrecon.tui.screens import dashboard
        buckets = {"missing_binary": {f"tool{i}": "x" for i in range(7)}}
        with patch(
            "nexusrecon.tools.registry.get_registry",
            return_value=_fake_registry({}, buckets),
        ):
            out = dashboard._render_missing_binaries(limit=4)
        assert "(+3 more)" in out

    def test_empty_when_no_missing_binaries(self):
        from nexusrecon.tui.screens import dashboard
        with patch(
            "nexusrecon.tools.registry.get_registry",
            return_value=_fake_registry({}, {"missing_binary": {}}),
        ):
            assert dashboard._render_missing_binaries() == ""

    def test_empty_string_on_error(self):
        from nexusrecon.tui.screens import dashboard
        with patch(
            "nexusrecon.tools.registry.get_registry",
            side_effect=RuntimeError("boom"),
        ):
            assert dashboard._render_missing_binaries() == ""


class TestWelcomeShimStaysHonestToo:
    def test_welcome_breakdown_distinguishes_and_keeps_active(self):
        """The legacy welcome shim shares the same honesty fix and keeps
        the ``active`` token its TUI-1 test asserts on."""
        from nexusrecon.tui.screens import welcome
        with patch(
            "nexusrecon.tools.registry.get_registry",
            return_value=_fake_registry(_BALANCED_COUNTS),
        ):
            out = welcome._tool_availability_breakdown()
        assert "80 active" in out
        assert "10 missing keys" in out
        assert "6 missing binaries" in out
        assert "skipped (missing keys)" not in out

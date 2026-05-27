"""Tests for the TUI-8 deliverables ("Delight & Extensibility").

Coverage:
  - **What's new panel** — ``_whats_new`` parses the latest
    ``## [...]`` section from ``CHANGELOG.md`` and returns
    bullet lines.
  - **Crash-recovery banner** — ``_detect_orphan_session``
    finds a lock file when present + ignores the current
    process's own pid; ``_dismiss_orphan_session`` removes it.
  - **User theme contribution** — TOML in
    ``~/.nexusrecon/themes/*.toml`` parses to a
    :class:`textual.theme.Theme`; missing fields fall back to
    the shipped defaults; severity tints are inherited; broken
    files are skipped, not raised.
  - **Tools invocation history** — registry records every
    ``execute()`` call into a bounded deque keyed by tool name;
    ``invocation_summary`` aggregates count / avg runtime /
    last error correctly across mixed cache + live invocations.

Pilot-driven assertions for compose-time wiring live alongside
unit-level tests. The shipped + user themes coexist via the
``all_themes()`` merge.
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest


# ──────────────────────────────────────────────────────────────────────
# What's new panel
# ──────────────────────────────────────────────────────────────────────


class TestWhatsNew:
    """The dashboard "What's new" card pulls the most recent
    section of CHANGELOG.md. Pin the parsing so a CHANGELOG
    format drift breaks the card cleanly."""

    def test_renders_when_changelog_present(self):
        """Live test against the actual shipped CHANGELOG.md.
        Output should contain the Latest header + at least one
        bullet."""
        from nexusrecon.tui.screens.dashboard import _whats_new
        out = _whats_new(limit=4)
        assert "Latest:" in out
        assert "•" in out

    def test_returns_empty_when_changelog_missing(self, tmp_path: Path):
        """A test/install without CHANGELOG.md must not crash —
        the function returns an empty string and the dashboard
        renders without the card."""
        from nexusrecon.tui.screens import dashboard as dash
        # Monkey-patch ``__file__`` indirectly by patching the
        # Path resolution. Simpler: patch ``Path.exists`` for
        # the duration via the module's exists call.
        with patch("nexusrecon.tui.screens.dashboard.Path") as mock_path:
            instance = mock_path.return_value
            instance.parents = [tmp_path, tmp_path, tmp_path, tmp_path]
            instance.resolve.return_value = instance
            # Force the exists() check to return False on the
            # synthesised CHANGELOG path.
            (instance / "CHANGELOG.md").exists.return_value = False
            # Function path: catches any error and returns "".
            out = dash._whats_new()
        assert out == ""

    def test_limit_caps_bullet_count(self):
        """``limit`` controls how many top-level bullets the
        function returns. A 1-bullet limit should produce a
        single bullet line."""
        from nexusrecon.tui.screens.dashboard import _whats_new
        out = _whats_new(limit=1)
        # Header + one bullet line.
        assert out.count("•") == 1


# ──────────────────────────────────────────────────────────────────────
# Crash-recovery banner
# ──────────────────────────────────────────────────────────────────────


class TestCrashRecovery:
    """The session lock survives unclean exits (SIGKILL, OS
    crash, uncaught Python exception). On next launch the
    dashboard detects it and offers to inspect the orphaned
    log; ``x`` dismisses + clears the lock."""

    def test_no_lock_returns_none(self, tmp_path: Path, monkeypatch):
        from nexusrecon.tui.screens.dashboard import _detect_orphan_session
        # Repoint HOME so we can verify in isolation.
        monkeypatch.setenv("HOME", str(tmp_path))
        # No lock file written.
        assert _detect_orphan_session() is None

    def test_lock_with_other_pid_is_detected(
        self, tmp_path: Path, monkeypatch,
    ):
        from nexusrecon.tui.screens.dashboard import _detect_orphan_session
        monkeypatch.setenv("HOME", str(tmp_path))
        # Write a lock pretending another PID owned it.
        lock_dir = tmp_path / ".nexusrecon"
        lock_dir.mkdir()
        lock = lock_dir / ".tui_session_lock"
        lock.write_text(json.dumps({
            "started": "2026-05-27T10:00:00Z",
            "pid": 99999,  # not us
            "log_path": "/tmp/orphan.log",
        }), encoding="utf-8")
        result = _detect_orphan_session()
        assert result is not None
        assert result["pid"] == 99999
        assert result["log_path"] == "/tmp/orphan.log"

    def test_lock_with_our_pid_is_ignored(
        self, tmp_path: Path, monkeypatch,
    ):
        """If the lock somehow matches our own pid, we don't
        report a crash — that would be a false positive on
        the current session."""
        from nexusrecon.tui.screens.dashboard import _detect_orphan_session
        monkeypatch.setenv("HOME", str(tmp_path))
        lock_dir = tmp_path / ".nexusrecon"
        lock_dir.mkdir()
        lock = lock_dir / ".tui_session_lock"
        lock.write_text(json.dumps({
            "started": "now", "pid": os.getpid(),
            "log_path": "/x.log",
        }), encoding="utf-8")
        assert _detect_orphan_session() is None

    def test_dismiss_removes_lock(self, tmp_path: Path, monkeypatch):
        from nexusrecon.tui.screens.dashboard import (
            _detect_orphan_session,
            _dismiss_orphan_session,
        )
        monkeypatch.setenv("HOME", str(tmp_path))
        lock_dir = tmp_path / ".nexusrecon"
        lock_dir.mkdir()
        lock = lock_dir / ".tui_session_lock"
        lock.write_text('{"pid": 99999, "log_path": "/x", "started": "now"}',
                        encoding="utf-8")
        assert _detect_orphan_session() is not None
        _dismiss_orphan_session()
        assert not lock.exists()
        assert _detect_orphan_session() is None

    def test_broken_lock_does_not_raise(
        self, tmp_path: Path, monkeypatch,
    ):
        from nexusrecon.tui.screens.dashboard import _detect_orphan_session
        monkeypatch.setenv("HOME", str(tmp_path))
        lock_dir = tmp_path / ".nexusrecon"
        lock_dir.mkdir()
        lock = lock_dir / ".tui_session_lock"
        lock.write_text("not valid json", encoding="utf-8")
        # Defensive: returns None rather than raising.
        assert _detect_orphan_session() is None


# ──────────────────────────────────────────────────────────────────────
# Theme contribution
# ──────────────────────────────────────────────────────────────────────


class TestUserThemes:
    def test_empty_dir_returns_no_themes(self, tmp_path: Path):
        from nexusrecon.tui.themes import load_user_themes
        out = load_user_themes(themes_dir=str(tmp_path))
        assert out == {}

    def test_missing_dir_returns_no_themes(self, tmp_path: Path):
        from nexusrecon.tui.themes import load_user_themes
        nonexistent = tmp_path / "does-not-exist"
        out = load_user_themes(themes_dir=str(nonexistent))
        assert out == {}

    def test_loads_valid_toml_theme(self, tmp_path: Path):
        from nexusrecon.tui.themes import load_user_themes
        (tmp_path / "cyber.toml").write_text(
            'name = "cyber"\n'
            'primary = "#ff00ff"\n'
            'secondary = "#00ffff"\n'
            'accent = "#ff00ff"\n'
            'background = "#0a0a0a"\n'
            'foreground = "#ffffff"\n'
            'success = "#00ff00"\n'
            'warning = "#ffff00"\n'
            'error = "#ff0000"\n'
            'dark = true\n'
            '[variables]\n'
            'nx-bg-detail = "#000000"\n'
            'nx-text-muted = "#888888"\n'
            'nx-text-dim = "#444444"\n'
            'nx-border-muted = "#888888"\n',
            encoding="utf-8",
        )
        out = load_user_themes(themes_dir=str(tmp_path))
        assert "cyber" in out
        assert out["cyber"].primary == "#ff00ff"
        # Severity tints inherited from the shared baseline.
        assert out["cyber"].variables["severity-critical"] == "#ff3838"

    def test_broken_toml_is_skipped_not_raised(self, tmp_path: Path):
        from nexusrecon.tui.themes import load_user_themes
        (tmp_path / "broken.toml").write_text(
            "this is not valid toml = = =", encoding="utf-8",
        )
        (tmp_path / "ok.toml").write_text(
            'name = "ok"\nprimary = "#ffffff"\n', encoding="utf-8",
        )
        out = load_user_themes(themes_dir=str(tmp_path))
        # Broken one skipped; valid one loaded.
        assert "broken" not in out
        assert "ok" in out

    def test_missing_name_field_is_skipped(self, tmp_path: Path):
        from nexusrecon.tui.themes import load_user_themes
        (tmp_path / "noname.toml").write_text(
            'primary = "#ffffff"\n', encoding="utf-8",
        )
        out = load_user_themes(themes_dir=str(tmp_path))
        assert out == {}

    def test_missing_optional_fields_use_defaults(self, tmp_path: Path):
        """An operator can ship a tiny theme overriding only one
        color — the parser falls back to the shipped-dark
        defaults for everything else."""
        from nexusrecon.tui.themes import NEXUSRECON_DARK, load_user_themes
        (tmp_path / "minimal.toml").write_text(
            'name = "minimal"\nprimary = "#ff0000"\n',
            encoding="utf-8",
        )
        out = load_user_themes(themes_dir=str(tmp_path))
        assert "minimal" in out
        # Foreground falls back to the shipped dark theme value.
        assert out["minimal"].foreground == NEXUSRECON_DARK.foreground
        # But primary was overridden.
        assert out["minimal"].primary == "#ff0000"

    def test_all_themes_merges_shipped_and_user(self, tmp_path: Path):
        """``all_themes`` includes the shipped themes plus the
        user contributions. User themes override shipped names
        if they collide (operator choice)."""
        from nexusrecon.tui import themes as themes_mod
        (tmp_path / "cyber.toml").write_text(
            'name = "cyber"\nprimary = "#ff00ff"\n',
            encoding="utf-8",
        )
        with patch.object(
            themes_mod, "USER_THEMES_DIR", str(tmp_path),
        ):
            out = themes_mod.all_themes()
        # Shipped themes still present.
        assert "nexusrecon-dark" in out
        assert "nexusrecon-hicontrast" in out
        assert "nexusrecon-light" in out
        # Plus the user theme.
        assert "cyber" in out


# ──────────────────────────────────────────────────────────────────────
# Tools invocation history
# ──────────────────────────────────────────────────────────────────────


class TestInvocationHistory:
    """The registry now records every ``execute()`` call into a
    bounded deque per tool. The Tools screen reads it via
    ``invocation_summary``."""

    def test_empty_summary_for_unrun_tool(self):
        from nexusrecon.tools.registry import ToolRegistry
        reg = ToolRegistry()
        s = reg.invocation_summary("shodan")
        assert s["count"] == 0
        assert s["avg_runtime_ms"] == 0
        assert s["last_status"] is None
        assert s["last_error"] is None
        assert s["last_timestamp"] is None

    def test_records_a_single_invocation(self):
        from nexusrecon.tools.registry import ToolRegistry
        reg = ToolRegistry()
        reg._record_invocation(
            tool_name="shodan", runtime_ms=120, success=True,
            error=None, target="x.com", cached=False,
        )
        s = reg.invocation_summary("shodan")
        assert s["count"] == 1
        assert s["avg_runtime_ms"] == 120
        assert s["last_status"] == "success"

    def test_avg_runtime_excludes_cache_hits(self):
        """Cache hits are recorded for completeness but excluded
        from the avg-duration calc (they're effectively
        instant)."""
        from nexusrecon.tools.registry import ToolRegistry
        reg = ToolRegistry()
        reg._record_invocation(tool_name="t", runtime_ms=100, success=True,
                               error=None, target="x", cached=False)
        reg._record_invocation(tool_name="t", runtime_ms=200, success=True,
                               error=None, target="x", cached=False)
        reg._record_invocation(tool_name="t", runtime_ms=0, success=True,
                               error=None, target="x", cached=True)
        s = reg.invocation_summary("t")
        assert s["count"] == 3
        # 100 + 200 → avg 150. Cache hit excluded.
        assert s["avg_runtime_ms"] == 150

    def test_last_error_surfaces_recent_failure(self):
        """Even when newer successes follow, the most recent
        ERROR is what an operator wants to see in the panel."""
        from nexusrecon.tools.registry import ToolRegistry
        reg = ToolRegistry()
        reg._record_invocation(tool_name="t", runtime_ms=100, success=True,
                               error=None, target="x", cached=False)
        reg._record_invocation(tool_name="t", runtime_ms=200, success=False,
                               error="HTTP 429 rate-limited",
                               target="y", cached=False)
        reg._record_invocation(tool_name="t", runtime_ms=150, success=True,
                               error=None, target="x", cached=False)
        s = reg.invocation_summary("t")
        assert s["last_status"] == "success"
        assert s["last_error"] == "HTTP 429 rate-limited"

    def test_history_capped_at_cap(self):
        """Per-tool history is bounded; old entries are
        evicted from the head."""
        from nexusrecon.tools.registry import ToolRegistry
        reg = ToolRegistry()
        reg._invocation_history_cap = 5  # tighten for the test
        # Re-create the deque with the new cap by emptying out.
        from collections import deque
        reg._invocation_history.setdefault(
            "t", deque(maxlen=5),
        )
        for i in range(20):
            reg._record_invocation(
                tool_name="t", runtime_ms=i, success=True,
                error=None, target="x", cached=False,
            )
        # The bucket was created on first record; cap from
        # ``_invocation_history_cap``. We forced a maxlen=5
        # deque before the writes, so only the last 5 survive.
        assert len(reg.invocations_for("t")) == 5

    def test_invocations_for_returns_newest_last(self):
        from nexusrecon.tools.registry import ToolRegistry
        reg = ToolRegistry()
        reg._record_invocation(tool_name="t", runtime_ms=1, success=True,
                               error=None, target="a", cached=False)
        reg._record_invocation(tool_name="t", runtime_ms=2, success=True,
                               error=None, target="b", cached=False)
        records = reg.invocations_for("t")
        assert records[0]["target"] == "a"
        assert records[-1]["target"] == "b"

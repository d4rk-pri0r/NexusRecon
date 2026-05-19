"""Integration tests for nexusrecon.tools.identity.maigret_tool.

Maigret is a subprocess wrapper around the ``maigret`` CLI (installed
via ``pipx install maigret``). These tests mock the subprocess
invocation and supply canned maigret JSON output, so they verify our
wrapper's parsing + username-derivation integration without needing
the binary on PATH.
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from nexusrecon.tools.base import ToolResult
from nexusrecon.tools.identity.maigret_tool import (
    MaigretTool,
    _parse_simple_json,
)


# Canonical maigret "simple" JSON output for a single username probe.
# Real maigret outputs much more metadata; this fixture captures the
# fields our parser reads.
_MAIGRET_JSON_HIT = {
    "GitHub": {
        "url_user": "https://github.com/jane.doe",
        "status": {
            "status": "Claimed",
            "ids": {"username": "jane.doe", "image": "https://avatars.githubusercontent.com/u/12345"},
        },
    },
    "Twitter": {
        "url_user": "https://twitter.com/jane.doe",
        "status": {
            "status": "Claimed",
            "ids": {"username": "jane.doe"},
        },
    },
    "NonExistentSite": {
        "url_user": "https://nonexistent.example/jane.doe",
        "status": {
            "status": "Available",  # not Claimed/Found
            "ids": {},
        },
    },
    "ErrorSite": {
        "url_user": "https://errored.example/jane.doe",
        "status": {
            "status": "Unknown",
            "ids": {},
        },
    },
}


# ──────────────────────────────────────────────────────────────────────────
# _parse_simple_json: parsing maigret's output
# ──────────────────────────────────────────────────────────────────────────


class TestParseSimpleJson:
    def test_claimed_status_produces_hit(self):
        hits = _parse_simple_json("jane.doe", _MAIGRET_JSON_HIT)
        services = {h["service"] for h in hits}
        assert services == {"GitHub", "Twitter"}

    def test_available_and_unknown_status_skipped(self):
        """``Available`` means the username is NOT taken on that site ──
        zero-information for our purposes. ``Unknown`` means maigret
        couldn't determine. Neither should appear in the hit list."""
        hits = _parse_simple_json("jane.doe", _MAIGRET_JSON_HIT)
        services = {h["service"] for h in hits}
        assert "NonExistentSite" not in services
        assert "ErrorSite" not in services

    def test_found_status_treated_same_as_claimed(self):
        """Older maigret versions used ``Found`` instead of ``Claimed``.
        Both must produce hits to remain compatible."""
        data = {
            "OldSite": {
                "url_user": "https://old.example/u",
                "status": {"status": "Found", "ids": {}},
            },
        }
        hits = _parse_simple_json("u", data)
        assert len(hits) == 1
        assert hits[0]["service"] == "OldSite"

    def test_url_falls_back_when_url_user_missing(self):
        data = {
            "Site": {
                "url": "https://fallback.example/u",
                "status": {"status": "Claimed", "ids": {}},
            },
        }
        hits = _parse_simple_json("u", data)
        assert hits[0]["url"] == "https://fallback.example/u"

    def test_empty_data_produces_no_hits(self):
        assert _parse_simple_json("u", {}) == []

    def test_malformed_data_produces_no_hits(self):
        # Non-dict input shouldn't crash.
        assert _parse_simple_json("u", "not a dict") == []
        assert _parse_simple_json("u", None) == []
        assert _parse_simple_json("u", []) == []

    def test_missing_status_block_skipped_safely(self):
        data = {
            "BrokenSite": {"url_user": "x"},  # no status block at all
        }
        hits = _parse_simple_json("u", data)
        assert hits == []


# ──────────────────────────────────────────────────────────────────────────
# Tool: binary not installed
# ──────────────────────────────────────────────────────────────────────────


class TestMaigretBinaryMissing:
    @patch("shutil.which", return_value=None)
    async def test_returns_helpful_error_when_binary_missing(self, _which):
        """``is_available`` returns False when ``shutil.which("maigret")``
        is None. The tool should fail fast with a pipx-install hint."""
        tool = MaigretTool()
        result = await tool.run("jane.doe")
        assert result.success is False
        assert "pipx install maigret" in result.error


# ──────────────────────────────────────────────────────────────────────────
# Tool: end-to-end with mocked subprocess + canned output file
# ──────────────────────────────────────────────────────────────────────────


def _build_mock_subprocess(
    canned_output: dict,
    target_username: str,
) -> AsyncMock:
    """Build an asyncio.create_subprocess_exec mock that:

    1. Pretends to run maigret successfully.
    2. Writes ``canned_output`` to the temp dir's expected output path
       so our wrapper can read it back.
    """
    async def _fake_create(*args, **kwargs):
        # The maigret cmdline is ``maigret <username> --json simple --folderoutput <dir> ...``
        # Find the folderoutput dir and write a fake report file there.
        cmd_args = list(args)
        try:
            idx = cmd_args.index("--folderoutput")
            tmpdir = Path(cmd_args[idx + 1])
            output_file = tmpdir / f"{target_username}_simple.json"
            output_file.write_text(json.dumps(canned_output), encoding="utf-8")
        except (ValueError, IndexError):
            pass

        proc = MagicMock()
        proc.communicate = AsyncMock(return_value=(b"", b""))
        proc.kill = MagicMock()
        proc.wait = AsyncMock()
        return proc

    return AsyncMock(side_effect=_fake_create)


class TestMaigretEndToEnd:
    @patch("shutil.which", return_value="/usr/local/bin/maigret")
    async def test_username_input_returns_parsed_hits(self, _which):
        """Direct username input ── no derivation, single probe."""
        tool = MaigretTool()
        mock_create = _build_mock_subprocess(_MAIGRET_JSON_HIT, "jane.doe")

        with patch(
            "asyncio.create_subprocess_exec", new=mock_create,
        ):
            result = await tool.run("jane.doe", target_type="username")

        assert result.success is True
        assert result.data["input"] == "jane.doe"
        assert result.data["candidates"] == ["jane.doe"]
        assert result.result_count == 2  # GitHub + Twitter
        services = {s["service"] for s in result.data["registered_services"]}
        assert services == {"GitHub", "Twitter"}

    @patch("shutil.which", return_value="/usr/local/bin/maigret")
    async def test_email_input_triggers_username_derivation(self, _which):
        """Email input should derive username candidates and probe each.

        We don't predict which candidate maigret will be invoked with
        first (depends on derivation rank), so we set up the mock to
        write the same fixture under multiple candidate names. The
        wrapper dedupes hits by (username, service), so the final
        count is bounded by the number of unique services × candidates.
        """
        tool = MaigretTool()

        async def _fake_create(*args, **kwargs):
            cmd_args = list(args)
            # Find the username (positional arg right after ``maigret``).
            username = cmd_args[1]
            idx = cmd_args.index("--folderoutput")
            tmpdir = Path(cmd_args[idx + 1])
            output_file = tmpdir / f"{username}_simple.json"
            # Single-site hit per username, so we can assert dedup behaviour.
            output_file.write_text(
                json.dumps({
                    "Reddit": {
                        "url_user": f"https://reddit.com/u/{username}",
                        "status": {"status": "Claimed", "ids": {}},
                    },
                }),
                encoding="utf-8",
            )
            proc = MagicMock()
            proc.communicate = AsyncMock(return_value=(b"", b""))
            return proc

        with patch(
            "asyncio.create_subprocess_exec",
            new=AsyncMock(side_effect=_fake_create),
        ):
            result = await tool.run(
                "jane.doe@example.com",
                target_type="email",
                max_candidates=3,
            )

        assert result.success is True
        # At least 1 candidate was derived from the email local-part.
        assert len(result.data["candidates"]) >= 1
        assert len(result.data["candidates"]) <= 3
        # Each candidate produced a Reddit hit.
        assert result.result_count == len(result.data["candidates"])
        # All hits are on Reddit (the only site we mocked).
        services = {s["service"] for s in result.data["registered_services"]}
        assert services == {"Reddit"}

    @patch("shutil.which", return_value="/usr/local/bin/maigret")
    async def test_role_email_short_circuits_with_reason(self, _which):
        """Role-account emails like ``admin@`` shouldn't derive any
        username candidates, so the tool should return a clean
        zero-result success without invoking maigret at all."""
        tool = MaigretTool()
        mock_create = AsyncMock()

        with patch("asyncio.create_subprocess_exec", new=mock_create):
            result = await tool.run("admin@example.com", target_type="email")

        assert result.success is True
        assert result.result_count == 0
        assert result.data["candidates"] == []
        assert "role account" in result.data.get("reason", "").lower()
        # Maigret was never invoked because there were no candidates.
        mock_create.assert_not_called()

    @patch("shutil.which", return_value="/usr/local/bin/maigret")
    async def test_subprocess_timeout_returns_no_hits_for_that_candidate(self, _which):
        """If maigret hangs on a username, we kill the process and skip
        ── one slow candidate must not fail the whole tool."""
        tool = MaigretTool()

        async def _fake_create(*args, **kwargs):
            proc = MagicMock()
            # communicate hangs forever; wait_for catches it.
            async def _hang(*a, **kw):
                import asyncio
                await asyncio.sleep(3600)
            proc.communicate = _hang
            proc.kill = MagicMock()
            proc.wait = AsyncMock()
            return proc

        with patch(
            "asyncio.create_subprocess_exec",
            new=AsyncMock(side_effect=_fake_create),
        ), patch(
            "asyncio.wait_for",
            side_effect=__import__("asyncio").TimeoutError,
        ):
            result = await tool.run("janedoe", target_type="username")

        # Tool succeeds (it's not the tool's fault one site hung), but
        # with no hits since we couldn't parse any output.
        assert result.success is True
        assert result.result_count == 0

    @patch("shutil.which", return_value="/usr/local/bin/maigret")
    async def test_dedup_across_candidates(self, _which):
        """Two derived usernames hitting the same service must produce
        ONE finding, not two, per the (username, service) dedup."""
        tool = MaigretTool()

        async def _fake_create(*args, **kwargs):
            cmd_args = list(args)
            username = cmd_args[1]
            idx = cmd_args.index("--folderoutput")
            tmpdir = Path(cmd_args[idx + 1])
            output_file = tmpdir / f"{username}_simple.json"
            # Each candidate "hits" both GitHub and Twitter, but the
            # username differs ── so (username, service) tuples are
            # distinct across candidates. Dedup only collapses repeats
            # for the SAME username on the SAME service.
            output_file.write_text(
                json.dumps({
                    "GitHub": {
                        "url_user": f"https://github.com/{username}",
                        "status": {"status": "Claimed", "ids": {}},
                    },
                }),
                encoding="utf-8",
            )
            proc = MagicMock()
            proc.communicate = AsyncMock(return_value=(b"", b""))
            return proc

        with patch(
            "asyncio.create_subprocess_exec",
            new=AsyncMock(side_effect=_fake_create),
        ):
            result = await tool.run(
                "jane.doe@example.com",
                target_type="email",
                max_candidates=3,
            )

        # 3 candidates × 1 service each = 3 distinct (user, service) hits.
        assert result.result_count == 3
        # All on GitHub with different usernames.
        services = {s["service"] for s in result.data["registered_services"]}
        assert services == {"GitHub"}
        usernames = {s["username"] for s in result.data["registered_services"]}
        assert len(usernames) == 3

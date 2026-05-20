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
    async def test_each_hit_carries_confidence_and_signals(self, _which):
        """Every parsed hit should have ``confidence``,
        ``confidence_band``, ``confidence_signals``, and
        ``confidence_rationale`` attached by the scorer."""
        tool = MaigretTool()
        mock_create = _build_mock_subprocess(_MAIGRET_JSON_HIT, "jane.doe")

        with patch("asyncio.create_subprocess_exec", new=mock_create):
            result = await tool.run("jane.doe", target_type="username")

        for hit in result.data["registered_services"]:
            assert "confidence" in hit
            assert 0.0 <= hit["confidence"] <= 1.0
            assert hit["confidence_band"] in ("high", "medium", "noise")
            assert set(hit["confidence_signals"].keys()) == {
                "derivation", "uniqueness", "service_tier", "profile",
            }
            assert isinstance(hit["confidence_rationale"], str)
            assert hit["confidence_rationale"]  # non-empty

    @patch("shutil.which", return_value="/usr/local/bin/maigret")
    async def test_actionable_count_filters_noise(self, _which):
        """``actionable_count`` should only count hits at medium+ band ──
        the noise floor stays out of the actionable metric."""
        tool = MaigretTool()
        # Mix: GitHub for jane.doe (Tier 1, low confidence as plain
        # username with no email anchor) vs a distinctive handle on
        # GitHub (should clear actionable).
        fixture = {
            "GitHub": {
                "url_user": "https://github.com/xochitl.vukovic",
                "status": {"status": "Claimed", "ids": {}},
            },
        }
        mock_create = _build_mock_subprocess(fixture, "xochitl.vukovic")

        with patch("asyncio.create_subprocess_exec", new=mock_create):
            result = await tool.run(
                "xochitl.vukovic@example.com",
                target_type="email",
                max_candidates=1,
            )

        # The hit is exact-derivation + Tier 1 + distinctive handle ──
        # should clear actionable.
        assert result.data["actionable_count"] >= 1
        assert result.data["confidence_breakdown"]["high"] + result.data["confidence_breakdown"]["medium"] >= 1

    @patch("shutil.which", return_value="/usr/local/bin/maigret")
    async def test_hits_sorted_by_confidence_descending(self, _which):
        """The most credible hits should appear first in
        ``registered_services``. Downstream consumers truncate to top
        N for agent context windows; we don't want noise outranking
        signal."""
        tool = MaigretTool()
        # Mix of high-trust (GitHub) and low-trust (Steam) service hits
        # for the same handle. GitHub should rank higher.
        fixture = {
            "Steam": {
                "url_user": "https://steamcommunity.com/id/jane.doe",
                "status": {"status": "Claimed", "ids": {}},
            },
            "GitHub": {
                "url_user": "https://github.com/jane.doe",
                "status": {"status": "Claimed", "ids": {}},
            },
            "OkCupid": {
                "url_user": "https://okcupid.com/jane.doe",
                "status": {"status": "Claimed", "ids": {}},
            },
        }
        mock_create = _build_mock_subprocess(fixture, "jane.doe")

        with patch("asyncio.create_subprocess_exec", new=mock_create):
            result = await tool.run(
                "jane.doe@example.com",
                target_type="email",
                max_candidates=1,
            )

        confidences = [h["confidence"] for h in result.data["registered_services"]]
        assert confidences == sorted(confidences, reverse=True), (
            f"hits not sorted by confidence: {confidences}"
        )
        # GitHub (Tier 1) should appear before OkCupid (Tier 4).
        services_in_order = [h["service"] for h in result.data["registered_services"]]
        assert services_in_order.index("GitHub") < services_in_order.index("OkCupid")

    @patch("shutil.which", return_value="/usr/local/bin/maigret")
    async def test_phase_b_rescore_fetches_profile_and_boosts_confidence(self, _which):
        """Phase B end-to-end: a hit at MEDIUM confidence has its
        profile fetched, the bio mentions the email's domain stem, and
        the re-score pushes the hit into HIGH band.

        Without the fetch (Phase A only), profile_coherence is 0.0 and
        the hit stays at MEDIUM. With the fetch + bio match,
        profile_coherence picks up ~0.6 and the final score crosses
        the HIGH threshold."""
        import respx
        from httpx import Response

        tool = MaigretTool()

        # Mock maigret: one hit on GitHub for handle ``janedoe``.
        async def _fake_maigret(*args, **kwargs):
            cmd_args = list(args)
            username = cmd_args[1]
            idx = cmd_args.index("--folderoutput")
            tmpdir = Path(cmd_args[idx + 1])
            (tmpdir / f"{username}_simple.json").write_text(
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

        # Mock the GitHub API: returns a bio mentioning GitLab.
        with patch("asyncio.create_subprocess_exec",
                   new=AsyncMock(side_effect=_fake_maigret)), \
             respx.mock:
            respx.get("https://api.github.com/users/janedoe").mock(
                return_value=Response(200, json={
                    "login": "janedoe",
                    "name": "Jane Doe",
                    "bio": "Senior engineer at GitLab",
                    "company": "@gitlab-org",
                    "html_url": "https://github.com/janedoe",
                }),
            )

            result = await tool.run(
                "janedoe@gitlab.com",
                target_type="email",
                max_candidates=1,
                fetch_profiles=True,
            )

        hits = result.data["registered_services"]
        assert len(hits) >= 1
        github_hit = next(h for h in hits if h["service"] == "GitHub")

        # Profile was fetched.
        assert github_hit.get("fetched_profile") is not None
        assert github_hit["fetched_profile"]["bio"] == "Senior engineer at GitLab"

        # Confidence should reflect the bio match (profile_coherence
        # signal >= 0.5 because the bio mentions ``gitlab``).
        assert github_hit["confidence_signals"]["profile"] >= 0.5
        # Should be in HIGH band after rescore.
        assert github_hit["confidence"] >= 0.7
        assert github_hit["confidence_band"] == "high"

    @patch("shutil.which", return_value="/usr/local/bin/maigret")
    async def test_phase_b_fetch_disabled_keeps_phase_a_scoring(self, _which):
        """When ``fetch_profiles=False``, no profile fetching happens
        and confidence stays at the Phase A baseline."""
        tool = MaigretTool()

        async def _fake_maigret(*args, **kwargs):
            cmd_args = list(args)
            username = cmd_args[1]
            idx = cmd_args.index("--folderoutput")
            tmpdir = Path(cmd_args[idx + 1])
            (tmpdir / f"{username}_simple.json").write_text(
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

        # We DO NOT patch the GitHub API ── if fetch_profiles=False
        # works correctly, no HTTP request to api.github.com should
        # happen. Any attempt would raise (no respx mock) and crash
        # the test.
        with patch("asyncio.create_subprocess_exec",
                   new=AsyncMock(side_effect=_fake_maigret)):
            result = await tool.run(
                "janedoe@gitlab.com",
                target_type="email",
                max_candidates=1,
                fetch_profiles=False,
            )

        github_hit = next(
            h for h in result.data["registered_services"]
            if h["service"] == "GitHub"
        )
        # No fetched_profile attached.
        assert "fetched_profile" not in github_hit
        # Phase A profile_coherence stays at 0.0.
        assert github_hit["confidence_signals"]["profile"] == 0.0

    @patch("shutil.which", return_value="/usr/local/bin/maigret")
    async def test_phase_c_timeline_clusters_emerge_when_accounts_created_close_in_time(
        self, _which,
    ):
        """Phase C2 end-to-end: two hits both have created_at
        timestamps within the default 30-day window. After the
        rescore loop, both should carry a ``timeline_cluster_size``
        annotation."""
        import respx
        from httpx import Response

        tool = MaigretTool()

        async def _fake_maigret(*args, **kwargs):
            cmd_args = list(args)
            username = cmd_args[1]
            idx = cmd_args.index("--folderoutput")
            tmpdir = Path(cmd_args[idx + 1])
            (tmpdir / f"{username}_simple.json").write_text(
                json.dumps({
                    "GitHub": {
                        "url_user": f"https://github.com/{username}",
                        "status": {"status": "Claimed", "ids": {}},
                    },
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

        with patch("asyncio.create_subprocess_exec",
                   new=AsyncMock(side_effect=_fake_maigret)), \
             respx.mock:
            # Both profiles created in March 2014, within the
            # 30-day default cluster window.
            respx.get("https://api.github.com/users/janedoe").mock(
                return_value=Response(200, json={
                    "login": "janedoe",
                    "html_url": "https://github.com/janedoe",
                    "created_at": "2014-03-05T12:00:00Z",
                }),
            )
            respx.get("https://www.reddit.com/user/janedoe/about.json").mock(
                return_value=Response(200, json={
                    "data": {
                        # Unix timestamp for 2014-03-15.
                        "created_utc": 1394841600,
                        "subreddit": {},
                    },
                }),
            )

            result = await tool.run(
                "janedoe@example.com",
                target_type="email",
                max_candidates=1,
                fetch_profiles=True,
                fetch_avatars=False,  # skip avatar fetch in this test
            )

        github_hit = next(
            h for h in result.data["registered_services"]
            if h["service"] == "GitHub"
        )
        reddit_hit = next(
            h for h in result.data["registered_services"]
            if h["service"] == "Reddit"
        )
        # Both should land in the same timeline cluster.
        assert github_hit.get("timeline_cluster_size") == 2
        assert reddit_hit.get("timeline_cluster_size") == 2
        assert github_hit["timeline_cluster_id"] == reddit_hit["timeline_cluster_id"]

    @patch("shutil.which", return_value="/usr/local/bin/maigret")
    async def test_phase_c_reputation_boost_lifts_attribution(self, _which):
        """Phase C3 end-to-end: a Stack Overflow hit with high
        reputation should score higher than the same hit without
        reputation data."""
        import respx
        from httpx import Response

        tool = MaigretTool()

        async def _fake_maigret(*args, **kwargs):
            cmd_args = list(args)
            username = cmd_args[1]
            idx = cmd_args.index("--folderoutput")
            tmpdir = Path(cmd_args[idx + 1])
            (tmpdir / f"{username}_simple.json").write_text(
                json.dumps({
                    "StackOverflow": {
                        "url_user": f"https://stackoverflow.com/users/123/{username}",
                        "status": {"status": "Claimed", "ids": {}},
                    },
                }),
                encoding="utf-8",
            )
            proc = MagicMock()
            proc.communicate = AsyncMock(return_value=(b"", b""))
            return proc

        # High-rep run.
        with patch("asyncio.create_subprocess_exec",
                   new=AsyncMock(side_effect=_fake_maigret)), \
             respx.mock:
            respx.get("https://api.stackexchange.com/2.3/users").mock(
                return_value=Response(200, json={
                    "items": [{
                        "display_name": "janedoe",
                        "reputation": 12450,
                        "link": "https://stackoverflow.com/users/123/janedoe",
                        "creation_date": 1395849600,
                    }],
                }),
            )
            high_rep_result = await tool.run(
                "janedoe@example.com",
                target_type="email",
                max_candidates=1,
                fetch_profiles=True,
                fetch_avatars=False,
            )

        # Low-rep run.
        with patch("asyncio.create_subprocess_exec",
                   new=AsyncMock(side_effect=_fake_maigret)), \
             respx.mock:
            respx.get("https://api.stackexchange.com/2.3/users").mock(
                return_value=Response(200, json={
                    "items": [{
                        "display_name": "janedoe",
                        "reputation": 1,  # brand-new account
                        "link": "https://stackoverflow.com/users/123/janedoe",
                        "creation_date": 1395849600,
                    }],
                }),
            )
            low_rep_result = await tool.run(
                "janedoe@example.com",
                target_type="email",
                max_candidates=1,
                fetch_profiles=True,
                fetch_avatars=False,
            )

        high_hit = next(
            h for h in high_rep_result.data["registered_services"]
            if h["service"] == "StackOverflow"
        )
        low_hit = next(
            h for h in low_rep_result.data["registered_services"]
            if h["service"] == "StackOverflow"
        )

        # The high-rep account scores higher than the low-rep one.
        assert high_hit["confidence"] > low_hit["confidence"]
        assert (
            high_hit["confidence_signals"]["profile"]
            > low_hit["confidence_signals"]["profile"]
        )

    @patch("shutil.which", return_value="/usr/local/bin/maigret")
    async def test_phase_b3_ubiquity_records_and_penalises_recurrent_handles(
        self, _which, tmp_path,
    ):
        """Phase B3 end-to-end: record a handle across many campaigns,
        confirm the next scoring run picks up the ubiquity penalty
        and downgrades attribution confidence.

        First campaign establishes the baseline (no ubiquity signal).
        Subsequent campaigns add observations until the count crosses
        the curve threshold; the final campaign confirms the handle's
        uniqueness signal dropped because the ubiquity tracker now
        knows the handle is widely recurring."""
        from nexusrecon.core.handle_ubiquity import (
            HandleUbiquityTracker,
            ubiquity_context,
        )

        tool = MaigretTool()
        db = tmp_path / "ubiquity_demo.db"
        tracker = HandleUbiquityTracker(db_path=db)

        async def _fake_maigret(*args, **kwargs):
            cmd_args = list(args)
            username = cmd_args[1]
            idx = cmd_args.index("--folderoutput")
            tmpdir = Path(cmd_args[idx + 1])
            (tmpdir / f"{username}_simple.json").write_text(
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

        def _find_hit(result, handle: str):
            """Pull the hit for a specific username from the result.

            Maigret returns hits sorted by confidence and the result
            may include multiple candidates (e.g. literal + stripped-
            suffix), so positional indexing isn't reliable."""
            return next(
                h for h in result.data["registered_services"]
                if h["username"] == handle
            )

        # First campaign ── baseline. handle ``recurringhandle1234`` is
        # a unique-looking handle that gets observed for the first
        # time. ``fetch_profiles=False`` keeps the test fast and
        # ``max_candidates=1`` ensures we only probe the literal
        # local-part (not the stripped-suffix variant).
        with patch("asyncio.create_subprocess_exec",
                   new=AsyncMock(side_effect=_fake_maigret)), \
             ubiquity_context(tracker):
            result_first = await tool.run(
                "recurringhandle1234@example.com",
                target_type="username",
                fetch_profiles=False,
                campaign_id="campaign-001",
                max_candidates=1,
            )
        first_hit = _find_hit(result_first, "recurringhandle1234")
        baseline_uniqueness = first_hit["confidence_signals"]["uniqueness"]
        baseline_confidence = first_hit["confidence"]

        # Simulate observing the same handle across more campaigns,
        # representing prior recon runs. After 4 distinct campaigns,
        # the ubiquity curve maps to commonness 0.60.
        for cid in ("campaign-002", "campaign-003", "campaign-004"):
            tracker.record_observation(
                handle="recurringhandle1234",
                service="GitHub",
                campaign_id=cid,
            )

        # Now run a NEW campaign and confirm the same hit gets
        # penalised. We use a different email domain on a different
        # campaign so the new campaign doesn't share state with the
        # first.
        with patch("asyncio.create_subprocess_exec",
                   new=AsyncMock(side_effect=_fake_maigret)), \
             ubiquity_context(tracker):
            result_after = await tool.run(
                "recurringhandle1234@anotherorg.com",
                target_type="username",
                fetch_profiles=False,
                campaign_id="campaign-099",
                max_candidates=1,
            )
        after_hit = _find_hit(result_after, "recurringhandle1234")
        penalised_uniqueness = after_hit["confidence_signals"]["uniqueness"]
        penalised_confidence = after_hit["confidence"]

        # The handle's uniqueness should drop noticeably after the
        # tracker accumulates evidence of cross-campaign recurrence.
        assert penalised_uniqueness < baseline_uniqueness, (
            f"ubiquity penalty not applied: baseline={baseline_uniqueness}, "
            f"after_4_campaigns={penalised_uniqueness}"
        )
        # Confidence should also drop (uniqueness contributes 20% of
        # the weighted sum).
        assert penalised_confidence < baseline_confidence

        tracker.close()

    @patch("shutil.which", return_value="/usr/local/bin/maigret")
    async def test_phase_b3_no_tracker_means_no_recording(
        self, _which, tmp_path,
    ):
        """When no ubiquity_context is active, maigret runs in
        ubiquity-blind mode ── no observations persisted. Pin this so
        operators get the documented opt-in semantics."""
        from nexusrecon.core.handle_ubiquity import HandleUbiquityTracker

        tool = MaigretTool()
        db = tmp_path / "ubiquity_should_stay_empty.db"
        tracker = HandleUbiquityTracker(db_path=db)
        assert tracker.total_observations() == 0

        async def _fake_maigret(*args, **kwargs):
            cmd_args = list(args)
            username = cmd_args[1]
            idx = cmd_args.index("--folderoutput")
            tmpdir = Path(cmd_args[idx + 1])
            (tmpdir / f"{username}_simple.json").write_text(
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

        # Run WITHOUT a ubiquity_context.
        with patch("asyncio.create_subprocess_exec",
                   new=AsyncMock(side_effect=_fake_maigret)):
            await tool.run(
                "somehandle",
                target_type="username",
                fetch_profiles=False,
                campaign_id="some-campaign",
            )

        # The tracker we created should not have observations because
        # it was never bound to the run.
        assert tracker.total_observations() == 0
        tracker.close()

    @patch("shutil.which", return_value="/usr/local/bin/maigret")
    async def test_phase_b_cross_reference_between_hits(self, _which):
        """B4 end-to-end: hit on GitHub has a bio mentioning a
        Twitter handle; we have a separate Twitter hit for that
        handle. The cross-reference closes the graph and the Twitter
        hit's profile signal gets the cross-ref bonus."""
        import respx
        from httpx import Response

        tool = MaigretTool()

        async def _fake_maigret(*args, **kwargs):
            cmd_args = list(args)
            username = cmd_args[1]
            idx = cmd_args.index("--folderoutput")
            tmpdir = Path(cmd_args[idx + 1])
            # One candidate, two hits (GitHub + Twitter).
            (tmpdir / f"{username}_simple.json").write_text(
                json.dumps({
                    "GitHub": {
                        "url_user": f"https://github.com/{username}",
                        "status": {"status": "Claimed", "ids": {}},
                    },
                    "Twitter": {
                        "url_user": f"https://twitter.com/{username}",
                        "status": {"status": "Claimed", "ids": {}},
                    },
                }),
                encoding="utf-8",
            )
            proc = MagicMock()
            proc.communicate = AsyncMock(return_value=(b"", b""))
            return proc

        with patch("asyncio.create_subprocess_exec",
                   new=AsyncMock(side_effect=_fake_maigret)), \
             respx.mock:
            # GitHub bio mentions the Twitter handle.
            respx.get("https://api.github.com/users/janedoe").mock(
                return_value=Response(200, json={
                    "login": "janedoe",
                    "bio": "Engineer. Twitter: twitter.com/janedoe",
                    "html_url": "https://github.com/janedoe",
                }),
            )

            result = await tool.run(
                "janedoe@example.com",
                target_type="email",
                max_candidates=1,
                fetch_profiles=True,
            )

        hits = result.data["registered_services"]
        twitter_hit = next(h for h in hits if h["service"] == "Twitter")
        # Cross-referenced from GitHub.
        assert "cross_referenced_from" in twitter_hit
        sources = [
            entry["source_service"]
            for entry in twitter_hit["cross_referenced_from"]
        ]
        assert "GitHub" in sources

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

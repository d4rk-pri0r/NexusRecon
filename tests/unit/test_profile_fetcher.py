"""Tests for nexusrecon.core.profile_fetcher.

The fetcher dispatches per-service to GitHub/GitLab/Reddit/StackOverflow
APIs or falls back to generic HTML extraction. We mock the HTTP layer
via respx and assert on:

  1. Dispatch correctness ── ``service="GitHub"`` hits the GitHub API,
     ``service="Reddit"`` hits Reddit's about.json, etc.
  2. Parsing correctness ── fields land in the right ProfileData slots.
  3. Error handling ── non-200 / connection error returns a ProfileData
     with ``.error`` set, not a raised exception.
  4. Generic fallback for unknown services ── pulls
     ``<meta name="description">`` and OG tags.
"""
from __future__ import annotations

import json

import httpx
import respx
from httpx import Response

from nexusrecon.core.profile_fetcher import (
    ProfileData,
    fetch_profile,
    fetch_profiles_batch,
)


# ──────────────────────────────────────────────────────────────────────
# ProfileData behaviour
# ──────────────────────────────────────────────────────────────────────


class TestProfileData:
    def test_empty_defaults(self):
        p = ProfileData()
        assert p.bio is None
        assert p.location is None
        assert p.fetched is False
        assert p.error is None
        assert p.linked_accounts == []

    def test_coherence_blob_joins_identity_fields(self):
        p = ProfileData(
            service="GitHub", username="jane",
            display_name="Jane Doe",
            bio="Engineer at GitLab",
            location="San Francisco",
            company="GitLab Inc.",
        )
        blob = p.coherence_blob()
        assert "jane doe" in blob
        assert "engineer at gitlab" in blob
        assert "san francisco" in blob
        assert "gitlab inc." in blob

    def test_coherence_blob_skips_none_fields(self):
        p = ProfileData(
            service="GitHub", username="jane",
            bio="Bio here",
            # location, company, display_name all None
        )
        blob = p.coherence_blob()
        assert blob == "bio here"

    def test_to_dict_is_json_safe(self):
        p = ProfileData(
            service="GitHub", username="jane",
            bio="bio", linked_accounts=[{"target_service": "Twitter"}],
        )
        d = p.to_dict()
        # All values must be JSON-serialisable.
        json.dumps(d)  # would raise if not


# ──────────────────────────────────────────────────────────────────────
# GitHub fetcher
# ──────────────────────────────────────────────────────────────────────


class TestGitHubFetcher:
    async def test_happy_path_extracts_all_fields(self):
        fixture = {
            "login": "janedoe",
            "name": "Jane Doe",
            "bio": "Senior engineer at GitLab. Opinions my own.",
            "location": "San Francisco",
            "company": "@gitlab-org",
            "blog": "https://janedoe.dev",
            "email": "jane@example.com",
            "html_url": "https://github.com/janedoe",
            "created_at": "2014-03-04T12:00:00Z",
            "updated_at": "2026-05-19T10:00:00Z",
            "public_repos": 47,
            "followers": 128,
            "twitter_username": "janedoe_twit",
        }
        with respx.mock:
            respx.get("https://api.github.com/users/janedoe").mock(
                return_value=Response(200, json=fixture),
            )
            profile = await fetch_profile("GitHub", "janedoe", "")

        assert profile.fetched is True
        assert profile.error is None
        assert profile.service == "GitHub"
        assert profile.display_name == "Jane Doe"
        assert profile.bio == "Senior engineer at GitLab. Opinions my own."
        assert profile.location == "San Francisco"
        assert profile.company == "@gitlab-org"
        assert profile.blog_url == "https://janedoe.dev"
        assert profile.email == "jane@example.com"
        assert profile.raw_extras["public_repos"] == 47
        assert profile.raw_extras["twitter_username"] == "janedoe_twit"

    async def test_404_returns_error_not_exception(self):
        with respx.mock:
            respx.get("https://api.github.com/users/nonexistent").mock(
                return_value=Response(404),
            )
            profile = await fetch_profile("GitHub", "nonexistent", "")
        assert profile.fetched is False
        assert profile.error is not None

    async def test_dispatch_is_case_insensitive(self):
        """``service="github"`` (lowercase) should still hit the
        GitHub API."""
        with respx.mock:
            respx.get("https://api.github.com/users/jane").mock(
                return_value=Response(200, json={"login": "jane"}),
            )
            profile = await fetch_profile("github", "jane", "")
        assert profile.fetched is True


# ──────────────────────────────────────────────────────────────────────
# GitLab fetcher
# ──────────────────────────────────────────────────────────────────────


class TestGitLabFetcher:
    async def test_happy_path(self):
        fixture = [{
            "id": 12345,
            "username": "janedoe",
            "name": "Jane Doe",
            "bio": "Backend engineer",
            "location": "Berlin",
            "organization": "GitLab",
            "job_title": "Senior Engineer",
            "website_url": "https://janedoe.dev",
            "public_email": "jane@example.com",
            "linkedin": "jane-doe",
            "twitter": "@janedoe",
            "web_url": "https://gitlab.com/janedoe",
            "created_at": "2014-03-04T12:00:00Z",
        }]
        with respx.mock:
            respx.get("https://gitlab.com/api/v4/users").mock(
                return_value=Response(200, json=fixture),
            )
            profile = await fetch_profile("GitLab", "janedoe", "")

        assert profile.fetched is True
        assert profile.display_name == "Jane Doe"
        assert profile.bio == "Backend engineer"
        assert profile.location == "Berlin"
        assert profile.company == "GitLab"
        assert profile.email == "jane@example.com"
        assert profile.raw_extras["job_title"] == "Senior Engineer"

    async def test_empty_user_list_returns_error(self):
        with respx.mock:
            respx.get("https://gitlab.com/api/v4/users").mock(
                return_value=Response(200, json=[]),
            )
            profile = await fetch_profile("GitLab", "nonexistent", "")
        assert profile.fetched is False
        assert profile.error is not None


# ──────────────────────────────────────────────────────────────────────
# Reddit fetcher
# ──────────────────────────────────────────────────────────────────────


class TestRedditFetcher:
    async def test_happy_path(self):
        fixture = {
            "data": {
                "name": "janedoe",
                "comment_karma": 4250,
                "link_karma": 1830,
                "created_utc": 1395849600,
                "is_employee": False,
                "verified": True,
                "subreddit": {
                    "title": "Jane Doe",
                    "public_description": "Software engineer interested in DevOps",
                },
            },
        }
        with respx.mock:
            respx.get("https://www.reddit.com/user/janedoe/about.json").mock(
                return_value=Response(200, json=fixture),
            )
            profile = await fetch_profile("Reddit", "janedoe", "")

        assert profile.fetched is True
        assert profile.display_name == "Jane Doe"
        assert profile.bio == "Software engineer interested in DevOps"
        assert profile.raw_extras["comment_karma"] == 4250
        assert profile.raw_extras["verified"] is True

    async def test_429_rate_limit_returns_error(self):
        with respx.mock:
            respx.get("https://www.reddit.com/user/janedoe/about.json").mock(
                return_value=Response(429),
            )
            profile = await fetch_profile("Reddit", "janedoe", "")
        assert profile.fetched is False
        assert profile.error is not None


# ──────────────────────────────────────────────────────────────────────
# Stack Exchange fetcher
# ──────────────────────────────────────────────────────────────────────


class TestStackExchangeFetcher:
    async def test_happy_path(self):
        fixture = {
            "items": [{
                "display_name": "Jane Doe",
                "reputation": 12450,
                "user_type": "registered",
                "account_id": 9876,
                "location": "San Francisco",
                "website_url": "https://janedoe.dev",
                "link": "https://stackoverflow.com/users/123456/jane-doe",
                "creation_date": 1395849600,
                "last_access_date": 1716000000,
            }],
        }
        with respx.mock:
            respx.get("https://api.stackexchange.com/2.3/users").mock(
                return_value=Response(200, json=fixture),
            )
            profile = await fetch_profile("StackOverflow", "janedoe", "")

        assert profile.fetched is True
        assert profile.display_name == "Jane Doe"
        assert profile.location == "San Francisco"
        assert profile.raw_extras["reputation"] == 12450
        # account_id is the cross-Stack-Exchange identity key.
        assert profile.raw_extras["account_id"] == 9876

    async def test_empty_items_returns_error(self):
        with respx.mock:
            respx.get("https://api.stackexchange.com/2.3/users").mock(
                return_value=Response(200, json={"items": []}),
            )
            profile = await fetch_profile("StackOverflow", "nonexistent", "")
        assert profile.fetched is False


# ──────────────────────────────────────────────────────────────────────
# Generic HTML fallback
# ──────────────────────────────────────────────────────────────────────


class TestGenericFallback:
    async def test_og_description_extracted(self):
        html = """
        <html><head>
            <meta property="og:title" content="Jane Doe (@jane) on Mastodon">
            <meta property="og:description" content="Engineer at GitLab. Opinions my own.">
        </head><body></body></html>
        """
        with respx.mock:
            respx.get("https://hachyderm.io/@jane").mock(
                return_value=Response(200, text=html),
            )
            profile = await fetch_profile(
                "Mastodon", "jane",
                url="https://hachyderm.io/@jane",
            )

        assert profile.fetched is True
        assert profile.display_name == "Jane Doe (@jane) on Mastodon"
        assert profile.bio == "Engineer at GitLab. Opinions my own."

    async def test_meta_description_fallback_when_no_og(self):
        html = """
        <html><head>
            <meta name="description" content="Backup description text">
        </head></html>
        """
        with respx.mock:
            respx.get("https://example.com/user").mock(
                return_value=Response(200, text=html),
            )
            profile = await fetch_profile(
                "UnknownService", "user",
                url="https://example.com/user",
            )
        assert profile.bio == "Backup description text"

    async def test_missing_meta_tags_returns_empty_profile(self):
        html = "<html><body>Just HTML, no meta tags.</body></html>"
        with respx.mock:
            respx.get("https://example.com/user").mock(
                return_value=Response(200, text=html),
            )
            profile = await fetch_profile(
                "UnknownService", "user",
                url="https://example.com/user",
            )
        assert profile.fetched is True
        assert profile.bio is None
        assert profile.display_name is None

    async def test_missing_url_returns_error(self):
        """Generic fallback needs the URL to fetch. Without one, it
        should report an error rather than guess."""
        profile = await fetch_profile("UnknownService", "user", url="")
        assert profile.fetched is False
        assert "URL" in (profile.error or "")


# ──────────────────────────────────────────────────────────────────────
# Batch fetcher
# ──────────────────────────────────────────────────────────────────────


class TestBatchFetcher:
    async def test_batch_processes_multiple_hits(self):
        hits = [
            {"service": "GitHub", "username": "jane", "url": ""},
            {"service": "Reddit", "username": "jane", "url": ""},
        ]
        with respx.mock:
            respx.get("https://api.github.com/users/jane").mock(
                return_value=Response(200, json={"login": "jane", "bio": "GH bio"}),
            )
            respx.get("https://www.reddit.com/user/jane/about.json").mock(
                return_value=Response(200, json={
                    "data": {
                        "subreddit": {"public_description": "Reddit bio"},
                    },
                }),
            )
            results = await fetch_profiles_batch(hits, max_concurrent=2)

        assert len(results) == 2
        assert results[0].bio == "GH bio"
        assert results[1].bio == "Reddit bio"

    async def test_batch_preserves_input_order(self):
        hits = [
            {"service": "GitHub", "username": "a", "url": ""},
            {"service": "GitHub", "username": "b", "url": ""},
            {"service": "GitHub", "username": "c", "url": ""},
        ]
        with respx.mock:
            respx.get("https://api.github.com/users/a").mock(
                return_value=Response(200, json={"login": "a"}))
            respx.get("https://api.github.com/users/b").mock(
                return_value=Response(200, json={"login": "b"}))
            respx.get("https://api.github.com/users/c").mock(
                return_value=Response(200, json={"login": "c"}))
            results = await fetch_profiles_batch(hits)

        assert [r.username for r in results] == ["a", "b", "c"]

    async def test_one_failed_hit_doesnt_break_batch(self):
        hits = [
            {"service": "GitHub", "username": "a", "url": ""},
            {"service": "GitHub", "username": "missing", "url": ""},
            {"service": "GitHub", "username": "c", "url": ""},
        ]
        with respx.mock:
            respx.get("https://api.github.com/users/a").mock(
                return_value=Response(200, json={"login": "a", "bio": "A"}))
            respx.get("https://api.github.com/users/missing").mock(
                return_value=Response(404))
            respx.get("https://api.github.com/users/c").mock(
                return_value=Response(200, json={"login": "c", "bio": "C"}))
            results = await fetch_profiles_batch(hits)

        assert results[0].fetched is True
        assert results[1].fetched is False
        assert results[2].fetched is True
        # Two successes + one failure, all returned.
        assert len(results) == 3


# ──────────────────────────────────────────────────────────────────────
# Error handling
# ──────────────────────────────────────────────────────────────────────


class TestErrorHandling:
    async def test_connection_error_returns_error_not_exception(self):
        with respx.mock:
            respx.get("https://api.github.com/users/jane").mock(
                side_effect=httpx.ConnectError("connection refused"),
            )
            profile = await fetch_profile("GitHub", "jane", "")
        assert profile.fetched is False
        assert profile.error is not None

    async def test_invalid_json_returns_error(self):
        with respx.mock:
            respx.get("https://api.github.com/users/jane").mock(
                return_value=Response(200, text="not json"),
            )
            profile = await fetch_profile("GitHub", "jane", "")
        assert profile.fetched is False

    async def test_empty_username_returns_error_without_fetch(self):
        profile = await fetch_profile("GitHub", "", "")
        assert profile.fetched is False
        assert "empty" in (profile.error or "").lower()

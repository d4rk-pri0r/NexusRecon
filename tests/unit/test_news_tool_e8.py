"""Tests for the Phase E8 extensions to news_tool.

The existing news_tool integration tests in tests/integration/test_tools_http.py
cover the pre-E8 shape (target / total_articles / sources_used / articles).
This file covers the ADDITIVE E8 behavior:

  - time_window_days kwarg controls recent_activity_records filtering
  - default applied when kwarg missing
  - time_window_days=0 disables windowing (empty records)
  - articles list stays unfiltered regardless of window
  - kind classification (news_article / press_release / earnings)
  - RecentActivity records carry the full per-article payload
  - Output shape is backward-compatible (all old keys present)
"""
from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from nexusrecon.core.recent_activity import DEFAULT_WINDOW_DAYS
from nexusrecon.tools.pretext.news_tool import (
    NewsTool,
    _articles_to_records,
    _classify_article_kind,
)

# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────


def _mock_config(newsapi_key: str | None = None):
    cfg = MagicMock()
    cfg.get_secret.side_effect = lambda name: {
        "newsapi_api_key": newsapi_key,
    }.get(name)
    return cfg


def _make_tool(newsapi_key: str | None = None) -> NewsTool:
    tool = NewsTool()
    tool.config = _mock_config(newsapi_key)
    return tool


def _iso(year: int, month: int = 1, day: int = 1) -> str:
    return datetime(year, month, day, tzinfo=UTC).isoformat()


def _rss_xml(items: list[dict[str, str]]) -> str:
    parts = ['<?xml version="1.0"?>', "<rss><channel>"]
    for it in items:
        parts.append("<item>")
        for k in ("title", "link", "description", "pubDate"):
            v = it.get(k)
            if v is not None:
                parts.append(f"<{k}>{v}</{k}>")
        parts.append("</item>")
    parts.append("</channel></rss>")
    return "".join(parts)


# ──────────────────────────────────────────────────────────────────────
# _classify_article_kind
# ──────────────────────────────────────────────────────────────────────


class TestClassifyArticleKind:
    def test_press_release_announces(self):
        assert _classify_article_kind("Acme Announces New Product") == "press_release"

    def test_press_release_launches(self):
        assert _classify_article_kind("Acme Launches AI Platform") == "press_release"

    def test_earnings(self):
        assert _classify_article_kind("Acme Q3 Earnings Beat Estimates") == "earnings"

    def test_ma_classifies_as_press_release(self):
        assert _classify_article_kind("Acme Acquires Startup Inc") == "press_release"

    def test_default_news_article(self):
        assert _classify_article_kind("Regular Headline About Stuff") == "news_article"

    def test_case_insensitive(self):
        assert _classify_article_kind("ACME ANNOUNCES THING") == "press_release"

    def test_empty_string(self):
        assert _classify_article_kind("") == "news_article"


# ──────────────────────────────────────────────────────────────────────
# _articles_to_records
# ──────────────────────────────────────────────────────────────────────


class TestArticlesToRecords:
    def test_basic_conversion(self):
        articles = [{
            "title": "Acme story",
            "source": "Google News RSS",
            "url": "https://example.com/x",
            "published_at": _iso(2024, 6, 1),
            "description": "snippet",
        }]
        records = _articles_to_records("example.com", articles)
        assert len(records) == 1
        r = records[0]
        assert r.target == "example.com"
        assert r.kind == "news_article"
        assert r.source == "Google News RSS"
        assert r.title == "Acme story"
        assert r.url == "https://example.com/x"
        assert r.summary == "snippet"
        assert r.published_at == _iso(2024, 6, 1)
        assert r.raw == articles[0]

    def test_kind_classification_applied(self):
        articles = [
            {"title": "Acme Announces Product",
             "source": "x", "url": "", "published_at": "", "description": ""},
            {"title": "Q3 Earnings",
             "source": "x", "url": "", "published_at": "", "description": ""},
        ]
        records = _articles_to_records("acme.com", articles)
        kinds = [r.kind for r in records]
        assert "press_release" in kinds
        assert "earnings" in kinds

    def test_skips_non_dict_entries(self):
        articles = [None, {"title": "OK", "source": "x"}, "string"]
        records = _articles_to_records("x", articles)
        assert len(records) == 1

    def test_falls_back_to_news_intel_source(self):
        articles = [{"title": "Story", "url": "u"}]  # no source
        records = _articles_to_records("x", articles)
        assert records[0].source == "news_intel"

    def test_url_none_when_empty(self):
        articles = [{"title": "Story", "source": "x", "url": ""}]
        records = _articles_to_records("x", articles)
        assert records[0].url is None

    def test_summary_truncated_to_500(self):
        long = "x" * 800
        articles = [{"title": "Story", "source": "x", "url": "", "description": long}]
        records = _articles_to_records("x", articles)
        assert len(records[0].summary) == 500


# ──────────────────────────────────────────────────────────────────────
# Tool: E8 additive shape
# ──────────────────────────────────────────────────────────────────────


class TestNewsToolE8Output:
    @pytest.mark.asyncio
    async def test_default_window_applied(self):
        # No time_window_days kwarg → default DEFAULT_WINDOW_DAYS is used
        # and echoed back in the response.
        tool = _make_tool()
        # Mock the RSS fetch to return a recent article
        recent_date = "Mon, 01 Jun 2024 00:00:00 GMT"
        xml = _rss_xml([{
            "title": "Recent story",
            "link": "https://x/1",
            "description": "snippet",
            "pubDate": recent_date,
        }])
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = xml
        with patch(
            "nexusrecon.tools.pretext.news_tool.httpx.AsyncClient",
        ) as cls:
            mock_client = AsyncMock()
            cls.return_value.__aenter__.return_value = mock_client
            mock_client.get.return_value = mock_resp
            result = await tool.run("example.com")
        assert result.success
        assert result.data["time_window_days"] == DEFAULT_WINDOW_DAYS

    @pytest.mark.asyncio
    async def test_articles_field_preserved(self):
        # Backward compat: articles list, total_articles, sources_used unchanged.
        tool = _make_tool()
        xml = _rss_xml([{
            "title": "S", "link": "u", "description": "d",
            "pubDate": "Mon, 01 Jan 2026 00:00:00 GMT",
        }])
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = xml
        with patch(
            "nexusrecon.tools.pretext.news_tool.httpx.AsyncClient",
        ) as cls:
            mock_client = AsyncMock()
            cls.return_value.__aenter__.return_value = mock_client
            mock_client.get.return_value = mock_resp
            result = await tool.run("example.com")
        d = result.data
        # Backward-compat fields all present
        assert "target" in d
        assert "total_articles" in d
        assert "sources_used" in d
        assert "articles" in d
        assert len(d["articles"]) >= 1
        # New additive fields present
        assert "recent_activity_records" in d
        assert "time_window_days" in d

    @pytest.mark.asyncio
    async def test_window_zero_disables_records(self):
        tool = _make_tool()
        xml = _rss_xml([{
            "title": "S", "link": "u", "description": "d",
            "pubDate": "Mon, 01 Jan 2026 00:00:00 GMT",
        }])
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = xml
        with patch(
            "nexusrecon.tools.pretext.news_tool.httpx.AsyncClient",
        ) as cls:
            mock_client = AsyncMock()
            cls.return_value.__aenter__.return_value = mock_client
            mock_client.get.return_value = mock_resp
            result = await tool.run("example.com", time_window_days=0)
        # articles still populated, but recent_activity_records is empty
        assert result.data["articles"]
        assert result.data["recent_activity_records"] == []
        assert result.data["time_window_days"] == 0

    @pytest.mark.asyncio
    async def test_articles_unfiltered_by_window(self):
        # Even with a tight window, articles list keeps everything we
        # fetched — only recent_activity_records is filtered.
        tool = _make_tool()
        old_date = "Mon, 01 Jan 2020 00:00:00 GMT"  # well outside any window
        xml = _rss_xml([{
            "title": "old", "link": "u", "description": "d",
            "pubDate": old_date,
        }])
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = xml
        with patch(
            "nexusrecon.tools.pretext.news_tool.httpx.AsyncClient",
        ) as cls:
            mock_client = AsyncMock()
            cls.return_value.__aenter__.return_value = mock_client
            mock_client.get.return_value = mock_resp
            result = await tool.run("example.com", time_window_days=30)
        assert len(result.data["articles"]) >= 1   # unfiltered
        # All articles are 2020-vintage; nothing inside the 30-day window
        assert result.data["recent_activity_records"] == []

    @pytest.mark.asyncio
    async def test_custom_window_applied(self):
        tool = _make_tool()
        xml = _rss_xml([{
            "title": "S", "link": "u", "description": "d",
            "pubDate": "Mon, 01 Jan 2026 00:00:00 GMT",
        }])
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = xml
        with patch(
            "nexusrecon.tools.pretext.news_tool.httpx.AsyncClient",
        ) as cls:
            mock_client = AsyncMock()
            cls.return_value.__aenter__.return_value = mock_client
            mock_client.get.return_value = mock_resp
            result = await tool.run("example.com", time_window_days=7)
        assert result.data["time_window_days"] == 7

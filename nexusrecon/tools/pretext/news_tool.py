"""News, press, M&A, and earnings intelligence tool.

Phase E8 extended this tool in-place: the existing news-aggregation
behaviour is unchanged (Google News RSS + Yahoo Finance RSS + the
NewsAPI provider, ``articles`` array in ``ToolResult.data``), and
two new outputs sit alongside it:

  - ``recent_activity_records``: a list of
    :class:`~nexusrecon.core.recent_activity.RecentActivity`
    payloads ── time-filtered to the last ``time_window_days``
    (default 90). Phase E9 pretext scoring consumes these to power
    the "what's plausibly topical right now" axis.
  - Aggregated ``time_window_days`` echo so consumers can verify
    which window was applied without re-reading the kwarg.

The existing top-level output shape is preserved exactly:

    {
        "target": str,
        "total_articles": int,
        "sources_used": list[str],
        "articles": [...],          # unfiltered, backward-compat
        # NEW additive fields:
        "recent_activity_records": [{...}],  # time-windowed
        "time_window_days": int,
    }

Backward-compatibility note: existing integration tests in
``tests/integration/test_tools_http.py`` only assert on
``total_articles``, ``sources_used``, and ``result_count``. New
fields are additive and do not change those.
"""
from __future__ import annotations

from typing import Any

import httpx

from nexusrecon.core.recent_activity import (
    DEFAULT_WINDOW_DAYS,
    RecentActivity,
    filter_by_window,
)
from nexusrecon.opsec.useragent import random_ua
from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool

NEWS_SOURCES = [
    {
        "name": "Google News RSS",
        "url": "https://news.google.com/rss/search",
        "params": {"q": "{target}", "hl": "en-US", "gl": "US", "ceid": "US:en"},
        "type": "rss",
    },
    {
        "name": "Yahoo Finance RSS",
        "url": "https://finance.yahoo.com/rss/headline",
        "params": {"s": "{target}"},
        "type": "rss",
    },
]

NEWS_API_URL = "https://newsapi.org/v2/everything"


@register_tool
class NewsTool(OSINTTool):
    name = "news_intel"
    tier = Tier.T0
    category = Category.NEWS
    requires_keys = []
    optional_keys = ["newsapi_api_key"]
    description = (
        "News, press releases, M&A activity, and earnings mining. "
        "Phase E8 adds time-windowed RecentActivity records for "
        "pretext scoring (default 90-day window)."
    )
    target_types = ["domain"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        articles: list[dict[str, Any]] = []
        sources_used: list[str] = []

        # Try NewsAPI if key is available
        api_key = self.config.get_secret("newsapi_api_key")
        if api_key:
            newsapi_results = await self._fetch_newsapi(target, api_key)
            articles.extend(newsapi_results)
            sources_used.append("newsapi")

        # RSS fallback
        rss_results = await self._fetch_rss_sources(target)
        articles.extend(rss_results)
        if rss_results:
            sources_used.append("rss")

        # ── Phase E8 additive: RecentActivity records (time-windowed) ──
        # ``time_window_days`` defaults to DEFAULT_WINDOW_DAYS (90).
        # Pass ``time_window_days=0`` to disable windowing entirely
        # (returns an empty recent_activity_records list).
        window_days = kwargs.get("time_window_days")
        if window_days is None:
            window_days = DEFAULT_WINDOW_DAYS
        else:
            window_days = int(window_days)

        all_records = _articles_to_records(target, articles)
        if window_days > 0:
            recent_records = filter_by_window(
                all_records, window_days=window_days,
            )
        else:
            recent_records = []

        return ToolResult(
            success=True, source=self.name,
            data={
                "target": target,
                "total_articles": len(articles),
                "sources_used": sources_used,
                "articles": articles[:50],
                # ── E8 additive fields ──
                "recent_activity_records": [
                    r.to_dict() for r in recent_records
                ],
                "time_window_days": window_days,
            },
            result_count=len(articles),
        )

    async def _fetch_newsapi(self, target: str, api_key: str) -> list[dict[str, Any]]:
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(
                    NEWS_API_URL,
                    params={
                        "q": target,
                        "language": "en",
                        "sortBy": "relevancy",
                        "pageSize": 20,
                        "apiKey": api_key,
                    },
                )
                if resp.status_code == 200:
                    data = resp.json()
                    return [
                        {
                            "title": a.get("title", ""),
                            "source": a.get("source", {}).get("name", ""),
                            "url": a.get("url", ""),
                            "published_at": a.get("publishedAt", ""),
                            "description": (a.get("description") or "")[:300],
                        }
                        for a in data.get("articles", [])
                    ]
        except Exception:
            pass
        return []

    async def _fetch_rss_sources(self, target: str) -> list[dict[str, Any]]:
        articles: list[dict[str, Any]] = []
        async with httpx.AsyncClient(timeout=8.0, follow_redirects=True) as client:
            for source in NEWS_SOURCES:
                try:
                    params = {k: v.format(target=target) for k, v in source["params"].items()}
                    resp = await client.get(source["url"], params=params, headers={"User-Agent": random_ua()})
                    if resp.status_code == 200:
                        parsed = self._parse_rss(resp.text)
                        for item in parsed[:10]:
                            articles.append({
                                "title": item.get("title", ""),
                                "source": source["name"],
                                "url": item.get("link", ""),
                                "published_at": item.get("pubDate", ""),
                                "description": (item.get("description") or "")[:300],
                            })
                except Exception:
                    continue
        return articles

    @staticmethod
    def _parse_rss(xml_text: str) -> list[dict[str, str]]:
        """Minimal RSS/XML parser without external dependencies."""
        items = []
        import re
        for item_match in re.finditer(r"<item>(.*?)</item>", xml_text, re.DOTALL):
            item_xml = item_match.group(1)
            item: dict[str, str] = {}
            for field in ("title", "link", "description", "pubDate", "source"):
                m = re.search(rf"<{field}[^>]*>(.*?)</{field}>", item_xml, re.DOTALL)
                if m:
                    import html as html_mod
                    item[field] = html_mod.unescape(re.sub(r"<[^>]+>", "", m.group(1)).strip())
            if item.get("title"):
                items.append(item)
        return items


# ──────────────────────────────────────────────────────────────────────
# Article → RecentActivity adapter
# ──────────────────────────────────────────────────────────────────────


def _articles_to_records(
    target: str,
    articles: list[dict[str, Any]],
) -> list[RecentActivity]:
    """Convert news-tool article dicts into RecentActivity records.

    The ``kind`` is heuristically assigned:
      - "press_release" when the title contains "announces" /
        "introduces" / "launches" markers.
      - "earnings" when the title carries an earnings marker.
      - "news_article" otherwise.

    Keeps the original article in ``raw`` so audit / re-processing
    has the unmodified upstream record.
    """
    out: list[RecentActivity] = []
    for a in articles:
        if not isinstance(a, dict):
            continue
        title = (a.get("title") or "").strip()
        out.append(RecentActivity(
            target=target,
            kind=_classify_article_kind(title),
            source=(a.get("source") or "news_intel"),
            title=title,
            url=a.get("url") or None,
            summary=(a.get("description") or "")[:500],
            published_at=a.get("published_at") or None,
            raw=dict(a),
        ))
    return out


_PRESS_RELEASE_MARKERS = (
    "announces", "announced", "introduces", "launches", "launched",
    "unveils", "debuts", "releases",
)
_EARNINGS_MARKERS = (
    "earnings", "quarterly results", "q1 ", "q2 ", "q3 ", "q4 ",
    "fiscal year", "reports revenue",
)
_MA_MARKERS = (
    "acquires", "acquired", "acquisition", "merges with", "merger",
    "to buy", "buys",
)


def _classify_article_kind(title: str) -> str:
    """Heuristic ``kind`` classifier for a news article title."""
    lower = title.lower()
    if any(m in lower for m in _PRESS_RELEASE_MARKERS):
        return "press_release"
    if any(m in lower for m in _EARNINGS_MARKERS):
        return "earnings"
    if any(m in lower for m in _MA_MARKERS):
        return "press_release"  # M&A is a press-release subtype
    return "news_article"

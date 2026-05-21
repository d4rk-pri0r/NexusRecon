"""News, press, M&A, and earnings intelligence tool."""
from __future__ import annotations

from typing import Any

import httpx

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
    description = "News, press releases, M&A activity, and earnings call mining"
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

        return ToolResult(
            success=True, source=self.name,
            data={
                "target": target,
                "total_articles": len(articles),
                "sources_used": sources_used,
                "articles": articles[:50],
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

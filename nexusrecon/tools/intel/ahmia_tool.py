"""Ahmia — clearnet Tor search engine for dark-web mentions of a target domain."""
from __future__ import annotations

from typing import Any

import httpx
from bs4 import BeautifulSoup

from nexusrecon.opsec.useragent import random_ua
from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool

_HEADERS = {
    "User-Agent": random_ua(),
    "Accept": "text/html",
}


@register_tool
class AhmiaTool(OSINTTool):
    name = "ahmia"
    tier = Tier.T0
    category = Category.INFRASTRUCTURE
    requires_keys = []
    description = "Search Ahmia.fi for dark-web (.onion) mentions of the target domain"
    target_types = ["domain"]
    dynamic_trigger_hints = ["dark web mention found", "onion service discovered"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        onion_results: list[dict[str, str]] = []
        try:
            async with httpx.AsyncClient(headers=_HEADERS, timeout=20.0, follow_redirects=True) as client:
                resp = await client.get(
                    "https://ahmia.fi/search/",
                    params={"q": target},
                )
                if resp.status_code != 200:
                    return ToolResult(
                        success=False,
                        source=self.name,
                        error=f"Ahmia returned HTTP {resp.status_code}",
                    )
                soup = BeautifulSoup(resp.text, "lxml")
                for li in soup.select("li.result"):
                    title_tag = li.select_one("h4 a") or li.select_one("a")
                    snippet_tag = li.select_one("p")
                    title = title_tag.get_text(strip=True) if title_tag else ""
                    onion_url = title_tag.get("href", "") if title_tag else ""
                    snippet = snippet_tag.get_text(strip=True)[:300] if snippet_tag else ""
                    if onion_url:
                        onion_results.append({
                            "title": title,
                            "onion_url": onion_url,
                            "snippet": snippet,
                        })
        except Exception as exc:
            return ToolResult(success=False, source=self.name, error=str(exc))

        return ToolResult(
            success=True,
            source=self.name,
            data={
                "target": target,
                "result_count": len(onion_results),
                "onion_results": onion_results,
            },
            result_count=len(onion_results),
        )

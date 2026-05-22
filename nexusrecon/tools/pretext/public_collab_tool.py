"""Public collaboration board discovery — accidentally-public Trello, Confluence, Notion."""
from __future__ import annotations

from typing import Any

import httpx

from nexusrecon.opsec.useragent import random_ua
from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool

_DORK_TEMPLATES = [
    'site:trello.com "{company}"',
    'site:trello.com "{domain}"',
    'site:*.atlassian.net "{company}"',
    'site:notion.so "{company}"',
    'site:notion.site "{domain}"',
    'site:confluence.com "{domain}"',
    'site:github.com "{domain}" wiki',
    'site:sharepoint.com "{company}"',
]


@register_tool
class PublicCollabTool(OSINTTool):
    name = "public_collab"
    tier = Tier.T0
    category = Category.PRETEXT
    requires_keys = []
    optional_keys = ["bing_search_api_key"]
    description = "Public collab board discovery — finds accidentally-public Trello/Confluence/Notion boards"
    target_types = ["domain"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        company = target.split(".")[0].replace("-", " ").title()
        dorks = [
            t.replace("{company}", company).replace("{domain}", target)
            for t in _DORK_TEMPLATES
        ]

        results: list[dict[str, Any]] = []
        bing_key = self.config.get_secret("bing_search_api_key")

        if bing_key:
            try:
                async with httpx.AsyncClient(
                    base_url="https://api.bing.microsoft.com/v7.0",
                    headers={
                        "Ocp-Apim-Subscription-Key": bing_key,
                        "User-Agent": random_ua(),
                    },
                    timeout=15.0,
                ) as client:
                    for dork in dorks[:5]:
                        resp = await client.get("/search", params={"q": dork, "count": 10})
                        if resp.status_code == 200:
                            for item in resp.json().get("webPages", {}).get("value", []):
                                url = item.get("url", "")
                                platform = _classify_platform(url)
                                if platform:
                                    results.append({
                                        "url": url,
                                        "title": item.get("name"),
                                        "snippet": item.get("snippet", "")[:200],
                                        "platform": platform,
                                        "dork": dork,
                                    })
            except Exception:
                pass

        # Trello public board probe (no auth needed for public boards)
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                trello_resp = await client.get(
                    "https://trello.com/search",
                    params={"q": target, "modelTypes": "boards"},
                    headers={"User-Agent": random_ua()},
                )
                if trello_resp.status_code == 200 and "boards" in trello_resp.text.lower():
                    results.append({
                        "url": f"https://trello.com/search?q={target}&modelTypes=boards",
                        "title": "Trello board search results",
                        "platform": "trello",
                        "note": "Manual review required — Trello search requires JS rendering",
                    })
        except Exception:
            pass

        data: dict[str, Any] = {
            "target": target,
            "company": company,
            "dorks": dorks,
            "results_found": len(results),
            "results": results,
            "manual_hint": (
                "Paste any dork above into Google to find exposed boards. "
                "Set BING_SEARCH_API_KEY for automated execution."
            ) if not bing_key else None,
        }
        return ToolResult(success=True, source=self.name, data=data, result_count=len(results))


def _classify_platform(url: str) -> str:
    if "trello.com" in url:
        return "trello"
    if "atlassian.net" in url or "confluence.com" in url:
        return "confluence/jira"
    if "notion.so" in url or "notion.site" in url:
        return "notion"
    if "sharepoint.com" in url:
        return "sharepoint"
    if "github.com" in url and "wiki" in url:
        return "github_wiki"
    return ""

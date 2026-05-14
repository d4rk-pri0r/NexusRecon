"""LinkedIn employee discovery via search engine dorks."""
from __future__ import annotations

from typing import Any, Dict, List

import httpx

from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool

# Dork templates that surface LinkedIn profiles for a company
_DORK_TEMPLATES = [
    'site:linkedin.com/in "{company}"',
    'site:linkedin.com/in "{company}" engineer',
    'site:linkedin.com/in "{company}" security',
    'site:linkedin.com/in "{company}" devops',
    'site:linkedin.com/in "{company}" developer',
    'site:linkedin.com/in "{company}" manager',
    'site:linkedin.com/in "{company}" director',
    'site:linkedin.com/in "{company}" IT',
]


@register_tool
class LinkedInDorksTool(OSINTTool):
    name = "linkedin_dorks"
    tier = Tier.T0
    category = Category.PRETEXT
    requires_keys = []
    description = "LinkedIn employee discovery — generates and optionally executes search dorks for company staff"
    target_types = ["domain"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        company = target.split(".")[0].replace("-", " ").title()
        dorks = [t.replace("{company}", company) for t in _DORK_TEMPLATES]

        profiles: List[Dict[str, Any]] = []
        bing_key = self.config.get_secret("bing_search_api_key")

        if bing_key:
            try:
                async with httpx.AsyncClient(
                    base_url="https://api.bing.microsoft.com/v7.0",
                    headers={
                        "Ocp-Apim-Subscription-Key": bing_key,
                        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
                    },
                    timeout=15.0,
                ) as client:
                    for dork in dorks[:4]:
                        resp = await client.get("/search", params={"q": dork, "count": 10})
                        if resp.status_code == 200:
                            for result in resp.json().get("webPages", {}).get("value", []):
                                url = result.get("url", "")
                                if "linkedin.com/in/" in url:
                                    profiles.append({
                                        "url": url,
                                        "name": result.get("name", "").replace(" | LinkedIn", ""),
                                        "snippet": result.get("snippet", "")[:200],
                                        "dork": dork,
                                    })
            except Exception:
                pass

        data: Dict[str, Any] = {
            "target": target,
            "company": company,
            "dorks": dorks,
            "profiles_found": len(profiles),
            "profiles": profiles,
            "manual_search_hint": (
                f"Paste any dork above into Google/Bing to enumerate employees. "
                f"Set BING_SEARCH_API_KEY in .env for automated execution."
            ) if not bing_key else None,
        }
        return ToolResult(success=True, source=self.name, data=data, result_count=len(profiles))

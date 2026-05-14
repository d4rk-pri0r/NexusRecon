"""Ransomwatch — check whether target domain/org is listed on a ransomware group's leak site."""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, List

import httpx

from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool

_POSTS_URL = "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json"
_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Accept": "application/json",
}


def _org_variants(domain: str) -> List[str]:
    """Derive company-name variants from a seed domain.

    e.g. acme-corp.com → ['acme', 'corp'], acme.com → ['acme']
    Only includes parts with ≥ 4 characters.
    """
    first_label = domain.split(".")[0].lower()
    parts = [p for p in re.split(r"[-_]", first_label) if len(p) >= 4]
    if len(first_label) >= 4 and first_label not in parts:
        parts.insert(0, first_label)
    return parts


@register_tool
class RansomwatchTool(OSINTTool):
    name = "ransomwatch"
    tier = Tier.T0
    category = Category.INFRASTRUCTURE
    requires_keys = []
    description = "Check ransomwatch posts.json for target domain / org name listings"
    target_types = ["domain"]
    dynamic_trigger_hints = ["ransomware listing found", "ransomware group mention"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        domain_lower = target.lower()
        variants = _org_variants(target)
        search_terms = [domain_lower] + variants

        try:
            async with httpx.AsyncClient(headers=_HEADERS, timeout=30.0, follow_redirects=True) as client:
                resp = await client.get(_POSTS_URL)
                if resp.status_code != 200:
                    return ToolResult(
                        success=False,
                        source=self.name,
                        error=f"ransomwatch posts.json returned HTTP {resp.status_code}",
                    )
                posts = resp.json()
        except Exception as exc:
            return ToolResult(success=False, source=self.name, error=str(exc))

        listings: List[Dict[str, Any]] = []
        for post in posts:
            title = str(post.get("post_title", "")).lower()
            url = str(post.get("post_url", "")).lower()
            combined = title + " " + url
            if any(term in combined for term in search_terms):
                listings.append({
                    "group_name": post.get("group_name", ""),
                    "post_title": post.get("post_title", ""),
                    "discovered": post.get("discovered", ""),
                    "url": post.get("post_url", ""),
                })

        return ToolResult(
            success=True,
            source=self.name,
            data={
                "target": target,
                "is_listed": len(listings) > 0,
                "listings": listings,
                "list_check_date": datetime.now(timezone.utc).isoformat(),
            },
            result_count=len(listings),
        )

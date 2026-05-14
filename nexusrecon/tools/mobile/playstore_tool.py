"""Google Play Store — discover apps published by a target organization."""
from __future__ import annotations

import asyncio
from typing import Any, Dict, List

from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool


def _search_play_sync(org_name: str, seed_domain: str) -> List[Dict[str, Any]]:
    try:
        from google_play_scraper import search
    except ImportError:
        return []

    try:
        results = search(org_name, n_hits=20, lang="en", country="us")
    except Exception:
        return []

    apps = []
    for r in results:
        dev_email = r.get("developerEmail", "") or ""
        app_title = r.get("title", "") or ""
        dev_name = r.get("developer", "") or ""
        # Filter: developer email domain matches seed or title substring matches org
        org_base = org_name.lower()
        seed_base = seed_domain.split(".")[0].lower()
        if (
            seed_domain.lower() in dev_email.lower()
            or seed_base in app_title.lower()
            or seed_base in dev_name.lower()
        ):
            apps.append({
                "package": r.get("appId", ""),
                "title": app_title,
                "developer": dev_name,
                "developer_email": dev_email,
                "install_count": r.get("realInstalls", 0) or 0,
                "url": f"https://play.google.com/store/apps/details?id={r.get('appId', '')}",
                "last_updated": str(r.get("updated", "")),
            })
    return apps


@register_tool
class PlayStoreTool(OSINTTool):
    name = "playstore"
    tier = Tier.T0
    category = Category.MOBILE
    requires_keys = []
    description = "Search Google Play Store for apps associated with the target organization"
    target_types = ["domain"]
    dynamic_trigger_hints = ["mobile app found", "android developer email matches domain"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        org_name = target.split(".")[0]
        apps = await asyncio.to_thread(_search_play_sync, org_name, target)
        return ToolResult(
            success=True,
            source=self.name,
            data={"target": target, "apps": apps},
            result_count=len(apps),
        )

"""FullHunt — attack surface enumeration."""
from __future__ import annotations

from typing import Any, Dict, List

import httpx

from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool


@register_tool
class FullHuntTool(OSINTTool):
    name = "fullhunt"
    tier = Tier.T0
    category = Category.INFRASTRUCTURE
    requires_keys = ["fullhunt_api_key"]
    description = "FullHunt attack surface enumeration — subdomains, exposed ports, technologies"
    target_types = ["domain"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        key = self.config.get_secret("fullhunt_api_key")
        if not key:
            return ToolResult(success=False, source=self.name, error="FULLHUNT_API_KEY not set")

        try:
            async with httpx.AsyncClient(
                base_url="https://fullhunt.io/api/v1",
                headers={
                    "X-API-KEY": key,
                    "Accept": "application/json",
                    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
                },
                timeout=20.0,
            ) as client:
                resp = await client.get(f"/domain/{target}/subdomains")

                if resp.status_code in (401, 403):
                    return ToolResult(success=False, source=self.name, error="Invalid FullHunt API key")
                if resp.status_code == 429:
                    return ToolResult(success=False, source=self.name, error="FullHunt rate limit exceeded")
                if resp.status_code != 200:
                    return ToolResult(success=False, source=self.name, error=f"FullHunt returned {resp.status_code}")

                raw = resp.json()
                hosts: List[str] = raw.get("hosts", [])
                metadata: Dict[str, Any] = raw.get("metadata", {})

                data: Dict[str, Any] = {
                    "domain": target,
                    "total": metadata.get("total", len(hosts)),
                    "all_results": metadata.get("all_results"),
                    "hosts": hosts[:300],
                }

        except Exception as exc:
            return ToolResult(success=False, source=self.name, error=str(exc))

        return ToolResult(success=True, source=self.name, data=data, result_count=len(hosts))

"""ProjectDiscovery Chaos DB — aggregated passive subdomain data."""
from __future__ import annotations

from typing import Any

import httpx

from nexusrecon.opsec.useragent import random_ua
from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool


@register_tool
class ChaosTool(OSINTTool):
    name = "chaos"
    tier = Tier.T0
    category = Category.SUBDOMAIN
    requires_keys = ["chaos_api_key"]
    description = "ProjectDiscovery Chaos DB — aggregated passive subdomains from 11+ sources"
    target_types = ["domain"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        key = self.config.get_secret("chaos_api_key")
        if not key:
            return ToolResult(success=False, source=self.name, error="CHAOS_API_KEY not set")

        try:
            async with httpx.AsyncClient(
                base_url="https://dns.projectdiscovery.io",
                headers={
                    "Authorization": key,
                    "Accept": "application/json",
                    "User-Agent": random_ua(),
                },
                timeout=30.0,
            ) as client:
                resp = await client.get(f"/dns/{target}/subdomains")

                if resp.status_code == 401:
                    return ToolResult(success=False, source=self.name, error="Invalid Chaos API key")
                if resp.status_code == 404:
                    return ToolResult(success=True, source=self.name, data={"domain": target, "subdomains": [], "count": 0}, result_count=0)
                if resp.status_code != 200:
                    return ToolResult(success=False, source=self.name, error=f"Chaos returned {resp.status_code}")

                raw = resp.json()
                # Chaos returns prefixes only — reconstruct FQDNs
                prefixes: list[str] = raw.get("subdomains", [])
                fqdns = sorted({f"{p}.{target}" for p in prefixes if p})

                data: dict[str, Any] = {
                    "domain": target,
                    "count": raw.get("count", len(fqdns)),
                    "subdomains": fqdns,
                }

        except Exception as exc:
            return ToolResult(success=False, source=self.name, error=str(exc))

        return ToolResult(success=True, source=self.name, data=data, result_count=len(fqdns))

"""AlienVault OTX — passive subdomain enumeration and threat intel."""
from __future__ import annotations

from typing import Any, Dict, List, Set

import httpx

from nexusrecon.opsec.useragent import random_ua
from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool


@register_tool
class OTXTool(OSINTTool):
    name = "otx_subdomains"
    tier = Tier.T0
    category = Category.SUBDOMAIN
    # Key is optional — unauthenticated works but is rate-limited
    requires_keys = []
    description = "AlienVault OTX passive subdomain enumeration (no key required, key increases quota)"
    target_types = ["domain"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        otx_key = self.config.get_secret("otx_api_key")
        headers: Dict[str, str] = {
            "Accept": "application/json",
            "User-Agent": random_ua(),
        }
        if otx_key:
            headers["X-OTX-API-KEY"] = otx_key

        try:
            async with httpx.AsyncClient(
                base_url="https://otx.alienvault.com",
                headers=headers,
                timeout=20.0,
            ) as client:
                resp = await client.get(f"/api/v1/indicators/domain/{target}/passive_dns")

                if resp.status_code == 403:
                    return ToolResult(success=False, source=self.name, error="OTX access denied — set OTX_API_KEY")
                if resp.status_code == 429:
                    return ToolResult(success=False, source=self.name, error="OTX rate limit — set OTX_API_KEY for higher quota")
                if resp.status_code != 200:
                    return ToolResult(success=False, source=self.name, error=f"OTX returned {resp.status_code}")

                raw = resp.json()
                records: List[Dict[str, Any]] = raw.get("passive_dns", [])

                subdomains: Set[str] = set()
                for r in records:
                    hostname = r.get("hostname", "")
                    if hostname and (hostname == target or hostname.endswith(f".{target}")):
                        subdomains.add(hostname)

                data: Dict[str, Any] = {
                    "domain": target,
                    "subdomain_count": len(subdomains),
                    "subdomains": sorted(subdomains),
                    "raw_record_count": len(records),
                }

        except Exception as exc:
            return ToolResult(success=False, source=self.name, error=str(exc))

        return ToolResult(success=True, source=self.name, data=data, result_count=len(subdomains))

"""IntelX Phonebook — email and subdomain discovery for a domain."""
from __future__ import annotations

from typing import Any, Dict, List, Set

import httpx

from nexusrecon.opsec.useragent import random_ua
from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool


@register_tool
class PhonebookTool(OSINTTool):
    name = "phonebook"
    tier = Tier.T0
    category = Category.EMAIL
    requires_keys = ["intelx_api_key"]
    description = "IntelX Phonebook — enumerates emails and subdomains associated with a domain"
    target_types = ["domain", "email"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        key = self.config.get_secret("intelx_api_key")
        if not key:
            return ToolResult(success=False, source=self.name, error="INTELX_API_KEY not set")

        try:
            async with httpx.AsyncClient(
                base_url="https://2.intelx.io",
                headers={
                    "x-key": key,
                    "Accept": "application/json",
                    "User-Agent": random_ua(),
                },
                timeout=20.0,
            ) as client:
                resp = await client.get(
                    "/phonebook/search",
                    params={"selector": target, "maxresults": 200, "timeout": 5},
                )

                if resp.status_code in (401, 403):
                    return ToolResult(success=False, source=self.name, error="Invalid IntelX API key")
                if resp.status_code == 402:
                    return ToolResult(success=False, source=self.name, error="IntelX quota exceeded")
                if resp.status_code != 200:
                    return ToolResult(success=False, source=self.name, error=f"IntelX returned {resp.status_code}")

                raw = resp.json()
                selectors: List[Dict[str, Any]] = raw.get("selectors", [])

                emails: Set[str] = set()
                subdomains: Set[str] = set()
                for s in selectors:
                    val = s.get("selectorvalue", "")
                    if "@" in val:
                        emails.add(val)
                    elif "." in val:
                        subdomains.add(val)

                data: Dict[str, Any] = {
                    "target": target,
                    "total_selectors": len(selectors),
                    "email_count": len(emails),
                    "subdomain_count": len(subdomains),
                    "emails": sorted(emails)[:200],
                    "subdomains": sorted(subdomains)[:200],
                }

        except Exception as exc:
            return ToolResult(success=False, source=self.name, error=str(exc))

        return ToolResult(
            success=True,
            source=self.name,
            data=data,
            result_count=len(emails) + len(subdomains),
        )

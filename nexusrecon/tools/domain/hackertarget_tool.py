"""HackerTarget — free passive DNS and reverse-IP lookup."""
from __future__ import annotations

from typing import Any, Dict, List

import httpx

from nexusrecon.opsec.useragent import random_ua
from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool


@register_tool
class HackerTargetTool(OSINTTool):
    name = "hackertarget"
    tier = Tier.T0
    category = Category.DNS
    requires_keys = []
    description = "HackerTarget free passive DNS — host search and reverse-IP lookup (no key required)"
    target_types = ["domain", "ip"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        target_type = kwargs.get("target_type", "domain")

        try:
            async with httpx.AsyncClient(
                base_url="https://api.hackertarget.com",
                headers={
                    "User-Agent": random_ua(),
                    "Accept": "text/plain",
                },
                timeout=20.0,
            ) as client:
                if target_type == "ip":
                    resp = await client.get("/reverseiplookup/", params={"q": target})
                else:
                    resp = await client.get("/hostsearch/", params={"q": target})

                body = resp.text.strip()

                if resp.status_code != 200 or "API count exceeded" in body or "error" == body.lower():
                    if "API count exceeded" in body:
                        return ToolResult(success=False, source=self.name, error="HackerTarget daily request limit reached")
                    return ToolResult(success=False, source=self.name, error=f"HackerTarget returned {resp.status_code}: {body[:100]}")

                if target_type == "ip":
                    hostnames = [line.strip() for line in body.splitlines() if line.strip()]
                    data: Dict[str, Any] = {
                        "ip": target,
                        "hosted_domains": hostnames,
                        "count": len(hostnames),
                    }
                    result_count = len(hostnames)
                else:
                    entries: List[Dict[str, str]] = []
                    for line in body.splitlines():
                        line = line.strip()
                        if "," in line:
                            parts = line.split(",", 1)
                            entries.append({"hostname": parts[0].strip(), "ip": parts[1].strip()})

                    data = {
                        "domain": target,
                        "count": len(entries),
                        "hosts": entries,
                        "subdomains": [e["hostname"] for e in entries],
                    }
                    result_count = len(entries)

        except Exception as exc:
            return ToolResult(success=False, source=self.name, error=str(exc))

        return ToolResult(success=True, source=self.name, data=data, result_count=result_count)

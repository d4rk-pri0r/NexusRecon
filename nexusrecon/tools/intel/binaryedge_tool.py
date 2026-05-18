"""BinaryEdge — internet scan data for subdomains and IPs."""
from __future__ import annotations

from typing import Any, Dict, List

import httpx

from nexusrecon.opsec.useragent import random_ua
from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool


@register_tool
class BinaryEdgeTool(OSINTTool):
    name = "binaryedge"
    tier = Tier.T0
    category = Category.INFRASTRUCTURE
    requires_keys = ["binaryedge_api_key"]
    description = "BinaryEdge internet scan data — subdomains, open ports, CVE associations"
    target_types = ["domain", "ip"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        key = self.config.get_secret("binaryedge_api_key")
        if not key:
            return ToolResult(success=False, source=self.name, error="BINARYEDGE_API_KEY not set")

        target_type = kwargs.get("target_type", "domain")

        try:
            async with httpx.AsyncClient(
                base_url="https://api.binaryedge.io/v2",
                headers={
                    "X-Key": key,
                    "Accept": "application/json",
                    "User-Agent": random_ua(),
                },
                timeout=20.0,
            ) as client:
                if target_type == "ip":
                    resp = await client.get(f"/query/ip/{target}")
                else:
                    resp = await client.get(f"/query/domains/subdomain/{target}")

                if resp.status_code == 401:
                    return ToolResult(success=False, source=self.name, error="Invalid BinaryEdge API key")
                if resp.status_code == 429:
                    return ToolResult(success=False, source=self.name, error="BinaryEdge quota exceeded")
                if resp.status_code != 200:
                    return ToolResult(success=False, source=self.name, error=f"BinaryEdge returned {resp.status_code}")

                raw = resp.json()

                if target_type == "ip":
                    events = raw.get("events", [])
                    data: Dict[str, Any] = {
                        "target": target,
                        "total": raw.get("total", len(events)),
                        "services": [
                            {
                                "port": e.get("port"),
                                "proto": e.get("proto"),
                                "service": e.get("result", {}).get("data", {}).get("service", {}).get("name"),
                                "product": e.get("result", {}).get("data", {}).get("service", {}).get("product"),
                                "cpe": e.get("result", {}).get("data", {}).get("service", {}).get("cpe", []),
                                "timestamp": e.get("ts"),
                            }
                            for e in events[:50]
                        ],
                    }
                    result_count = len(events)
                else:
                    subdomains: List[str] = raw.get("events", [])
                    data = {
                        "domain": target,
                        "total": raw.get("total", len(subdomains)),
                        "page": raw.get("page", 1),
                        "subdomains": subdomains[:200],
                    }
                    result_count = len(subdomains)

        except Exception as exc:
            return ToolResult(success=False, source=self.name, error=str(exc))

        return ToolResult(success=True, source=self.name, data=data, result_count=result_count)

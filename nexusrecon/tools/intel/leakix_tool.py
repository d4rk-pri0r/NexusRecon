"""LeakIX — exposed services with attached vulnerability context."""
from __future__ import annotations

from typing import Any

import httpx

from nexusrecon.opsec.useragent import random_ua
from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool


@register_tool
class LeakIXTool(OSINTTool):
    name = "leakix"
    tier = Tier.T0
    category = Category.INFRASTRUCTURE
    # Key is optional — unauthenticated returns basic results
    requires_keys = []
    description = (
        "LeakIX — exposed services with vulnerability context; uniquely surfaces "
        "misconfigurations and CVEs directly attached to discovered hosts"
    )
    target_types = ["domain", "ip"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        key = self.config.get_secret("leakix_api_key")
        headers: dict[str, str] = {
            "Accept": "application/json",
            "User-Agent": random_ua(),
        }
        if key:
            headers["api-key"] = key

        target_type = kwargs.get("target_type", "domain")
        query = f"host:{target}" if target_type == "ip" else f"domain:{target}"

        try:
            async with httpx.AsyncClient(
                base_url="https://leakix.net",
                headers=headers,
                timeout=20.0,
            ) as client:
                resp = await client.get(
                    "/api/search",
                    params={"q": query, "scope": "service", "page": 0},
                )

                if resp.status_code == 401:
                    return ToolResult(success=False, source=self.name, error="Invalid LeakIX API key")
                if resp.status_code == 429:
                    return ToolResult(success=False, source=self.name, error="LeakIX rate limit — set LEAKIX_API_KEY")
                if resp.status_code == 404:
                    return ToolResult(success=True, source=self.name, data={"query": query, "results": []}, result_count=0)
                if resp.status_code != 200:
                    return ToolResult(success=False, source=self.name, error=f"LeakIX returned {resp.status_code}")

                items: list[dict[str, Any]] = resp.json() or []
                results = []
                for item in items[:50]:
                    cves = [
                        {"id": c.get("name"), "score": c.get("score")}
                        for c in item.get("LeakSeverity", {}).get("CVEs", [])
                        if c.get("name")
                    ]
                    results.append({
                        "ip": item.get("ip"),
                        "port": item.get("port"),
                        "protocol": item.get("protocol"),
                        "service": item.get("service", {}).get("software", {}).get("name"),
                        "version": item.get("service", {}).get("software", {}).get("version"),
                        "country": item.get("geoip", {}).get("country_name"),
                        "leak_severity": item.get("LeakSeverity", {}).get("Score"),
                        "cves": cves,
                        "has_vulnerability": len(cves) > 0,
                        "summary": item.get("summary", "")[:200],
                        "event_type": item.get("event_type"),
                        "timestamp": item.get("time"),
                    })

                data: dict[str, Any] = {
                    "query": query,
                    "result_count": len(results),
                    "results": results,
                    "cve_hits": sum(1 for r in results if r["has_vulnerability"]),
                }

        except Exception as exc:
            return ToolResult(success=False, source=self.name, error=str(exc))

        return ToolResult(success=True, source=self.name, data=data, result_count=len(results))

"""ZoomEye — internet scan intelligence from China-region vantage point."""
from __future__ import annotations

from typing import Any, Dict, List

import httpx

from nexusrecon.opsec.useragent import random_ua
from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool


@register_tool
class ZoomEyeTool(OSINTTool):
    name = "zoomeye"
    tier = Tier.T0
    category = Category.INFRASTRUCTURE
    requires_keys = ["zoomeye_api_key"]
    description = "ZoomEye internet scan data — host/service discovery from China-region vantage point"
    target_types = ["domain", "ip"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        key = self.config.get_secret("zoomeye_api_key")
        if not key:
            return ToolResult(success=False, source=self.name, error="ZOOMEYE_API_KEY not set")

        target_type = kwargs.get("target_type", "domain")
        query = f"ip:{target}" if target_type == "ip" else f"hostname:{target}"

        try:
            async with httpx.AsyncClient(
                base_url="https://api.zoomeye.org",
                headers={
                    "API-KEY": key,
                    "Accept": "application/json",
                    "User-Agent": random_ua(),
                },
                timeout=20.0,
            ) as client:
                resp = await client.get(
                    "/host/search",
                    params={"query": query, "page": 1},
                )

                if resp.status_code in (401, 403):
                    return ToolResult(success=False, source=self.name, error="Invalid ZoomEye API key")
                if resp.status_code == 429:
                    return ToolResult(success=False, source=self.name, error="ZoomEye quota exceeded")
                if resp.status_code != 200:
                    return ToolResult(success=False, source=self.name, error=f"ZoomEye returned {resp.status_code}")

                raw = resp.json()

                # Non-200 logical errors are returned with code != 60000
                if raw.get("code") and raw["code"] != 60000:
                    return ToolResult(
                        success=False, source=self.name,
                        error=f"ZoomEye error {raw.get('code')}: {raw.get('message')}",
                    )

                matches: List[Dict[str, Any]] = raw.get("matches", [])
                data: Dict[str, Any] = {
                    "query": query,
                    "total": raw.get("total", len(matches)),
                    "hosts": [
                        {
                            "ip": m.get("ip"),
                            "port": m.get("portinfo", {}).get("port"),
                            "proto": m.get("portinfo", {}).get("transport"),
                            "service": m.get("portinfo", {}).get("service"),
                            "app": m.get("portinfo", {}).get("app"),
                            "version": m.get("portinfo", {}).get("version"),
                            "country": m.get("geoinfo", {}).get("country", {}).get("names", {}).get("en"),
                            "city": m.get("geoinfo", {}).get("city", {}).get("names", {}).get("en"),
                            "timestamp": m.get("timestamp"),
                        }
                        for m in matches[:50]
                    ],
                }

        except Exception as exc:
            return ToolResult(success=False, source=self.name, error=str(exc))

        return ToolResult(success=True, source=self.name, data=data, result_count=len(matches))

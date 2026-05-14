"""urlscan.io historical scan correlation tool."""
from __future__ import annotations
from typing import Any, Dict, Optional
import httpx
from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool


@register_tool
class URLScanTool(OSINTTool):
    name = "urlscan"
    tier = Tier.T0
    category = Category.INFRASTRUCTURE
    requires_keys = []
    description = "urlscan.io historical scan data and screenshot correlation"
    target_types = ["domain"]
    dynamic_trigger_hints = ["malicious url found", "phishing page detected"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        key = self.config.get_secret("urlscan_api_key")
        try:
            headers = {}
            if key:
                headers["API-Key"] = key

            client = httpx.AsyncClient(
                base_url="https://urlscan.io/api/v1",
                headers=headers,
                timeout=15.0,
            )

            # Search scans for domain
            resp = await client.get("/search/", params={"q": f"domain:{target}", "size": 50})

            data = {}
            if resp.status_code == 200:
                r = resp.json()
                results = []
                for hit in r.get("results", [])[:20]:
                    task = hit.get("task", {})
                    page = hit.get("page", {})
                    results.append({
                        "scan_url": page.get("url"),
                        "scan_date": hit.get("task", {}).get("time"),
                        "screenshot_url": hit.get("screenshot"),
                        "ip": page.get("ip"),
                        "country": page.get("country"),
                        "server": page.get("server"),
                        "title": page.get("title"),
                        "status": page.get("status"),
                    })
                data = {"total": r.get("total", 0), "scans": results}

            await client.aclose()
            return ToolResult(
                success=True, source=self.name, data=data,
                result_count=len(data.get("scans", [])),
            )
        except Exception as e:
            return ToolResult(success=False, source=self.name, error=str(e))

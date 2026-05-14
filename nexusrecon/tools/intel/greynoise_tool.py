"""GreyNoise API tool — IP noise context."""
from __future__ import annotations
from typing import Any, Dict, Optional
import httpx
from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool


@register_tool
class GreyNoiseTool(OSINTTool):
    name = "greynoise"
    tier = Tier.T0
    category = Category.INFRASTRUCTURE
    requires_keys = ["greynoise_api_key"]
    description = "GreyNoise IP classification (benign, malicious, unknown)"
    target_types = ["ip"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        key = self.config.get_secret("greynoise_api_key")
        if not key:
            return ToolResult(success=False, source=self.name, error="GREYNOISE_API_KEY not set")

        try:
            client = httpx.AsyncClient(
                base_url="https://api.greynoise.io",
                headers={"key": key},
                timeout=15.0,
            )

            # Quick check
            resp = await client.get("/v2/noise/quick", params={"ip": target})
            data = {}
            if resp.status_code == 200:
                r = resp.json()
                data = {
                    "ip": r.get("ip"),
                    "classification": r.get("classification"),  # benign, malicious, unknown
                    "noise": r.get("noise", False),
                    "riot": r.get("riot", False),
                    "name": r.get("name"),
                    "last_seen": r.get("last_seen"),
                    "cve": r.get("cve", []),
                    "tags": r.get("tags", []),
                    "actor": r.get("actor"),
                    "actor_type": r.get("actor_type"),
                }

            await client.aclose()
            return ToolResult(success=True, source=self.name, data=data, result_count=1)
        except Exception as e:
            return ToolResult(success=False, source=self.name, error=str(e))

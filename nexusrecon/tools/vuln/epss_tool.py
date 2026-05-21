"""EPSS (Exploit Prediction Scoring System) tool."""
from __future__ import annotations

from typing import Any

import httpx

from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool


@register_tool
class EPSSTool(OSINTTool):
    name = "epss"
    tier = Tier.T0
    category = Category.VULNERABILITY
    requires_keys = []
    description = "EPSS exploit prediction scores for CVEs"
    target_types = ["cve"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        try:
            client = httpx.AsyncClient(
                base_url="https://api.first.org/data/v1",
                timeout=10.0,
            )

            resp = await client.get("/epss", params={"cve": target})
            if resp.status_code == 200:
                data = resp.json()
                entries = data.get("data", [])
                if entries:
                    e = entries[0]
                    epss_score = float(e.get("epss", 0))
                    percentile = float(e.get("percentile", 0))
                    return ToolResult(
                        success=True, source=self.name,
                        data={
                            "cve": e.get("cve"),
                            "epss_score": epss_score,
                            "percentile": percentile,
                            "date": e.get("date"),
                        },
                        result_count=1,
                    )

            await client.aclose()
            return ToolResult(success=False, source=self.name, error="No EPSS data found")
        except Exception as e:
            return ToolResult(success=False, source=self.name, error=str(e))

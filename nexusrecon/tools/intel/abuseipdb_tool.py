"""AbuseIPDB tool — IP reputation and abuse reporting."""
from __future__ import annotations
from typing import Any, Dict, Optional
import httpx
from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool


@register_tool
class AbuseIPDBTool(OSINTTool):
    name = "abuseipdb"
    tier = Tier.T0
    category = Category.INFRASTRUCTURE
    requires_keys = ["abuseipdb_api_key"]
    description = "IP reputation scoring via AbuseIPDB"
    target_types = ["ip"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        key = self.config.get_secret("abuseipdb_api_key")
        if not key:
            return ToolResult(success=False, source=self.name, error="ABUSEIPDB_API_KEY not set")

        try:
            client = httpx.AsyncClient(
                base_url="https://api.abuseipdb.com/api/v2",
                headers={"Key": key, "Accept": "application/json"},
                timeout=10.0,
            )

            resp = await client.get("/check", params={
                "ipAddress": target,
                "maxAgeInDays": 90,
            })

            data = {}
            if resp.status_code == 200:
                r = resp.json().get("data", {})
                data = {
                    "ip": r.get("ipAddress"),
                    "abuse_score": r.get("abuseConfidenceScore"),
                    "total_reports": r.get("totalReports"),
                    "last_reported": r.get("lastReportedAt"),
                    "is_whitelisted": r.get("isWhitelisted"),
                    "country": r.get("countryCode"),
                    "isp": r.get("isp"),
                    "usage_type": r.get("usageType"),
                    "domains": r.get("domain"),
                    "reports": [
                        {
                            "comment": rep.get("comment", "")[:200],
                            "category": rep.get("categories", []),
                            "reported_at": rep.get("reportedAt"),
                        }
                        for rep in r.get("reports", [])[:10]
                    ],
                }

            await client.aclose()
            return ToolResult(
                success=True, source=self.name, data=data, result_count=1,
            )
        except Exception as e:
            return ToolResult(success=False, source=self.name, error=str(e))

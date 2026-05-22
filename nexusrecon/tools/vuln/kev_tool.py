"""CISA Known Exploited Vulnerabilities (KEV) catalog tool."""
from __future__ import annotations

from typing import Any

import httpx

from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool


@register_tool
class KEVTool(OSINTTool):
    name = "kev"
    tier = Tier.T0
    category = Category.VULNERABILITY
    requires_keys = []
    description = "CISA Known Exploited Vulnerabilities cross-reference"
    target_types = ["cve", "product"]
    dynamic_trigger_hints = ["known exploited vulnerability found", "cve detected"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        try:
            kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
            client = httpx.AsyncClient(timeout=15.0, follow_redirects=True)
            resp = await client.get(kev_url)

            if resp.status_code != 200:
                return ToolResult(success=False, source=self.name, error="Failed to fetch KEV catalog")

            catalog = resp.json()
            vulns = catalog.get("vulnerabilities", [])

            # Filter by target
            if target.startswith("CVE-"):
                matches = [v for v in vulns if v.get("cveID") == target]
            else:
                matches = [
                    v for v in vulns
                    if target.lower() in v.get("vendorProject", "").lower()
                    or target.lower() in v.get("product", "").lower()
                    or target.lower() in v.get("shortDescription", "").lower()
                ]

            data = {
                "total_kev": len(vulns),
                "matches": [
                    {
                        "cve_id": v.get("cveID"),
                        "vendor": v.get("vendorProject"),
                        "product": v.get("product"),
                        "description": v.get("shortDescription", "")[:200],
                        "date_added": v.get("dateAdded"),
                        "due_date": v.get("requiredAction"),
                        "known_ransom_campaign": v.get("knownRansomwareCampaignUse", "Unknown"),
                    }
                    for v in matches
                ],
                "catalog_date": catalog.get("dateReleased", ""),
            }

            await client.aclose()
            return ToolResult(
                success=True, source=self.name, data=data,
                result_count=len(matches),
            )
        except Exception as e:
            return ToolResult(success=False, source=self.name, error=str(e))

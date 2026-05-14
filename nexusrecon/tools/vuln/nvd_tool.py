"""NVD CVE search tool."""
from __future__ import annotations
from typing import Any, Dict, List, Optional
import httpx
from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool


@register_tool
class NVDTool(OSINTTool):
    name = "nvd"
    tier = Tier.T0
    category = Category.VULNERABILITY
    requires_keys = []
    description = "NVD CVE lookup and search"
    target_types = ["cve", "product"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        try:
            client = httpx.AsyncClient(
                base_url="https://services.nvd.nist.gov/rest/json/cves/2.0",
                timeout=15.0,
            )

            # Headers required by NVD API
            client.headers["User-Agent"] = "NexusRecon/1.0"

            if target.startswith("CVE-"):
                params = {"cveId": target}
            elif kwargs.get("product"):
                params = {"keywordSearch": target, "resultsPerPage": 20}
            else:
                params = {"keywordSearch": target, "resultsPerPage": 20}

            resp = await client.get("", params=params)
            data = {}
            if resp.status_code == 200:
                r = resp.json()
                vulnerabilities = r.get("vulnerabilities", [])
                data = {
                    "total": r.get("totalResults", 0),
                    "vulns": [
                        {
                            "cve_id": v.get("cve", {}).get("id"),
                            "description": v.get("cve", {}).get("descriptions", [{}])[0].get("value", "")[:300],
                            "cvss": v.get("cve", {}).get("metrics", {}),
                            "published": v.get("cve", {}).get("published"),
                            "modified": v.get("cve", {}).get("lastModified"),
                            "references": [
                                ref.get("url") for ref in v.get("cve", {}).get("references", [])[:10]
                            ],
                        }
                        for v in vulnerabilities[:20]
                    ],
                }

            await client.aclose()
            return ToolResult(
                success=True, source=self.name, data=data,
                result_count=data.get("total", 0),
            )
        except Exception as e:
            return ToolResult(success=False, source=self.name, error=str(e))

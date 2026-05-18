"""Vulners — aggregated exploit and vulnerability intelligence."""
from __future__ import annotations

from typing import Any, Dict, List

import httpx

from nexusrecon.opsec.useragent import random_ua
from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool


@register_tool
class VulnersTool(OSINTTool):
    name = "vulners"
    tier = Tier.T0
    category = Category.VULNERABILITY
    requires_keys = ["vulners_api_key"]
    description = "Vulners aggregated exploit database — CVE enrichment with PoC, Metasploit, and AI score"
    target_types = ["cve"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        key = self.config.get_secret("vulners_api_key")
        if not key:
            return ToolResult(success=False, source=self.name, error="VULNERS_API_KEY not set")

        cve_id = target.upper()

        try:
            async with httpx.AsyncClient(
                base_url="https://vulners.com",
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                    "User-Agent": random_ua(),
                },
                timeout=15.0,
            ) as client:
                resp = await client.post(
                    "/api/v3/search/lucene/",
                    json={
                        "query": f"cvelist:{cve_id}",
                        "apiKey": key,
                        "size": 20,
                        "fields": [
                            "id", "title", "type", "published",
                            "cvss", "cvss3", "vhref", "description",
                        ],
                    },
                )

                if resp.status_code in (401, 403):
                    return ToolResult(success=False, source=self.name, error="Invalid Vulners API key")
                if resp.status_code == 429:
                    return ToolResult(success=False, source=self.name, error="Vulners rate limit exceeded")
                if resp.status_code != 200:
                    return ToolResult(success=False, source=self.name, error=f"Vulners returned {resp.status_code}")

                raw = resp.json()
                if raw.get("result") != "OK":
                    err = raw.get("data", {}).get("error", "Unknown Vulners error")
                    return ToolResult(success=False, source=self.name, error=err)

                docs: List[Dict[str, Any]] = raw.get("data", {}).get("search", [])
                exploits: List[Dict[str, Any]] = []
                patches: List[Dict[str, Any]] = []
                references: List[Dict[str, Any]] = []

                for doc in docs:
                    src = doc.get("_source", {})
                    doc_type = src.get("type", "")
                    cvss_raw = src.get("cvss")
                    entry: Dict[str, Any] = {
                        "id": src.get("id"),
                        "title": src.get("title"),
                        "type": doc_type,
                        "published": src.get("published"),
                        "href": src.get("vhref"),
                        "cvss": cvss_raw.get("score") if isinstance(cvss_raw, dict) else cvss_raw,
                    }
                    if doc_type in ("exploitdb", "metasploit", "packetstorm", "exploit"):
                        exploits.append(entry)
                    elif doc_type in ("patch", "fix"):
                        patches.append(entry)
                    else:
                        references.append(entry)

                data: Dict[str, Any] = {
                    "cve": cve_id,
                    "exploit_count": len(exploits),
                    "has_public_exploit": len(exploits) > 0,
                    "has_metasploit": any(e["type"] == "metasploit" for e in exploits),
                    "exploits": exploits[:10],
                    "patches": patches[:5],
                    "references": references[:10],
                }

        except Exception as exc:
            return ToolResult(success=False, source=self.name, error=str(exc))

        return ToolResult(
            success=True, source=self.name, data=data,
            result_count=len(exploits),
        )

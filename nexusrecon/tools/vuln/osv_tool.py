"""OSV.dev — Google open-source vulnerability database."""
from __future__ import annotations

from typing import Any, Dict, List, Set

import httpx

from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool


@register_tool
class OSVTool(OSINTTool):
    name = "osv"
    tier = Tier.T0
    category = Category.VULNERABILITY
    requires_keys = []
    description = "OSV.dev — open-source vuln DB covering npm, PyPI, Go, Cargo, Maven, and more by CVE"
    target_types = ["cve"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        cve_id = target.upper()

        try:
            async with httpx.AsyncClient(
                base_url="https://api.osv.dev/v1",
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
                },
                timeout=15.0,
            ) as client:
                resp = await client.post("/query", json={"cves": [cve_id]})

                if resp.status_code != 200:
                    return ToolResult(
                        success=False, source=self.name,
                        error=f"OSV returned {resp.status_code}",
                    )

                raw = resp.json()
                vulns: List[Dict[str, Any]] = raw.get("vulns", [])

                parsed: List[Dict[str, Any]] = []
                for v in vulns:
                    affected: List[Dict[str, Any]] = []
                    for aff in v.get("affected", [])[:10]:
                        pkg = aff.get("package", {})
                        fixed_versions: List[str] = []
                        for r in aff.get("ranges", []):
                            for event in r.get("events", []):
                                if "fixed" in event:
                                    fixed_versions.append(event["fixed"])
                        affected.append({
                            "ecosystem": pkg.get("ecosystem"),
                            "package": pkg.get("name"),
                            "fixed_versions": fixed_versions,
                        })

                    severity_list: List[Dict[str, Any]] = v.get("severity", [])
                    parsed.append({
                        "id": v.get("id"),
                        "summary": v.get("summary"),
                        "severity_score": severity_list[0].get("score") if severity_list else None,
                        "published": v.get("published"),
                        "modified": v.get("modified"),
                        "aliases": v.get("aliases", []),
                        "affected_packages": affected,
                        "references": [r.get("url") for r in v.get("references", [])[:5]],
                    })

                ecosystems: Set[str] = {
                    a["ecosystem"]
                    for v in parsed
                    for a in v.get("affected_packages", [])
                    if a.get("ecosystem")
                }

                data: Dict[str, Any] = {
                    "cve": cve_id,
                    "vuln_count": len(parsed),
                    "ecosystems": sorted(ecosystems),
                    "vulns": parsed,
                }

        except Exception as exc:
            return ToolResult(success=False, source=self.name, error=str(exc))

        return ToolResult(success=True, source=self.name, data=data, result_count=len(parsed))

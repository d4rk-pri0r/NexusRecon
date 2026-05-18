"""GitHub Security Advisory (GHSA) — package-level vulnerability data by CVE."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

import httpx

from nexusrecon.opsec.useragent import random_ua
from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool


@register_tool
class GitHubAdvisoryTool(OSINTTool):
    name = "github_advisory"
    tier = Tier.T0
    category = Category.VULNERABILITY
    # Works unauthenticated (60 req/hr); GITHUB_TOKEN raises to 5000/hr
    requires_keys = []
    description = "GitHub Security Advisory DB (GHSA) — package-level CVE data with affected/patched versions"
    target_types = ["cve"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        cve_id = target.upper()
        token = self.config.get_secret("github_token")

        headers: Dict[str, str] = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": random_ua(),
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"

        try:
            async with httpx.AsyncClient(
                base_url="https://api.github.com",
                headers=headers,
                timeout=15.0,
            ) as client:
                resp = await client.get("/advisories", params={"cve_id": cve_id, "per_page": 10})

                if resp.status_code == 429 or resp.status_code == 403:
                    return ToolResult(
                        success=False, source=self.name,
                        error="GitHub rate limit exceeded — set GITHUB_TOKEN for higher quota",
                    )
                if resp.status_code != 200:
                    return ToolResult(
                        success=False, source=self.name,
                        error=f"GitHub Advisory returned {resp.status_code}",
                    )

                advisories: List[Dict[str, Any]] = resp.json()
                parsed: List[Dict[str, Any]] = []

                for adv in advisories:
                    cvss = adv.get("cvss") or {}
                    parsed.append({
                        "ghsa_id": adv.get("ghsa_id"),
                        "summary": adv.get("summary"),
                        "severity": adv.get("severity"),
                        "cvss_score": cvss.get("score"),
                        "cvss_vector": cvss.get("vector_string"),
                        "published": adv.get("published_at"),
                        "updated": adv.get("updated_at"),
                        "cwes": [c.get("cwe_id") for c in adv.get("cwes", [])],
                        "affected_packages": [
                            {
                                "ecosystem": p.get("package", {}).get("ecosystem"),
                                "name": p.get("package", {}).get("name"),
                                "vulnerable_versions": p.get("vulnerable_version_range"),
                                "patched_versions": p.get("patched_versions"),
                                "first_patched": p.get("first_patched_version"),
                            }
                            for p in adv.get("vulnerabilities", [])[:10]
                        ],
                        "references": [r.get("url") for r in adv.get("references", [])[:5]],
                        "url": adv.get("html_url"),
                    })

                data: Dict[str, Any] = {
                    "cve": cve_id,
                    "advisory_count": len(parsed),
                    "advisories": parsed,
                }

        except Exception as exc:
            return ToolResult(success=False, source=self.name, error=str(exc))

        return ToolResult(success=True, source=self.name, data=data, result_count=len(parsed))

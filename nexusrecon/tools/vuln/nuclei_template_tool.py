"""Nuclei template existence check — is there a ready-to-run template for this CVE?"""
from __future__ import annotations

from typing import Any, Dict, List

import httpx

from nexusrecon.opsec.useragent import random_ua
from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool


@register_tool
class NucleiTemplateTool(OSINTTool):
    name = "nuclei_template"
    tier = Tier.T0
    category = Category.VULNERABILITY
    # Works unauthenticated; GITHUB_TOKEN gives 5000 req/hr vs 60
    requires_keys = []
    description = (
        "Nuclei template lookup — checks projectdiscovery/nuclei-templates for a ready-to-run "
        "CVE template and provides the exact nuclei command to run"
    )
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
                resp = await client.get(
                    "/search/code",
                    params={
                        "q": f"{cve_id} repo:projectdiscovery/nuclei-templates",
                        "per_page": 10,
                    },
                )

                if resp.status_code in (403, 429):
                    return ToolResult(
                        success=False, source=self.name,
                        error="GitHub rate limit exceeded — set GITHUB_TOKEN for higher quota",
                    )
                if resp.status_code != 200:
                    return ToolResult(
                        success=False, source=self.name,
                        error=f"GitHub returned {resp.status_code}",
                    )

                items: List[Dict[str, Any]] = resp.json().get("items", [])
                templates: List[Dict[str, Any]] = [
                    {
                        "name": item.get("name"),
                        "path": item.get("path"),
                        "url": item.get("html_url"),
                    }
                    for item in items
                ]

                # Build the nuclei run hint from the first template path found
                run_hint: str | None = None
                if templates:
                    first_path = templates[0]["path"]
                    run_hint = f"nuclei -u <target> -t {first_path}"

                data: Dict[str, Any] = {
                    "cve": cve_id,
                    "has_template": len(templates) > 0,
                    "template_count": len(templates),
                    "templates": templates,
                    "nuclei_run_hint": run_hint,
                }

        except Exception as exc:
            return ToolResult(success=False, source=self.name, error=str(exc))

        return ToolResult(
            success=True, source=self.name, data=data,
            result_count=len(templates),
        )

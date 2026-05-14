"""Docker Hub org repo enumeration tool."""
from __future__ import annotations
from typing import Any, Dict, List, Optional
import httpx
from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool


@register_tool
class DockerHubTool(OSINTTool):
    name = "dockerhub"
    tier = Tier.T0
    category = Category.CODE
    requires_keys = []
    description = "Docker Hub org repo listing and image metadata extraction"
    target_types = ["domain"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        try:
            client = httpx.AsyncClient(base_url="https://hub.docker.com", timeout=10.0)
            org = target.split(".")[0].lower()
            repos = []
            page = 1

            while True:
                resp = await client.get(f"/v2/repositories/{org}/", params={"page": page, "page_size": 100})
                if resp.status_code != 200:
                    break
                data = resp.json()
                results = data.get("results", [])
                if not results:
                    break
                for r in results:
                    repos.append({
                        "name": r.get("name"),
                        "full_name": r.get("full_name"),
                        "description": r.get("description"),
                        "pull_count": r.get("pull_count"),
                        "star_count": r.get("star_count"),
                        "last_updated": r.get("last_updated"),
                        "is_private": r.get("is_private"),
                    })
                if not data.get("next"):
                    break
                page += 1

            await client.aclose()
            return ToolResult(
                success=True, source=self.name, data={"repos": repos},
                result_count=len(repos),
            )
        except Exception as e:
            return ToolResult(success=False, source=self.name, error=str(e))

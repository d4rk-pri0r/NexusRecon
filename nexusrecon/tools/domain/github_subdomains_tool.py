"""GitHub subdomain discovery — finds subdomain mentions in public repositories."""
from __future__ import annotations

import re
from typing import Any, Dict, List, Set

import httpx

from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool


@register_tool
class GitHubSubdomainsTool(OSINTTool):
    name = "github_subdomains"
    tier = Tier.T0
    category = Category.SUBDOMAIN
    requires_keys = ["github_token"]
    description = "GitHub code search for subdomain mentions in public repositories"
    target_types = ["domain"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        token = self.config.get_secret("github_token")
        if not token:
            return ToolResult(success=False, source=self.name, error="GITHUB_TOKEN not set")

        # Regex to extract subdomains from text snippets
        sub_pattern = re.compile(
            r'((?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+' + re.escape(target) + r')',
            re.IGNORECASE,
        )

        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
        }

        subdomains: Set[str] = set()
        sources: List[Dict[str, str]] = []

        try:
            async with httpx.AsyncClient(
                base_url="https://api.github.com",
                headers=headers,
                timeout=20.0,
            ) as client:
                # Search across config/env/yaml/txt files that tend to contain hostnames
                for query in [
                    f'"{target}" extension:yaml',
                    f'"{target}" extension:env',
                    f'"{target}" extension:conf',
                ]:
                    resp = await client.get(
                        "/search/code",
                        params={"q": query, "per_page": 30},
                    )
                    if resp.status_code == 403 or resp.status_code == 429:
                        break
                    if resp.status_code != 200:
                        continue

                    for item in resp.json().get("items", []):
                        for match_obj in item.get("text_matches", []):
                            fragment = match_obj.get("fragment", "")
                            for found in sub_pattern.findall(fragment):
                                sub = found.lower().rstrip(".")
                                if sub != target:
                                    subdomains.add(sub)
                                    sources.append({
                                        "subdomain": sub,
                                        "repo": item.get("repository", {}).get("full_name"),
                                        "file": item.get("path"),
                                    })

        except Exception as exc:
            return ToolResult(success=False, source=self.name, error=str(exc))

        data: Dict[str, Any] = {
            "domain": target,
            "subdomain_count": len(subdomains),
            "subdomains": sorted(subdomains),
            "sources": sources[:50],
        }
        return ToolResult(success=True, source=self.name, data=data, result_count=len(subdomains))

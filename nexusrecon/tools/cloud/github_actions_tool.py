"""GitHub Actions workflow analysis — leaked secrets and infrastructure patterns."""
from __future__ import annotations

import re
from typing import Any

import httpx

from nexusrecon.opsec.useragent import random_ua
from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool

# Patterns indicating leaked credentials or internal infra in workflow files
_SECRET_PATTERNS = [
    (re.compile(r'AWS_ACCESS_KEY_ID\s*[:=]\s*([A-Z0-9]{20})', re.I), "aws_access_key"),
    (re.compile(r'AWS_ACCOUNT_ID\s*[:=]\s*([0-9]{12})', re.I), "aws_account_id"),
    (re.compile(r'(?:password|passwd|secret|token|api_key|apikey)\s*[:=]\s*([^\s\n${}]{8,})', re.I), "credential"),
    (re.compile(r'https?://([a-zA-Z0-9.-]+\.(?:internal|corp|local|intranet))', re.I), "internal_host"),
    (re.compile(r'([a-zA-Z0-9.-]+\.(amazonaws\.com|azure\.com|googleapis\.com))', re.I), "cloud_endpoint"),
]


@register_tool
class GitHubActionsTool(OSINTTool):
    name = "github_actions_leaks"
    tier = Tier.T0
    category = Category.CODE
    requires_keys = ["github_token"]
    description = "GitHub Actions workflow analysis — finds leaked secrets and internal infrastructure patterns"
    target_types = ["domain"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        token = self.config.get_secret("github_token")
        if not token:
            return ToolResult(success=False, source=self.name, error="GITHUB_TOKEN not set")

        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": random_ua(),
        }

        findings: list[dict[str, Any]] = []
        workflows_reviewed: list[str] = []

        try:
            async with httpx.AsyncClient(
                base_url="https://api.github.com",
                headers=headers,
                timeout=20.0,
            ) as client:
                # Search for workflow files mentioning the target domain
                search_resp = await client.get(
                    "/search/code",
                    params={
                        "q": f"{target} path:.github/workflows",
                        "per_page": 20,
                    },
                )
                if search_resp.status_code == 403:
                    return ToolResult(success=False, source=self.name, error="GitHub rate limit — increase quota with GITHUB_TOKEN")
                if search_resp.status_code != 200:
                    return ToolResult(success=False, source=self.name, error=f"GitHub returned {search_resp.status_code}")

                for item in search_resp.json().get("items", []):
                    item.get("url")
                    repo = item.get("repository", {}).get("full_name", "")
                    path = item.get("path", "")
                    workflows_reviewed.append(f"{repo}/{path}")

                    # Fetch raw file content
                    raw_resp = await client.get(
                        item.get("url", ""),
                        headers={**headers, "Accept": "application/vnd.github.raw+json"},
                    )
                    if raw_resp.status_code != 200:
                        continue

                    content = raw_resp.text
                    for pattern, label in _SECRET_PATTERNS:
                        for match in pattern.finditer(content):
                            value = match.group(1) if match.lastindex else match.group(0)
                            # Redact actual credential values — surface existence, not cleartext
                            if label == "credential":
                                value = value[:3] + "***"
                            findings.append({
                                "type": label,
                                "value": value,
                                "repo": repo,
                                "file": path,
                                "url": item.get("html_url"),
                                "context": content[max(0, match.start() - 50):match.end() + 50].replace("\n", " "),
                            })

        except Exception as exc:
            return ToolResult(success=False, source=self.name, error=str(exc))

        data: dict[str, Any] = {
            "target": target,
            "workflows_reviewed": workflows_reviewed,
            "finding_count": len(findings),
            "findings": findings[:100],
            "types_found": list({f["type"] for f in findings}),
        }
        return ToolResult(success=True, source=self.name, data=data, result_count=len(findings))

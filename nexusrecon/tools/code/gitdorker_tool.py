"""gitdorker tool — automated GitHub dork scanning."""
from __future__ import annotations
import asyncio
import time
from typing import Any, Dict, List, Optional
import httpx
from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool

CURATED_DORKS = [
    ('"access_key"', 'AWS Access Keys'),
    ('"secret_key"', 'AWS Secret Keys'),
    ('"api_key"', 'API Keys'),
    ('"auth_token"', 'Auth Tokens'),
    ('"client_secret"', 'Client Secrets'),
    ('"database_password"', 'Database Passwords'),
    ('"db_password"', 'Database Passwords'),
    ('"password"', 'Hardcoded Passwords'),
    ('"private_key"', 'Private Keys'),
    ('"BEGIN RSA PRIVATE KEY"', 'RSA Private Keys'),
    ('"BEGIN OPENSSH"', 'SSH Private Keys'),
    ('connection_string', 'Connection Strings'),
    ('"jdbc:"', 'JDBC URLs'),
    ('"mongodb://"', 'MongoDB Connection Strings'),
    ('"postgres://"', 'PostgreSQL Connection Strings'),
    ('"slack_token"', 'Slack Tokens'),
    ('"stripe"', 'Stripe Keys'),
    ('"twilio"', 'Twilio Keys'),
    ('"sendgrid"', 'SendGrid Keys'),
    ('"mailchimp"', 'Mailchimp Keys'),
]


@register_tool
class GitDorkerTool(OSINTTool):
    name = "gitdorker"
    tier = Tier.T0
    category = Category.SECRET
    requires_keys = ["github_token"]
    description = "Curated GitHub dork scanning for leaked secrets"
    target_types = ["domain", "github_org"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        token = self.config.get_secret("github_token")
        if not token:
            return ToolResult(success=False, source=self.name, error="GITHUB_TOKEN not set")

        try:
            client = httpx.AsyncClient(
                base_url="https://api.github.com",
                headers={
                    "Authorization": f"token {token}",
                    "Accept": "application/vnd.github+json",
                },
                timeout=10.0,
            )

            results = []
            for dork, description in CURATED_DORKS:
                q = f'{dork} org:{target}' if not target.startswith("http") else f'{dork} "{target}"'
                resp = await client.get("/search/code", params={"q": q, "per_page": 1})
                time.sleep(1.1)
                if resp.status_code == 200:
                    data = resp.json()
                    total = data.get("total_count", 0)
                    if total > 0:
                        results.append({
                            "dork": dork, "description": description,
                            "total": total,
                        })

            await client.aclose()
            return ToolResult(
                success=True, source=self.name, data={"dork_results": results},
                result_count=sum(r["total"] for r in results),
            )
        except Exception as e:
            return ToolResult(success=False, source=self.name, error=str(e))

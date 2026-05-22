"""Subdomain takeover detection — CNAME fingerprinting + HTTP probe."""
from __future__ import annotations

import asyncio
from typing import Any

import dns.asyncresolver
import httpx

from nexusrecon.opsec.useragent import random_ua
from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool

_HEADERS = {
    "User-Agent": random_ua(),
    "Accept": "text/html,application/xhtml+xml",
}

TAKEOVER_FINGERPRINTS = [
    {"service": "S3 Bucket", "cname_contains": "s3.amazonaws.com", "body_contains": "NoSuchBucket"},
    {"service": "GitHub Pages", "cname_contains": "github.io", "body_contains": "There isn't a GitHub Pages site here"},
    {"service": "Heroku", "cname_contains": "herokuapp.com", "body_contains": "No such app"},
    {"service": "Azure", "cname_contains": ".azurewebsites.net", "body_contains": "404 Web Site not found"},
    {"service": "Shopify", "cname_contains": "myshopify.com", "body_contains": "Sorry, this shop is currently unavailable"},
    {"service": "Fastly", "cname_contains": "fastly.net", "body_contains": "Fastly error: unknown domain"},
    {"service": "Tumblr", "cname_contains": "tumblr.com", "body_contains": "There's nothing here"},
    {"service": "Unbounce", "cname_contains": "unbouncepages.com", "body_contains": "The requested URL was not found on this server"},
    {"service": "Bitbucket", "cname_contains": "bitbucket.io", "body_contains": "Repository not found"},
    {"service": "Cargo", "cname_contains": "cargocollective.com", "body_contains": "404 Not Found"},
    {"service": "Pantheon", "cname_contains": "pantheonsite.io", "body_contains": "The gods are wise"},
    {"service": "Zendesk", "cname_contains": "zendesk.com", "body_contains": "Help Center Closed"},
    {"service": "Surge", "cname_contains": "surge.sh", "body_contains": "project not found"},
]


async def _resolve_cname(subdomain: str) -> str | None:
    try:
        resolver = dns.asyncresolver.Resolver()
        answer = await resolver.resolve(subdomain, "CNAME")
        return str(answer[0].target).rstrip(".")
    except Exception:
        return None


async def _check_takeover(
    subdomain: str,
    client: httpx.AsyncClient,
    sem: asyncio.Semaphore,
) -> dict[str, Any] | None:
    async with sem:
        cname = await _resolve_cname(subdomain)
        if not cname:
            return None
        for fp in TAKEOVER_FINGERPRINTS:
            if fp["cname_contains"] in cname:
                try:
                    resp = await client.get(f"https://{subdomain}", timeout=8.0)
                    body = resp.text
                except Exception:
                    try:
                        resp = await client.get(f"http://{subdomain}", timeout=8.0)
                        body = resp.text
                    except Exception:
                        body = ""
                if fp["body_contains"].lower() in body.lower():
                    return {
                        "subdomain": subdomain,
                        "service": fp["service"],
                        "cname": cname,
                        "evidence": fp["body_contains"],
                    }
    return None


@register_tool
class SubdomainTakeoverTool(OSINTTool):
    name = "subdomain_takeover"
    tier = Tier.T1
    category = Category.WEB
    requires_keys = []
    description = "Check subdomains for dangling CNAME takeover opportunities"
    target_types = ["domain"]
    dynamic_trigger_hints = ["CNAME points to S3/Heroku/GitHub Pages", "404 with cloud provider header"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        subdomains: list[str] = kwargs.get("subdomains", [target])
        if not subdomains:
            subdomains = [target]

        sem = asyncio.Semaphore(20)
        vulnerable: list[dict[str, Any]] = []

        async with httpx.AsyncClient(headers=_HEADERS, timeout=10.0, follow_redirects=True) as client:
            results = await asyncio.gather(
                *(_check_takeover(sub, client, sem) for sub in subdomains),
                return_exceptions=True,
            )

        for r in results:
            if isinstance(r, dict):
                vulnerable.append(r)

        return ToolResult(
            success=True,
            source=self.name,
            data={
                "target": target,
                "vulnerable": vulnerable,
                "tested_count": len(subdomains),
            },
            result_count=len(vulnerable),
        )

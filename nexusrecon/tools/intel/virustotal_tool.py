"""VirusTotal API tool, domain, IP, and URL enrichment."""
from __future__ import annotations

import base64
from typing import Any

from nexusrecon.opsec.useragent import random_ua
from nexusrecon.tools.base import (
    BaseHTTPTool,
    Category,
    Tier,
    ToolResult,
    make_http_client,
)
from nexusrecon.tools.registry import register_tool


@register_tool
class VirusTotalTool(BaseHTTPTool):
    name = "virustotal"
    provider_label = "VirusTotal"
    tier = Tier.T0
    category = Category.INFRASTRUCTURE
    requires_keys = ["virustotal_api_key"]
    description = "VirusTotal domain/IP/URL reputation and passive DNS"
    target_types = ["domain", "ip", "url"]
    dynamic_trigger_hints = ["malicious domain found", "c2 infrastructure detected", "suspicious url"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        key = self.config.get_secret("virustotal_api_key")
        if not key:
            return ToolResult(success=False, source=self.name, error="VIRUSTOTAL_API_KEY not set")

        try:
            async with make_http_client(
                base_url="https://www.virustotal.com/api/v3",
                headers={"x-apikey": key, "User-Agent": random_ua()},
                timeout=15.0,
                **self._proxy_kwargs(),
            ) as client:
                target_type = kwargs.get("target_type", "domain")
                if target_type == "domain":
                    endpoint = f"/domains/{target}"
                elif target_type == "ip":
                    endpoint = f"/ip_addresses/{target}"
                elif target_type == "url":
                    url_id = base64.urlsafe_b64encode(target.encode()).decode().strip("=")
                    endpoint = f"/urls/{url_id}"
                else:
                    return ToolResult(success=False, source=self.name, error=f"Unknown type: {target_type}")

                # ``classify_response`` from :class:`BaseHTTPTool` replaces
                # a bare ``if resp.status_code == 200`` gate that previously
                # masked VT auth errors (401), rate limits (429), and 5xx
                # outages as silent empty responses.
                resp = await client.get(endpoint)
                fail = self.classify_response(resp, endpoint)
                if fail is not None:
                    return fail

                r = resp.json()
                attrs = r.get("data", {}).get("attributes", {})
                data: dict[str, Any] = {
                    "reputation": attrs.get("reputation"),
                    "categories": attrs.get("categories", {}),
                    "last_analysis_stats": attrs.get("last_analysis_stats", {}),
                    "whois": attrs.get("whois", "")[:500] if target_type == "domain" else None,
                    "total_votes": attrs.get("total_votes", {}),
                    "registrar": attrs.get("registrar"),
                    "creation_date": attrs.get("creation_date"),
                }

                # Subdomains for domain reports, auxiliary endpoint; we
                # keep the soft-fail behaviour because the primary
                # /domains/{target} response is already in hand and a
                # subdomain-fetch failure shouldn't poison the call.
                if target_type == "domain":
                    sub_resp = await client.get(f"/domains/{target}/subdomains", params={"limit": 20})
                    if sub_resp.status_code == 200:
                        data["subdomains"] = [
                            d.get("id") for d in sub_resp.json().get("data", [])
                        ]

            return ToolResult(
                success=True, source=self.name, data=data,
                result_count=len(data.get("subdomains", [])),
            )
        except Exception as e:
            return ToolResult(success=False, source=self.name, error=str(e))

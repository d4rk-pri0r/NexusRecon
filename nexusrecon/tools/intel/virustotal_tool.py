"""VirusTotal API tool — domain, IP, and URL enrichment."""
from __future__ import annotations
import base64
from typing import Any, Dict, Optional
import httpx
from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool


@register_tool
class VirusTotalTool(OSINTTool):
    name = "virustotal"
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
            client = httpx.AsyncClient(
                base_url="https://www.virustotal.com/api/v3",
                headers={"x-apikey": key},
                timeout=15.0,
            )

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

            resp = await client.get(endpoint)
            data = {}
            if resp.status_code == 200:
                r = resp.json()
                attrs = r.get("data", {}).get("attributes", {})
                data = {
                    "reputation": attrs.get("reputation"),
                    "categories": attrs.get("categories", {}),
                    "last_analysis_stats": attrs.get("last_analysis_stats", {}),
                    "whois": attrs.get("whois", "")[:500] if target_type == "domain" else None,
                    "total_votes": attrs.get("total_votes", {}),
                    "registrar": attrs.get("registrar"),
                    "creation_date": attrs.get("creation_date"),
                }

                # Subdomains for domain reports
                if target_type == "domain":
                    sub_resp = await client.get(f"/domains/{target}/subdomains", params={"limit": 20})
                    if sub_resp.status_code == 200:
                        data["subdomains"] = [
                            d.get("id") for d in sub_resp.json().get("data", [])
                        ]

            await client.aclose()
            return ToolResult(
                success=True, source=self.name, data=data,
                result_count=len(data.get("subdomains", [])),
            )
        except Exception as e:
            return ToolResult(success=False, source=self.name, error=str(e))

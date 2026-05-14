"""Passive DNS tool — SecurityTrails API."""
from __future__ import annotations
from typing import Any, Dict, List, Optional
import httpx
from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool


@register_tool
class PassiveDNSTool(OSINTTool):
    name = "passive_dns"
    tier = Tier.T0
    category = Category.DNS
    requires_keys = ["securitytrails_api_key"]
    description = "Passive DNS history via SecurityTrails API"
    target_types = ["domain"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        key = self.config.get_secret("securitytrails_api_key")
        if not key:
            return ToolResult(success=False, source=self.name, error="SECURITYTRAILS_API_KEY not set")

        try:
            client = httpx.AsyncClient(
                base_url="https://api.securitytrails.com/v1",
                headers={"APIKEY": key},
                timeout=15.0,
            )

            results: Dict[str, Any] = {}

            # Subdomain enumeration
            resp = await client.get(f"/domain/{target}/subdomains")
            if resp.status_code == 200:
                data = resp.json()
                subs = [f"{s}.{target}" for s in data.get("subdomains", [])]
                results["subdomains"] = subs

            # DNS history
            resp = await client.get(f"/dns/{target}/history")
            if resp.status_code == 200:
                results["dns_history"] = resp.json()

            # WHOIS
            resp = await client.get(f"/domain/{target}/whois")
            if resp.status_code == 200:
                results["whois"] = resp.json()

            # Associated domains
            resp = await client.get(f"/domain/{target}/associated")
            if resp.status_code == 200:
                results["associated"] = resp.json().get("domains", [])

            await client.aclose()
            total_subs = len(results.get("subdomains", []))
            return ToolResult(
                success=True, source=self.name, data=results, result_count=total_subs,
            )
        except Exception as e:
            return ToolResult(success=False, source=self.name, error=str(e))

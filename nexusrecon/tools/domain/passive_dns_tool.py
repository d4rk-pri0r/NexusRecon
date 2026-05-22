"""Passive DNS tool — SecurityTrails API."""
from __future__ import annotations

from typing import Any

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
            async with httpx.AsyncClient(
                base_url="https://api.securitytrails.com/v1",
                headers={"APIKEY": key},
                timeout=15.0,
            ) as client:
                results: dict[str, Any] = {}
                endpoint_errors: list[str] = []

                # Four endpoints. The primary one (subdomain enum) hard-
                # fails on auth errors so a bad/missing key is visible.
                # The auxiliary endpoints (history, whois, associated)
                # may legitimately 404 for some targets, so we record
                # which ones failed in ``endpoint_errors`` but don't
                # fail the whole call as long as the primary succeeded.
                #
                # Previous revision had every endpoint silently fall out
                # of an ``if status_code == 200`` gate, leaving callers
                # unable to tell "this domain has no SecurityTrails
                # footprint" from "my key is bad / quota exhausted".

                resp = await client.get(f"/domain/{target}/subdomains")
                if resp.status_code in (401, 403):
                    return ToolResult(
                        success=False, source=self.name,
                        error=f"SecurityTrails auth failure (HTTP {resp.status_code}) — check SECURITYTRAILS_API_KEY",
                    )
                if resp.status_code == 429:
                    return ToolResult(
                        success=False, source=self.name,
                        error="SecurityTrails rate limit / monthly quota exceeded",
                    )
                if resp.status_code != 200:
                    return ToolResult(
                        success=False, source=self.name,
                        error=f"SecurityTrails subdomains returned HTTP {resp.status_code}",
                    )
                data = resp.json()
                subs = [f"{s}.{target}" for s in data.get("subdomains", [])]
                results["subdomains"] = subs

                # Auxiliary endpoints — record failures but don't abort.
                for endpoint, key_name in [
                    (f"/dns/{target}/history", "dns_history"),
                    (f"/domain/{target}/whois", "whois"),
                    (f"/domain/{target}/associated", "associated"),
                ]:
                    aux = await client.get(endpoint)
                    if aux.status_code == 200:
                        body = aux.json()
                        if key_name == "associated":
                            results[key_name] = body.get("domains", [])
                        else:
                            results[key_name] = body
                    else:
                        endpoint_errors.append(
                            f"{endpoint} returned HTTP {aux.status_code}"
                        )

                if endpoint_errors:
                    results["_endpoint_errors"] = endpoint_errors

            total_subs = len(results.get("subdomains", []))
            return ToolResult(
                success=True, source=self.name, data=results, result_count=total_subs,
            )
        except Exception as e:
            return ToolResult(success=False, source=self.name, error=str(e))

"""CertSpotter — certificate transparency monitoring (sslmate.com)."""
from __future__ import annotations

from typing import Any, Dict, List, Set

import httpx

from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool


@register_tool
class CertSpotterTool(OSINTTool):
    name = "certspotter"
    tier = Tier.T0
    category = Category.CERTIFICATE
    # Key is optional — unauthenticated works at lower rate limits
    requires_keys = []
    description = "CertSpotter CT log search — alternative to crt.sh with independent indexing"
    target_types = ["domain"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        key = self.config.get_secret("certspotter_api_key")
        headers: Dict[str, str] = {
            "Accept": "application/json",
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
        }
        if key:
            headers["Authorization"] = f"Bearer {key}"

        try:
            async with httpx.AsyncClient(
                base_url="https://api.certspotter.com/v1",
                headers=headers,
                timeout=20.0,
            ) as client:
                resp = await client.get(
                    "/issuances",
                    params={
                        "domain": target,
                        "include_subdomains": "true",
                        "expand": "dns_names",
                    },
                )

                if resp.status_code == 429:
                    return ToolResult(
                        success=False, source=self.name,
                        error="CertSpotter rate limit — set CERTSPOTTER_API_KEY for higher quota",
                    )
                if resp.status_code != 200:
                    return ToolResult(success=False, source=self.name, error=f"CertSpotter returned {resp.status_code}")

                certs: List[Dict[str, Any]] = resp.json()

                all_dns_names: Set[str] = set()
                cert_list: List[Dict[str, Any]] = []
                for cert in certs[:200]:
                    dns_names: List[str] = cert.get("dns_names", [])
                    all_dns_names.update(dns_names)
                    issuer = cert.get("issuer")
                    cert_list.append({
                        "id": cert.get("id"),
                        "tbs_sha256": cert.get("tbs_sha256"),
                        "dns_names": dns_names,
                        "not_before": cert.get("not_before"),
                        "not_after": cert.get("not_after"),
                        "issuer": issuer.get("name") if isinstance(issuer, dict) else issuer,
                    })

                # Strip wildcards for the subdomain list
                subdomains = sorted({n for n in all_dns_names if not n.startswith("*")})

                data: Dict[str, Any] = {
                    "domain": target,
                    "certificate_count": len(certs),
                    "unique_domains": len(subdomains),
                    "subdomains": subdomains,
                    "certificates": cert_list[:50],
                }

        except Exception as exc:
            return ToolResult(success=False, source=self.name, error=str(exc))

        return ToolResult(success=True, source=self.name, data=data, result_count=len(subdomains))

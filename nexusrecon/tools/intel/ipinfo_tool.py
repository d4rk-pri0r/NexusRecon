"""IPinfo — IP geolocation, ASN, and VPN/proxy/hosting detection."""
from __future__ import annotations

from typing import Any, Dict

import httpx

from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool


@register_tool
class IPInfoTool(OSINTTool):
    name = "ipinfo"
    tier = Tier.T0
    category = Category.INFRASTRUCTURE
    # Key is optional — free tier allows 50k req/month without auth
    requires_keys = []
    description = "IPinfo — IP geolocation, ASN, ISP, and VPN/proxy/hosting flag detection"
    target_types = ["ip"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        token = self.config.get_secret("ipinfo_api_key")
        params: Dict[str, str] = {}
        if token:
            params["token"] = token

        try:
            async with httpx.AsyncClient(
                base_url="https://ipinfo.io",
                headers={
                    "Accept": "application/json",
                    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
                },
                timeout=10.0,
            ) as client:
                resp = await client.get(f"/{target}/json", params=params)

                if resp.status_code == 429:
                    return ToolResult(success=False, source=self.name, error="IPinfo rate limit — set IPINFO_API_KEY for higher quota")
                if resp.status_code != 200:
                    return ToolResult(success=False, source=self.name, error=f"IPinfo returned {resp.status_code}")

                raw = resp.json()

                # Parse ASN out of org field ("AS12345 Cloudflare Inc")
                org = raw.get("org", "")
                asn, org_name = (org.split(" ", 1) + [""])[:2] if " " in org else (org, "")

                data: Dict[str, Any] = {
                    "ip": raw.get("ip"),
                    "hostname": raw.get("hostname"),
                    "city": raw.get("city"),
                    "region": raw.get("region"),
                    "country": raw.get("country"),
                    "loc": raw.get("loc"),
                    "org": org,
                    "asn": asn,
                    "org_name": org_name,
                    "postal": raw.get("postal"),
                    "timezone": raw.get("timezone"),
                    # Privacy fields — only present with paid token
                    "vpn": raw.get("privacy", {}).get("vpn", False),
                    "proxy": raw.get("privacy", {}).get("proxy", False),
                    "tor": raw.get("privacy", {}).get("tor", False),
                    "hosting": raw.get("privacy", {}).get("hosting", False),
                    # Abuse contact — useful for reporting
                    "abuse_email": raw.get("abuse", {}).get("email"),
                }

        except Exception as exc:
            return ToolResult(success=False, source=self.name, error=str(exc))

        return ToolResult(success=True, source=self.name, data=data, result_count=1)

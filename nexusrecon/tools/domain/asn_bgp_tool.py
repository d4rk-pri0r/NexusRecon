"""ASN and BGP lookup tool via BGPView API."""
from __future__ import annotations

import ipaddress
import socket
from typing import Any

import httpx

from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool


@register_tool
class ASNBGPTool(OSINTTool):
    name = "asn_bgp"
    tier = Tier.T0
    category = Category.INFRASTRUCTURE
    requires_keys = []
    description = "ASN and BGP prefix mapping via BGPView API"
    target_types = ["ip", "asn"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        try:
            # B19: resolve domain targets to IP before hitting the BGPView /ip/ endpoint
            is_asn = target.upper().startswith("AS")
            resolved = target
            if not is_asn:
                try:
                    ipaddress.ip_address(target)
                except ValueError:
                    # target is a hostname — resolve to IP
                    try:
                        resolved = socket.gethostbyname(target)
                    except socket.gaierror as dns_err:
                        return ToolResult(
                            success=False,
                            source=self.name,
                            error=f"DNS resolution failed for domain {target!r}: {dns_err}",
                        )

            client = httpx.AsyncClient(base_url="https://api.bgpview.io", timeout=10.0)
            results: dict[str, Any] = {}

            if is_asn:
                # ASN lookup
                asn = target.upper().lstrip("AS")
                resp = await client.get(f"/asn/{asn}")
                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    results = {
                        "asn": data.get("asn"),
                        "name": data.get("name"),
                        "description": data.get("description"),
                        "country": data.get("country_code"),
                        "rir": data.get("rir"),
                        "prefixes_v4": [p.get("prefix") for p in data.get("ipv4_prefixes", [])[:50]],
                        "prefixes_v6": [p.get("prefix") for p in data.get("ipv6_prefixes", [])[:50]],
                        "peers": [p.get("asn") for p in data.get("peers", [])[:50]],
                        "upstreams": [u.get("asn") for u in data.get("upstreams", [])],
                        "downstreams": [d.get("asn") for d in data.get("downstreams", [])],
                    }
            else:
                # IP lookup (resolved is a valid IP at this point)
                resp = await client.get(f"/ip/{resolved}")
                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    results = {
                        "ip": data.get("ip"),
                        "asn": data.get("asn", {}).get("asn"),
                        "asn_name": data.get("asn", {}).get("name"),
                        "description": data.get("asn", {}).get("description_short"),
                        "country": data.get("asn", {}).get("country_code"),
                        "rir": data.get("rir"),
                    }

            await client.aclose()
            return ToolResult(success=True, source=self.name, data=results, result_count=1)
        except Exception as e:
            return ToolResult(success=False, source=self.name, error=str(e))

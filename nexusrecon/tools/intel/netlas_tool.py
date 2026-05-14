"""Netlas.io — internet scan data (freemium Shodan/Censys alternative)."""
from __future__ import annotations

from typing import Any, Dict, List

import httpx

from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool


@register_tool
class NetlasTool(OSINTTool):
    name = "netlas"
    tier = Tier.T0
    category = Category.INFRASTRUCTURE
    requires_keys = ["netlas_api_key"]
    description = "Netlas.io internet scan data — host/service discovery with certificate and banner data"
    target_types = ["domain", "ip"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        key = self.config.get_secret("netlas_api_key")
        if not key:
            return ToolResult(success=False, source=self.name, error="NETLAS_API_KEY not set")

        target_type = kwargs.get("target_type", "domain")
        query = f"ip:{target}" if target_type == "ip" else f"domain:{target}"

        try:
            async with httpx.AsyncClient(
                base_url="https://app.netlas.io",
                headers={
                    "X-API-Key": key,
                    "Accept": "application/json",
                    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
                },
                timeout=20.0,
            ) as client:
                resp = await client.get(
                    "/api/responses/",
                    params={"q": query, "source_type": "include", "size": 50},
                )

                if resp.status_code in (401, 403):
                    return ToolResult(success=False, source=self.name, error="Invalid Netlas API key")
                if resp.status_code == 429:
                    return ToolResult(success=False, source=self.name, error="Netlas quota exceeded")
                if resp.status_code != 200:
                    return ToolResult(success=False, source=self.name, error=f"Netlas returned {resp.status_code}")

                raw = resp.json()
                items: List[Dict[str, Any]] = raw.get("items", [])

                hosts = []
                for item in items:
                    d = item.get("data", {})
                    iface = d.get("iface", {})
                    cert = d.get("certificate", {}) or {}
                    subject = cert.get("subject", {})
                    hosts.append({
                        "ip": iface.get("ipv4") or iface.get("ipv6"),
                        "port": d.get("port"),
                        "protocol": d.get("protocol"),
                        "app": d.get("app", {}).get("http", {}).get("title") if d.get("app") else None,
                        "server": d.get("http", {}).get("headers", {}).get("server"),
                        "cert_cn": subject.get("common_name"),
                        "cert_org": subject.get("organization"),
                        "cert_sans": cert.get("subject_alt_name", {}).get("dns_names", [])[:5],
                        "timestamp": d.get("timestamp"),
                    })

                data: Dict[str, Any] = {
                    "query": query,
                    "total": raw.get("count", len(items)),
                    "hosts": hosts,
                }

        except Exception as exc:
            return ToolResult(success=False, source=self.name, error=str(exc))

        return ToolResult(success=True, source=self.name, data=data, result_count=len(hosts))

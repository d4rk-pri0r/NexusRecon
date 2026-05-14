"""Shodan API tool — host info + search + facets."""
from __future__ import annotations
from typing import Any, Dict, List, Optional
import httpx
from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool


@register_tool
class ShodanTool(OSINTTool):
    name = "shodan"
    tier = Tier.T0
    category = Category.INFRASTRUCTURE
    requires_keys = ["shodan_api_key"]
    description = "Shodan host search, service enumeration, and historical data"
    target_types = ["domain", "ip"]
    dynamic_trigger_hints = ["open port found", "internet-facing service exposed", "banner found"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        key = self.config.get_secret("shodan_api_key")
        if not key:
            return ToolResult(success=False, source=self.name, error="SHODAN_API_KEY not set")

        results: Dict[str, Any] = {}
        try:
            async with httpx.AsyncClient(
                base_url="https://api.shodan.io",
                params={"key": key},
                timeout=15.0,
            ) as client:
                # If domain, resolve to IPs via DNS first
                if not kwargs.get("is_ip", False):
                    resp = await client.get("/shodan/host/search", params={
                        "query": f'hostname:"{target}"', "facets": "port:10,org:10",
                    })
                    if resp.status_code == 200:
                        results["search"] = self._parse_search_results(resp.json())

                # If IP, get host details
                if kwargs.get("ip"):
                    resp = await client.get(f"/shodan/host/{kwargs['ip']}")
                    if resp.status_code == 200:
                        results["host"] = self._parse_host(resp.json())

                # DNS lookup
                if not kwargs.get("is_ip", False):
                    resp = await client.get("/dns/resolve", params={"hostnames": target})
                    if resp.status_code == 200:
                        results["dns_resolution"] = resp.json()

            total = results.get("search", {}).get("total", 0)
            return ToolResult(
                success=True, source=self.name, data=results, result_count=total,
            )
        except Exception as e:
            return ToolResult(success=False, source=self.name, error=str(e))

    def _parse_search_results(self, data: Dict) -> Dict:
        hosts = []
        for match in data.get("matches", []):
            hosts.append({
                "ip": match.get("ip_str"),
                "port": match.get("port"),
                "protocol": match.get("transport"),
                "product": match.get("product"),
                "version": match.get("version"),
                "org": match.get("org"),
                "country": match.get("location", {}).get("country_name"),
                "city": match.get("location", {}).get("city"),
                "data": match.get("data", "")[:500],
                "timestamp": match.get("timestamp"),
            })
        return {"total": data.get("total", 0), "hosts": hosts}

    def _parse_host(self, data: Dict) -> Dict:
        return {
            "ip": data.get("ip_str"),
            "ports": data.get("ports", []),
            "hostnames": data.get("hostnames", []),
            "domains": data.get("domains", []),
            "org": data.get("org"),
            "isp": data.get("isp"),
            "os": data.get("os"),
            "country": data.get("location", {}).get("country_name"),
            "services": [
                {
                    "port": s.get("port"),
                    "product": s.get("product"),
                    "version": s.get("version"),
                    "transport": s.get("transport"),
                }
                for s in data.get("data", [])
            ],
            "vulns": data.get("vulns", []),
            "tags": data.get("tags", []),
        }

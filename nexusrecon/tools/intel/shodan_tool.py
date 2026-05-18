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
                # Each endpoint below was previously gated by
                # ``if resp.status_code == 200`` and silently skipped on
                # any other status. That made bad keys, rate limits, and
                # provider outages indistinguishable from "no data for
                # this target". The shared status-code helper below
                # converts those into explicit failures.
                primary_endpoint = "host search" if not kwargs.get("is_ip", False) else "host details"

                # If domain, do a hostname-scoped host search (primary).
                if not kwargs.get("is_ip", False):
                    resp = await client.get("/shodan/host/search", params={
                        "query": f'hostname:"{target}"', "facets": "port:10,org:10",
                    })
                    fail = self._classify_status(resp, primary_endpoint)
                    if fail is not None:
                        return fail
                    results["search"] = self._parse_search_results(resp.json())

                # If an explicit IP was supplied, get host details (primary).
                if kwargs.get("ip"):
                    resp = await client.get(f"/shodan/host/{kwargs['ip']}")
                    fail = self._classify_status(resp, "host details")
                    if fail is not None:
                        return fail
                    results["host"] = self._parse_host(resp.json())

                # DNS lookup is auxiliary — failures here don't fail the
                # whole call, just leave ``dns_resolution`` absent.
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

    def _classify_status(self, resp: httpx.Response, endpoint: str) -> Optional[ToolResult]:
        """Convert provider error codes into explicit ``ToolResult``
        failures. Returns ``None`` if the response is 2xx (caller
        continues). Returns a populated ``ToolResult(success=False)``
        otherwise.

        Shodan documents 401/403 for auth failures (bad/missing key) and
        429 for rate-limit; 5xx are transient provider outages.
        """
        if resp.status_code in (401, 403):
            return ToolResult(
                success=False, source=self.name,
                error=f"Shodan auth failure on {endpoint} (HTTP {resp.status_code}) — check SHODAN_API_KEY",
            )
        if resp.status_code == 429:
            return ToolResult(
                success=False, source=self.name,
                error=f"Shodan rate limit on {endpoint} — back off and retry",
            )
        if resp.status_code != 200:
            return ToolResult(
                success=False, source=self.name,
                error=f"Shodan {endpoint} returned HTTP {resp.status_code}",
            )
        return None

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

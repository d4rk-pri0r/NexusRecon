"""Censys API tool — hosts and certificates search."""
from __future__ import annotations
from typing import Any, Dict, List, Optional
import httpx
from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool


@register_tool
class CensysTool(OSINTTool):
    name = "censys"
    tier = Tier.T0
    category = Category.INFRASTRUCTURE
    requires_keys = ["censys_api_id", "censys_api_secret"]
    description = "Censys host and certificate search"
    target_types = ["domain", "ip"]
    dynamic_trigger_hints = ["open port found", "tls certificate found", "internet-facing host found"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        api_id = self.config.get_secret("censys_api_id")
        api_secret = self.config.get_secret("censys_api_secret")
        if not api_id or not api_secret:
            return ToolResult(success=False, source=self.name, error="CENSYS_API_ID or CENSYS_API_SECRET not set")

        try:
            client = httpx.AsyncClient(
                base_url="https://search.censys.io/api/v2",
                auth=(api_id, api_secret),
                timeout=15.0,
            )

            results: Dict[str, Any] = {}

            # Host search
            if kwargs.get("ip") or not kwargs.get("is_domain", True):
                ip = kwargs.get("ip", target)
                resp = await client.get(f"/hosts/{ip}")
                if resp.status_code == 200:
                    results["host"] = resp.json()

            # Certificate search by domain
            if not kwargs.get("is_ip", False):
                resp = await client.get("/certificates/search", params={
                    "q": f"names: {target}", "per_page": 20,
                })
                if resp.status_code == 200:
                    data = resp.json()
                    results["certificates"] = {
                        "total": data.get("result", {}).get("total", 0),
                        "hits": [
                            {
                                "fingerprint_sha256": h.get("fingerprint_sha256"),
                                "names": h.get("parsed", {}).get("subject", {}).get("common_name", []),
                                "not_after": h.get("parsed", {}).get("validity", {}).get("end"),
                            }
                            for h in data.get("result", {}).get("hits", [])[:20]
                        ],
                    }

            await client.aclose()
            return ToolResult(
                success=True, source=self.name, data=results,
                result_count=results.get("certificates", {}).get("total", 0),
            )
        except Exception as e:
            return ToolResult(success=False, source=self.name, error=str(e))

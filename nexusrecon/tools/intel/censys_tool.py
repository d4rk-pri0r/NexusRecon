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
            async with httpx.AsyncClient(
                base_url="https://search.censys.io/api/v2",
                auth=(api_id, api_secret),
                timeout=15.0,
            ) as client:
                results: Dict[str, Any] = {}

                # The status-code branches below replace bare ``if status
                # == 200`` gates that previously masked Censys auth errors,
                # rate-limits, and 5xx outages as silent empty responses.

                # Host search
                if kwargs.get("ip") or not kwargs.get("is_domain", True):
                    ip = kwargs.get("ip", target)
                    resp = await client.get(f"/hosts/{ip}")
                    fail = self._classify_status(resp, f"hosts/{ip}")
                    if fail is not None:
                        return fail
                    results["host"] = resp.json()

                # Certificate search by domain
                if not kwargs.get("is_ip", False):
                    resp = await client.get("/certificates/search", params={
                        "q": f"names: {target}", "per_page": 20,
                    })
                    fail = self._classify_status(resp, "certificates/search")
                    if fail is not None:
                        return fail
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

            return ToolResult(
                success=True, source=self.name, data=results,
                result_count=results.get("certificates", {}).get("total", 0),
            )
        except Exception as e:
            return ToolResult(success=False, source=self.name, error=str(e))

    def _classify_status(self, resp: httpx.Response, endpoint: str) -> Optional[ToolResult]:
        """Convert provider error codes into explicit failures.
        Returns ``None`` on 2xx so the caller continues."""
        if resp.status_code in (401, 403):
            return ToolResult(
                success=False, source=self.name,
                error=f"Censys auth failure on {endpoint} (HTTP {resp.status_code}) — check CENSYS_API_ID / CENSYS_API_SECRET",
            )
        if resp.status_code == 429:
            return ToolResult(
                success=False, source=self.name,
                error=f"Censys rate limit on {endpoint} — back off and retry",
            )
        if resp.status_code != 200:
            return ToolResult(
                success=False, source=self.name,
                error=f"Censys {endpoint} returned HTTP {resp.status_code}",
            )
        return None

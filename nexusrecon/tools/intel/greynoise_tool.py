"""GreyNoise API tool, IP noise context."""
from __future__ import annotations
from typing import Any, Dict
import httpx
from nexusrecon.tools.base import BaseHTTPTool, Category, Tier, ToolResult
from nexusrecon.tools.registry import register_tool


@register_tool
class GreyNoiseTool(BaseHTTPTool):
    name = "greynoise"
    provider_label = "GreyNoise"
    tier = Tier.T0
    category = Category.INFRASTRUCTURE
    requires_keys = ["greynoise_api_key"]
    description = "GreyNoise IP classification (benign, malicious, unknown)"
    target_types = ["ip"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        key = self.config.get_secret("greynoise_api_key")
        if not key:
            return ToolResult(success=False, source=self.name, error="GREYNOISE_API_KEY not set")

        try:
            async with httpx.AsyncClient(
                base_url="https://api.greynoise.io",
                headers={"key": key},
                timeout=15.0,
                **self._proxy_kwargs(),
            ) as client:
                resp = await client.get("/v2/noise/quick", params={"ip": target})

                # ``classify_response`` from :class:`BaseHTTPTool` replaces
                # an earlier revision that had no status-code branches at
                # all; every non-2xx response (bad key, rate limit, 5xx)
                # returned ``success=True`` with empty data, making
                # provider outages and quota exhaustion silently
                # indistinguishable from "IP not in database".
                fail = self.classify_response(resp)
                if fail is not None:
                    return fail

                r = resp.json()

            data = {
                "ip": r.get("ip"),
                "classification": r.get("classification"),  # benign, malicious, unknown
                "noise": r.get("noise", False),
                "riot": r.get("riot", False),
                "name": r.get("name"),
                "last_seen": r.get("last_seen"),
                "cve": r.get("cve", []),
                "tags": r.get("tags", []),
                "actor": r.get("actor"),
                "actor_type": r.get("actor_type"),
            }
            # GreyNoise returns 200 for both seen and unseen IPs; an
            # "unknown" classification with no signals means the IP
            # isn't in their database. That's a legitimate zero-result
            # answer, not a hit — reflect that in ``result_count``.
            has_signal = (
                data["noise"]
                or data["riot"]
                or (data["classification"] not in (None, "unknown"))
            )
            return ToolResult(
                success=True, source=self.name, data=data,
                result_count=1 if has_signal else 0,
            )
        except Exception as e:
            return ToolResult(success=False, source=self.name, error=str(e))

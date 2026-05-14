"""LeakCheck — breach database search by email, username, phone, or domain."""
from __future__ import annotations

from typing import Any, Dict, List

import httpx

from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool

# Maps target_type values to the query type LeakCheck expects
_TYPE_MAP = {
    "email": "email",
    "username": "username",
    "phone": "phone",
    "domain": "domain",
}


@register_tool
class LeakCheckTool(OSINTTool):
    name = "leakcheck"
    tier = Tier.T0
    category = Category.BREACH
    requires_keys = ["leakcheck_api_key"]
    description = (
        "LeakCheck breach database — search by email, username, phone, or domain "
        "across hundreds of breach sources"
    )
    target_types = ["email", "username", "phone", "domain"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        key = self.config.get_secret("leakcheck_api_key")
        if not key:
            return ToolResult(
                success=False, source=self.name, error="LEAKCHECK_API_KEY not set"
            )

        target_type = kwargs.get("target_type", "email")
        query_type = _TYPE_MAP.get(target_type, "email")

        try:
            async with httpx.AsyncClient(
                base_url="https://leakcheck.io",
                headers={
                    "X-API-Key": key,
                    "Accept": "application/json",
                    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
                },
                timeout=20.0,
            ) as client:
                resp = await client.get(
                    f"/api/v2/query/{target}",
                    params={"type": query_type},
                )

                if resp.status_code == 401:
                    return ToolResult(
                        success=False, source=self.name, error="Invalid LeakCheck API key"
                    )
                if resp.status_code == 429:
                    return ToolResult(
                        success=False, source=self.name, error="LeakCheck quota exhausted"
                    )
                if resp.status_code != 200:
                    return ToolResult(
                        success=False,
                        source=self.name,
                        error=f"LeakCheck returned {resp.status_code}",
                    )

                raw = resp.json()
                if not raw.get("success"):
                    return ToolResult(
                        success=False,
                        source=self.name,
                        error=raw.get("message", "LeakCheck returned success=false"),
                    )

                found: int = raw.get("found", 0)
                entries: List[Dict[str, Any]] = raw.get("result", [])
                data = {
                    "query": target,
                    "query_type": query_type,
                    "found": found,
                    "quota_remaining": raw.get("quota"),
                    "results": [
                        {
                            "email": e.get("email"),
                            "username": e.get("username"),
                            # Truncate credentials — we surface existence, not cleartext
                            "password": (e.get("password") or "")[:4] + "***" if e.get("password") else None,
                            "hash": (e.get("hash") or "")[:16] + "..." if e.get("hash") else None,
                            "hash_type": e.get("hash_type"),
                            "database": e.get("database", {}).get("name"),
                            "breach_date": e.get("database", {}).get("breach_date"),
                            "unverified": e.get("database", {}).get("unverified", False),
                            "compilation": e.get("database", {}).get("compilation", False),
                        }
                        for e in entries[:100]
                    ],
                }

        except Exception as exc:
            return ToolResult(success=False, source=self.name, error=str(exc))

        return ToolResult(
            success=True,
            source=self.name,
            data=data,
            result_count=found,
        )

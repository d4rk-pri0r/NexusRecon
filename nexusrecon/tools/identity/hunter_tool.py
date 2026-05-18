"""Hunter.io API tool for email enumeration."""
from __future__ import annotations
from typing import Any, Dict, List, Optional
import httpx
from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool


@register_tool
class HunterTool(OSINTTool):
    name = "hunter"
    tier = Tier.T0
    category = Category.EMAIL
    requires_keys = ["hunter_api_key"]
    description = "Email discovery and pattern detection via Hunter.io API"
    target_types = ["domain"]
    dynamic_trigger_hints = ["email address discovered", "employee record found"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        key = self.config.get_secret("hunter_api_key")
        if not key:
            return ToolResult(success=False, source=self.name, error="HUNTER_API_KEY not set")

        try:
            async with httpx.AsyncClient(
                base_url="https://api.hunter.io/v2", timeout=15.0,
            ) as client:
                # Previous revision read ``if resp.status_code == 200``
                # and silently fell through on auth/rate-limit/server
                # errors, returning ``success=True`` with an empty
                # ``emails`` list. That hid bad ``HUNTER_API_KEY``
                # values from the operator. Hunter documents:
                #   401 Unauthorized → invalid key
                #   429 Rate limit   → free-tier quota (25 req/mo)
                #                      or paid-tier burst limit
                resp = await client.get(
                    "/domain-search",
                    params={"domain": target, "api_key": key},
                )
                if resp.status_code in (401, 403):
                    return ToolResult(
                        success=False, source=self.name,
                        error=f"Hunter auth failure (HTTP {resp.status_code}) — check HUNTER_API_KEY",
                    )
                if resp.status_code == 429:
                    return ToolResult(
                        success=False, source=self.name,
                        error="Hunter rate limit / monthly quota exceeded — upgrade plan or back off",
                    )
                if resp.status_code != 200:
                    return ToolResult(
                        success=False, source=self.name,
                        error=f"Hunter domain-search returned HTTP {resp.status_code}",
                    )

                domain_data = resp.json()

            # Email pattern extraction
            emails = []
            pattern_data = domain_data.get("data", {})
            for em in pattern_data.get("emails", []):
                emails.append({
                    "email": em.get("value"),
                    "first_name": em.get("first_name"),
                    "last_name": em.get("last_name"),
                    "position": em.get("position"),
                    "department": em.get("department"),
                    "confidence": em.get("confidence"),
                    "sources": em.get("sources", []),
                })

            # Domain info
            domain_info = domain_data.get("data", {}).get("organization", {})
            pattern_type = domain_data.get("data", {}).get("pattern", "")

            return ToolResult(
                success=True, source=self.name,
                data={"emails": emails, "pattern": pattern_type, "domain_info": domain_info},
                result_count=len(emails),
            )
        except Exception as e:
            return ToolResult(success=False, source=self.name, error=str(e))

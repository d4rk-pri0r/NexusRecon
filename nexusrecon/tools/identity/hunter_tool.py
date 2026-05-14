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
            client = httpx.AsyncClient(base_url="https://api.hunter.io/v2", timeout=15.0)

            # Domain search
            resp = await client.get("/domain-search", params={"domain": target, "api_key": key})
            domain_data = {}
            if resp.status_code == 200:
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
            pattern_counts = domain_data.get("data", {}).get("email_pattern", "")
            pattern_type = domain_data.get("data", {}).get("pattern", "")

            await client.aclose()
            return ToolResult(
                success=True, source=self.name,
                data={"emails": emails, "pattern": pattern_type, "domain_info": domain_info},
                result_count=len(emails),
            )
        except Exception as e:
            return ToolResult(success=False, source=self.name, error=str(e))

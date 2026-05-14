"""EmailRep — email reputation, breach signals, and deliverability."""
from __future__ import annotations

from typing import Any, Dict

import httpx

from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool


@register_tool
class EmailRepTool(OSINTTool):
    name = "emailrep"
    tier = Tier.T0
    category = Category.BREACH
    # Key is optional — unauthenticated requests work but are rate-limited
    requires_keys = []
    description = (
        "EmailRep.io email reputation: breach signals, deliverability, "
        "spoofability, and malicious-activity flags"
    )
    target_types = ["email"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        key = self.config.get_secret("emailrep_api_key")
        headers: Dict[str, str] = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
            "Accept": "application/json",
        }
        if key:
            headers["Key"] = key

        try:
            async with httpx.AsyncClient(
                base_url="https://emailrep.io",
                headers=headers,
                timeout=15.0,
            ) as client:
                resp = await client.get(f"/{target}")

                if resp.status_code == 400:
                    return ToolResult(
                        success=False,
                        source=self.name,
                        error=f"Invalid email address: {target}",
                    )
                if resp.status_code == 429:
                    return ToolResult(
                        success=False,
                        source=self.name,
                        error="EmailRep rate limit reached — set EMAILREP_API_KEY for higher quota",
                    )
                if resp.status_code != 200:
                    return ToolResult(
                        success=False,
                        source=self.name,
                        error=f"EmailRep returned {resp.status_code}",
                    )

                raw = resp.json()
                details = raw.get("details", {})
                data = {
                    "email": raw.get("email"),
                    "reputation": raw.get("reputation"),
                    "suspicious": raw.get("suspicious", False),
                    "references": raw.get("references", 0),
                    "credentials_leaked": details.get("credentials_leaked", False),
                    "credentials_leaked_recent": details.get("credentials_leaked_recent", False),
                    "data_breach": details.get("data_breach", False),
                    "malicious_activity": details.get("malicious_activity", False),
                    "malicious_activity_recent": details.get("malicious_activity_recent", False),
                    "blacklisted": details.get("blacklisted", False),
                    "spam": details.get("spam", False),
                    "disposable": details.get("disposable", False),
                    "free_provider": details.get("free_provider", False),
                    "deliverable": details.get("deliverable"),
                    "spoofable": details.get("spoofable", False),
                    "spf_strict": details.get("spf_strict"),
                    "dmarc_enforced": details.get("dmarc_enforced"),
                    "first_seen": details.get("first_seen"),
                    "last_seen": details.get("last_seen"),
                    "domain_reputation": details.get("domain_reputation"),
                    "profiles": details.get("profiles", []),
                }

        except Exception as exc:
            return ToolResult(success=False, source=self.name, error=str(exc))

        suspicious = data["suspicious"]
        return ToolResult(
            success=True,
            source=self.name,
            data=data,
            result_count=1 if suspicious or data["credentials_leaked"] else 0,
        )

"""WHOIS lookup tool — live registration data."""
from __future__ import annotations
from typing import Any, Dict, Optional
import whois
from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool


@register_tool
class WHOISTool(OSINTTool):
    name = "whois"
    tier = Tier.T0
    category = Category.DOMAIN
    requires_keys = []
    description = "WHOIS registration data lookup"
    target_types = ["domain"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        try:
            w = whois.whois(target)
            data = {
                "registrar": w.registrar,
                "creation_date": str(w.creation_date) if w.creation_date else None,
                "expiration_date": str(w.expiration_date) if w.expiration_date else None,
                "updated_date": str(w.updated_date) if w.updated_date else None,
                "registrant_name": str(w.name) if hasattr(w, "name") and w.name else None,
                "registrant_org": str(w.org) if hasattr(w, "org") and w.org else None,
                "registrant_email": str(w.emails) if w.emails else None,
                "registrant_country": str(w.country) if hasattr(w, "country") and w.country else None,
                "nameservers": w.name_servers if w.name_servers else [],
                "status": w.status if w.status else [],
                "dnssec": w.dnssec,
            }
            return ToolResult(success=True, source=self.name, data=data, result_count=1)
        except Exception as e:
            return ToolResult(success=False, source=self.name, error=str(e))

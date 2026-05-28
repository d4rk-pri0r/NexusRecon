"""WHOIS lookup tool — live registration data."""
from __future__ import annotations

from typing import Any

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
            # ``result_count`` should reflect whether the lookup
            # actually returned useful data. The python-whois library
            # returns an object with every field set to ``None`` for
            # unregistered TLDs, privacy-redacted domains, and
            # registrars that don't expose WHOIS — previously the tool
            # always returned ``result_count=1`` regardless, which
            # made empty lookups indistinguishable from real ones
            # in the campaign's aggregate metrics.
            has_data = any(v not in (None, [], "", "None") for v in data.values())
            return ToolResult(
                success=True, source=self.name, data=data,
                result_count=1 if has_data else 0,
            )
        except Exception as e:
            return ToolResult(success=False, source=self.name, error=str(e))

    def assess_result(self, result: ToolResult, target: str, target_type: str = "domain") -> str | None:
        # result_count is already 0 only when every WHOIS field (registrar,
        # dates, nameservers, status) came back empty. For an in-scope
        # domain that resolves, that is not real privacy redaction ── a
        # privacy-protected domain still exposes registrar + nameservers.
        # All-empty almost always means a WHOIS library/rate-limit/parse
        # failure, so flag it instead of emitting a misleading
        # "WHOIS Privacy / Registration Anomaly" finding.
        if result.result_count == 0:
            return (
                "WHOIS returned no registrar, dates, or nameservers for the "
                "domain; likely a WHOIS library, rate-limit, or parse failure "
                "rather than genuine privacy redaction"
            )
        return None

"""RDAP — modern structured WHOIS replacement."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

import httpx

from nexusrecon.opsec.useragent import random_ua
from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool


@register_tool
class RDAPTool(OSINTTool):
    name = "rdap"
    tier = Tier.T0
    category = Category.DOMAIN
    requires_keys = []
    description = "RDAP (modern WHOIS) — structured registration data, registrant org, nameservers, lifecycle events"
    target_types = ["domain", "ip"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        target_type = kwargs.get("target_type", "domain")

        try:
            async with httpx.AsyncClient(
                headers={
                    "Accept": "application/rdap+json, application/json",
                    "User-Agent": random_ua(),
                },
                timeout=15.0,
                follow_redirects=True,
            ) as client:
                url = (
                    f"https://rdap.org/ip/{target}"
                    if target_type == "ip"
                    else f"https://rdap.org/domain/{target}"
                )
                resp = await client.get(url)

                if resp.status_code == 404:
                    return ToolResult(success=False, source=self.name, error=f"RDAP: '{target}' not found in registry")
                if resp.status_code != 200:
                    return ToolResult(success=False, source=self.name, error=f"RDAP returned {resp.status_code}")

                raw = resp.json()
                data = self._parse(raw, target_type)

        except Exception as exc:
            return ToolResult(success=False, source=self.name, error=str(exc))

        return ToolResult(success=True, source=self.name, data=data, result_count=1)

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _vcard_field(self, vcard_array: List, field: str) -> Optional[str]:
        for prop in vcard_array:
            if isinstance(prop, list) and prop and prop[0] == field:
                return prop[3] if len(prop) > 3 else None
        return None

    def _parse_entity(self, entity: Dict[str, Any]) -> Dict[str, Any]:
        vcard_props: List = entity.get("vcardArray", [None, []])[1]
        parsed: Dict[str, Any] = {
            "handle": entity.get("handle"),
            "roles": entity.get("roles", []),
            "name": self._vcard_field(vcard_props, "fn"),
            "org": self._vcard_field(vcard_props, "org"),
            "email": self._vcard_field(vcard_props, "email"),
            "phone": self._vcard_field(vcard_props, "tel"),
        }
        return {k: v for k, v in parsed.items() if v}

    def _parse(self, raw: Dict[str, Any], target_type: str) -> Dict[str, Any]:
        events = {e.get("eventAction"): e.get("eventDate") for e in raw.get("events", [])}
        entities = [self._parse_entity(e) for e in raw.get("entities", [])]

        data: Dict[str, Any] = {
            "handle": raw.get("handle"),
            "name": raw.get("ldhName") or raw.get("name"),
            "status": raw.get("status", []),
            "entities": entities,
            "registered": events.get("registration"),
            "last_changed": events.get("last changed"),
            "expiration": events.get("expiration"),
            "nameservers": [
                ns.get("ldhName") for ns in raw.get("nameservers", []) if ns.get("ldhName")
            ],
        }

        if target_type == "ip":
            data.update({
                "start_address": raw.get("startAddress"),
                "end_address": raw.get("endAddress"),
                "ip_version": raw.get("ipVersion"),
                "country": raw.get("country"),
            })

        return data

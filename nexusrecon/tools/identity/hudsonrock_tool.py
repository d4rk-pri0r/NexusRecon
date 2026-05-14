"""Hudson Rock Cavalier — infostealer/malware-log credential lookup."""
from __future__ import annotations

from typing import Any, Dict, List

import httpx

from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool

_BASE = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools"
_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Accept": "application/json",
}


@register_tool
class HudsonRockTool(OSINTTool):
    name = "hudsonrock"
    tier = Tier.T0
    category = Category.BREACH
    requires_keys = []
    description = (
        "Hudson Rock Cavalier — checks whether an email or domain appears in "
        "infostealer malware logs (Raccoon, RedLine, Vidar, etc.)"
    )
    target_types = ["email", "domain"]
    dynamic_trigger_hints = ["infostealer credential found", "comboleak detected"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        target_type = kwargs.get("target_type", "email")
        try:
            if target_type == "email":
                data = await self._check_email(target)
            elif target_type == "domain":
                data = await self._check_domain(target)
            else:
                return ToolResult(
                    success=False,
                    source=self.name,
                    error=f"Unsupported target type: {target_type}",
                )
        except Exception as exc:
            return ToolResult(success=False, source=self.name, error=str(exc))

        compromised = data.get("compromised", False)
        return ToolResult(
            success=True,
            source=self.name,
            data=data,
            result_count=1 if compromised else 0,
        )

    async def _check_email(self, email: str) -> Dict[str, Any]:
        async with httpx.AsyncClient(headers=_HEADERS, timeout=15.0) as client:
            resp = await client.get(
                f"{_BASE}/is-email-compromised",
                params={"email": email},
            )
            if resp.status_code == 404:
                return {"compromised": False, "email": email}
            if resp.status_code != 200:
                return {"error": f"Hudson Rock returned {resp.status_code}"}

            raw = resp.json()
            message = raw.get("message", "")
            # Community endpoint returns details only when compromised
            if not raw.get("stealerFamily") and "not found" in message.lower():
                return {"compromised": False, "email": email, "message": message}

            return {
                "compromised": True,
                "email": email,
                "stealer_family": raw.get("stealerFamily"),
                "computer_name": raw.get("computerName"),
                "operating_system": raw.get("operatingSystem"),
                "date_compromised": raw.get("dateCompromised"),
                "antiviruses": raw.get("antiviruses"),
                "external_ip": raw.get("externalIp"),
                "malware_path": raw.get("malwarePath"),
            }

    async def _check_domain(self, domain: str) -> Dict[str, Any]:
        async with httpx.AsyncClient(headers=_HEADERS, timeout=20.0) as client:
            resp = await client.get(
                f"{_BASE}/is-domain-compromised",
                params={"domain": domain},
            )
            if resp.status_code == 404:
                return {"compromised": False, "domain": domain}
            if resp.status_code != 200:
                return {"error": f"Hudson Rock returned {resp.status_code}"}

            raw = resp.json()
            employees: List[Dict[str, Any]] = raw.get("stealers", [])
            employee_count = raw.get("employeeCredentialsCount", len(employees))
            client_count = raw.get("clientCredentialsCount", 0)

            if not employees and employee_count == 0:
                return {"compromised": False, "domain": domain}

            return {
                "compromised": True,
                "domain": domain,
                "employee_credentials_count": employee_count,
                "client_credentials_count": client_count,
                "stealers": [
                    {
                        "computer_name": s.get("computerName"),
                        "operating_system": s.get("operatingSystem"),
                        "date_compromised": s.get("dateCompromised"),
                        "stealer_family": s.get("stealerFamily"),
                        "antiviruses": s.get("antiviruses"),
                        "external_ip": s.get("externalIp"),
                        "credential_count": len(s.get("credentials", [])),
                    }
                    for s in employees[:25]
                ],
            }

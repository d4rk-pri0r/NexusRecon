"""Hudson Rock Cavalier — infostealer/malware-log credential lookup (D6 enhanced).

D6 changes vs. the original tool:
  - Optional ``HUDSONROCK_API_KEY`` support: when set, the ``X-API-KEY``
    header is added to every request.  The Cavalier paid tier exposes the
    full ``credentials`` array (url, username, password) per stealer session;
    without the key only the system-level fields are returned.
  - ``_check_email`` now surfaces ``captured_credentials`` — a list of
    ``{url, username, password}`` records from the stealer log.  Without
    a key the list is empty (the community endpoint doesn't return it).
  - ``_check_domain`` now includes ``captured_credentials`` per stealer
    session rather than reporting only ``credential_count``.
  - ``captured_urls`` is extracted separately (deduped) to give Phase 2.5
    and D4 an easy list of auth surfaces the stealer recorded against.

Shape contract (fields consumed by ``personal_pivot_tool._extract_credential_exposures``):

    email-check response:
        compromised: bool
        stealer_family: str | None
        computer_name: str | None
        operating_system: str | None
        date_compromised: str | None
        external_ip: str | None
        malware_path: str | None
        antiviruses: list[str] | None
        captured_credentials: list[{url, username, password}]
        captured_urls: list[str]           # deduped urls from captured_credentials

    domain-check response:
        compromised: bool
        employee_credentials_count: int
        client_credentials_count: int
        stealers: list[{
            computer_name, operating_system, date_compromised,
            stealer_family, antiviruses, external_ip,
            captured_credentials: list[{url, username, password}],
            credential_count: int,
        }]
        all_captured_urls: list[str]       # deduped across all stealers
"""
from __future__ import annotations

from typing import Any

import httpx

from nexusrecon.opsec.useragent import random_ua
from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool

_BASE = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools"


def _build_headers(api_key: str | None) -> dict[str, str]:
    """Return headers for the Cavalier request.

    The community tier works without authentication; the paid tier
    requires ``X-API-KEY``.  We always include a rotated UA.
    """
    headers: dict[str, str] = {
        "User-Agent": random_ua(),
        "Accept": "application/json",
    }
    if api_key:
        headers["X-API-KEY"] = api_key
    return headers


def _extract_captured(creds_raw: Any) -> list[dict[str, Any]]:
    """Normalise the ``credentials`` array from a Cavalier stealer record.

    Each entry maps to ``{url, username, password}`` with empty strings
    as defaults so downstream code can do ``if rec["password"]``
    unconditionally.
    """
    if not creds_raw or not isinstance(creds_raw, list):
        return []
    out: list[dict[str, Any]] = []
    for c in creds_raw:
        if not isinstance(c, dict):
            continue
        out.append({
            "url": (c.get("url") or "").strip(),
            "username": (c.get("username") or "").strip(),
            "password": (c.get("password") or c.get("password_hash") or "").strip(),
        })
    return out


def _dedup_urls(creds: list[dict[str, Any]]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for c in creds:
        u = c.get("url", "").strip()
        if u and u not in seen:
            seen.add(u)
            out.append(u)
    return out


@register_tool
class HudsonRockTool(OSINTTool):
    name = "hudsonrock"
    tier = Tier.T0
    category = Category.BREACH
    # API key is optional — the community tier works without it.
    # When present it unlocks the captured-credentials array.
    requires_keys = []
    optional_keys = ["hudsonrock_api_key"]
    description = (
        "Hudson Rock Cavalier — checks whether an email or domain appears in "
        "infostealer malware logs (Raccoon, RedLine, Vidar, etc.). "
        "Set HUDSONROCK_API_KEY for full credential detail (captured URLs, "
        "passwords, and usernames per stealer session)."
    )
    target_types = ["email", "domain"]
    dynamic_trigger_hints = ["infostealer credential found", "comboleak detected"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        # API key is optional; absence degrades to community-tier data only.
        api_key: str | None = self.config.get_secret("hudsonrock_api_key")

        target_type = kwargs.get("target_type", "email")
        try:
            if target_type == "email":
                data = await self._check_email(target, api_key)
            elif target_type == "domain":
                data = await self._check_domain(target, api_key)
            else:
                return ToolResult(
                    success=False,
                    source=self.name,
                    error=f"Unsupported target type: {target_type}",
                )
        except Exception as exc:
            return ToolResult(success=False, source=self.name, error=str(exc))

        # Surface HTTP-level failures as explicit ToolResult errors.
        if isinstance(data, dict) and data.get("error") and "compromised" not in data:
            return ToolResult(
                success=False, source=self.name, error=data["error"],
            )

        compromised = data.get("compromised", False)
        return ToolResult(
            success=True,
            source=self.name,
            data=data,
            result_count=1 if compromised else 0,
        )

    async def _check_email(
        self,
        email: str,
        api_key: str | None,
    ) -> dict[str, Any]:
        headers = _build_headers(api_key)
        async with httpx.AsyncClient(headers=headers, timeout=15.0) as client:
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

            # Community endpoint signals "not found" via a message, not 404.
            if not raw.get("stealerFamily") and "not found" in message.lower():
                return {"compromised": False, "email": email, "message": message}

            # Extract the credentials array (present on paid tier).
            creds_raw = raw.get("credentials") or []
            captured = _extract_captured(creds_raw)
            captured_urls = _dedup_urls(captured)

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
                # D6 additions — empty on community tier.
                "captured_credentials": captured,
                "captured_urls": captured_urls,
                # Useful for the extraction adapter — was this a paid-tier
                # response that included credential detail?
                "has_credential_detail": bool(creds_raw),
            }

    async def _check_domain(
        self,
        domain: str,
        api_key: str | None,
    ) -> dict[str, Any]:
        headers = _build_headers(api_key)
        async with httpx.AsyncClient(headers=headers, timeout=20.0) as client:
            resp = await client.get(
                f"{_BASE}/is-domain-compromised",
                params={"domain": domain},
            )
            if resp.status_code == 404:
                return {"compromised": False, "domain": domain}
            if resp.status_code != 200:
                return {"error": f"Hudson Rock returned {resp.status_code}"}

            raw = resp.json()
            employees: list[dict[str, Any]] = raw.get("stealers", [])
            employee_count = raw.get("employeeCredentialsCount", len(employees))
            client_count = raw.get("clientCredentialsCount", 0)

            if not employees and employee_count == 0:
                return {"compromised": False, "domain": domain}

            # Build per-stealer records including captured credentials.
            # Cap at 25 stealers — full credential arrays per stealer can
            # be very large.
            all_captured_urls: list[str] = []
            seen_urls: set[str] = set()
            stealer_records: list[dict[str, Any]] = []

            for s in employees[:25]:
                creds_raw = s.get("credentials") or []
                captured = _extract_captured(creds_raw)
                for c in captured:
                    u = c.get("url", "")
                    if u and u not in seen_urls:
                        seen_urls.add(u)
                        all_captured_urls.append(u)

                # Per-stealer record — cap captured_credentials at 20
                # to keep payloads manageable.
                stealer_records.append({
                    "computer_name": s.get("computerName"),
                    "operating_system": s.get("operatingSystem"),
                    "date_compromised": s.get("dateCompromised"),
                    "stealer_family": s.get("stealerFamily"),
                    "antiviruses": s.get("antiviruses"),
                    "external_ip": s.get("externalIp"),
                    "malware_path": s.get("malwarePath"),
                    "credential_count": len(creds_raw),
                    # D6: include credential detail when available.
                    "captured_credentials": captured[:20],
                    "has_credential_detail": bool(creds_raw),
                })

            return {
                "compromised": True,
                "domain": domain,
                "employee_credentials_count": employee_count,
                "client_credentials_count": client_count,
                "stealers": stealer_records,
                # D6: deduped URLs across all stealer sessions.
                "all_captured_urls": all_captured_urls,
                "has_credential_detail": any(
                    s["has_credential_detail"] for s in stealer_records
                ),
            }

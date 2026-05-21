"""DeHashed breach database search tool (Phase D5).

DeHashed aggregates breach data and infostealer logs. Unlike HIBP
(presence-only), DeHashed frequently carries cleartext passwords,
hashed credentials, and associated PII — making it the primary source
for the credential correlation module (D4).

Auth: HTTP Basic Auth, ``DEHASHED_USERNAME:DEHASHED_API_KEY``.
Endpoint: ``https://api.dehashed.com/search``
Docs: https://www.dehashed.com/docs

Returned data shape (key field: ``entries``):
    entries[].credential_kind — "password" | "hash" | "presence_only"
    entries[].password        — cleartext (empty string if not present)
    entries[].hashed_password — hash value (empty string if not present)
    entries[].database        — source breach name (e.g. "LinkedIn-2012")
    entries[].email / .username / .phone / .address / .ip_address

Integration notes:
  - ``personal_pivot_tool._extract_credential_exposures`` dispatches
    on ``tool_name == "dehashed"`` and reads this shape.
  - Pass ``target_type="email"`` (default) or ``"username"`` or
    ``"domain"`` — each maps to a DeHashed query field prefix.
  - DeHashed query syntax supports free-form Lucene-style expressions;
    ``target_type="raw"`` skips the field prefix so callers can pass
    ``"email:jane@co.com OR username:jdoe"`` directly.
"""
from __future__ import annotations

import base64
from typing import Any

import httpx

from nexusrecon.opsec.useragent import random_ua
from nexusrecon.tools.base import BaseHTTPTool, Category, Tier, ToolResult
from nexusrecon.tools.registry import register_tool


@register_tool
class DehashedTool(BaseHTTPTool):
    name = "dehashed"
    provider_label = "DeHashed"
    tier = Tier.T0
    category = Category.BREACH
    # Both username (the account email) and the API key are required
    # for HTTP Basic Auth.  Hudson Rock uses a header; DeHashed uses
    # old-school HTTP Basic, so both secrets are mandatory.
    requires_keys = ["dehashed_api_key", "dehashed_username"]
    description = (
        "DeHashed breach database — returns cleartext passwords, hashes, "
        "and PII for emails, usernames, or domains"
    )
    target_types = ["email", "username", "domain"]
    dynamic_trigger_hints = [
        "personal email confirmed",
        "breach correlation requested",
        "credential exposure check",
        "password spray candidate",
        "dehashed lookup requested",
    ]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        username = self.config.get_secret("dehashed_username")
        api_key = self.config.get_secret("dehashed_api_key")
        if not username or not api_key:
            return ToolResult(
                success=False,
                source=self.name,
                error="DEHASHED_USERNAME and DEHASHED_API_KEY both required",
            )

        # Build the query string.  "raw" skips field prefixing.
        target_type = kwargs.get("target_type", "email")
        if target_type == "raw":
            query = target
        elif target_type in ("email", "username", "domain", "ip_address",
                             "address", "phone", "vin", "name"):
            query = f"{target_type}:{target}"
        else:
            # Unknown type — treat as raw and let DeHashed parse it.
            query = target

        # HTTP Basic Auth: base64(username:api_key)
        auth_raw = f"{username}:{api_key}".encode()
        auth_header = f"Basic {base64.b64encode(auth_raw).decode()}"

        try:
            async with httpx.AsyncClient(
                base_url="https://api.dehashed.com",
                headers={
                    "Authorization": auth_header,
                    "Accept": "application/json",
                    "User-Agent": random_ua(),
                },
                timeout=20.0,
                **self._proxy_kwargs(),
            ) as client:
                resp = await client.get(
                    "/search",
                    params={
                        "query": query,
                        "size": int(kwargs.get("size", 50)),
                        "page": int(kwargs.get("page", 1)),
                    },
                )
                fail = self.classify_response(resp, "search")
                if fail is not None:
                    return fail

                raw = resp.json()

        except Exception as exc:
            return ToolResult(success=False, source=self.name, error=str(exc))

        entries_raw: list[Any] = raw.get("entries") or []
        entries: list[dict[str, Any]] = []

        for e in entries_raw:
            if not isinstance(e, dict):
                continue

            pwd = (e.get("password") or "").strip()
            hpwd = (e.get("hashed_password") or "").strip()

            # Classify credential kind.
            #   "password"     — cleartext is present
            #   "hash"         — only a hash is present (may be crackable)
            #   "presence_only"— neither; useful as correlation signal only
            if pwd:
                cred_kind = "password"
            elif hpwd:
                cred_kind = "hash"
            else:
                cred_kind = "presence_only"

            entry: dict[str, Any] = {
                "id": e.get("id"),
                "email": (e.get("email") or "").strip() or None,
                "username": (e.get("username") or "").strip() or None,
                "name": (e.get("name") or "").strip() or None,
                "database": (
                    e.get("database_name") or e.get("database") or ""
                ).strip() or None,
                # "obtained_from" is DeHashed's field for breach date/source.
                "breach_date": (
                    e.get("obtained_from") or e.get("breach_date") or ""
                ).strip() or None,
                "phone": (e.get("phone") or "").strip() or None,
                "address": (e.get("address") or "").strip() or None,
                "ip_address": (e.get("ip_address") or "").strip() or None,
                "vin": (e.get("vin") or "").strip() or None,
                # Credential fields — kept as empty strings (not None)
                # so downstream code can do ``if entry["password"]``
                # without key-existence checks.
                "password": pwd,
                "hashed_password": hpwd,
                "hash_type": (e.get("hash_type") or "").strip() or None,
                "credential_kind": cred_kind,
            }
            entries.append(entry)

        # Quick stats for the calling phase.
        by_kind: dict[str, int] = {}
        for entry in entries:
            k = entry["credential_kind"]
            by_kind[k] = by_kind.get(k, 0) + 1

        # ``total`` is the full-match count across all pages;
        # ``len(entries)`` is what we fetched in this page.
        total = int(raw.get("total") or len(entries))

        return ToolResult(
            success=True,
            source=self.name,
            data={
                "query": query,
                "total": total,
                "page": int(kwargs.get("page", 1)),
                "entries": entries,
                "by_credential_kind": by_kind,
                # DeHashed returns the caller's remaining API balance.
                "balance": raw.get("balance"),
            },
            result_count=len(entries),
        )

"""Breach data correlation tool — HIBP API + optional DeHashed/IntelX."""
from __future__ import annotations

import base64
from typing import Any

import httpx

from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool


@register_tool
class BreachTool(OSINTTool):
    name = "breach_lookup"
    tier = Tier.T0
    category = Category.BREACH
    requires_keys = ["haveibeenpwned_api_key"]
    description = "Breach data lookup via HIBP API, optional DeHashed and IntelX"
    target_types = ["email", "domain"]
    dynamic_trigger_hints = ["credential breach found", "email breach detected"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        results: dict[str, Any] = {}
        target_type = kwargs.get("target_type", "email")

        # HIBP
        hibp_result = await self._check_hibp(target, target_type)
        results["hibp"] = hibp_result

        # DeHashed (optional)
        dehashed_key = self.config.get_secret("dehashed_api_key")
        dehashed_user = self.config.get_secret("dehashed_username")
        if dehashed_key and dehashed_user:
            dehashed_result = await self._check_dehashed(target, target_type, dehashed_user, dehashed_key)
            results["dehashed"] = dehashed_result

        # IntelX (optional)
        intelx_key = self.config.get_secret("intelx_api_key")
        if intelx_key:
            intelx_result = await self._check_intelx(target, target_type, intelx_key)
            results["intelx"] = intelx_result

        total_breaches = len(hibp_result.get("breaches", []))
        return ToolResult(
            success=True, source=self.name, data=results,
            result_count=total_breaches,
        )

    async def _check_hibp(self, target: str, target_type: str) -> dict[str, Any]:
        key = self.config.get_secret("haveibeenpwned_api_key")
        if not key:
            return {"error": "HIBP API key not set"}

        try:
            client = httpx.AsyncClient(
                base_url="https://haveibeenpwned.com/api/v3",
                headers={
                    "hibp-api-key": key,
                    "User-Agent": "NexusRecon/1.0",
                },
                timeout=15.0,
            )

            if target_type == "email":
                resp = await client.get(f"/breachedaccount/{target}", params={"truncateResponse": True})
            elif target_type == "domain":
                resp = await client.get(f"/breaches?domain={target}")
            else:
                return {"error": f"Unsupported target type: {target_type}"}

            if resp.status_code == 200:
                breaches = resp.json()
                return {
                    "found": True,
                    "breach_count": len(breaches),
                    "breaches": [
                        {
                            "name": b.get("Name"),
                            "date": b.get("BreachDate"),
                            "domain": b.get("Domain"),
                            "data_classes": b.get("DataClasses", []),
                            "description": b.get("Description", "")[:200],
                        }
                        for b in breaches
                    ],
                }
            elif resp.status_code == 404:
                return {"found": False, "breach_count": 0, "breaches": []}
            else:
                return {"error": f"HIBP returned status {resp.status_code}"}

        except Exception as e:
            return {"error": str(e)}

    async def _check_dehashed(self, target: str, target_type: str, username: str, api_key: str) -> dict[str, Any]:
        """Query DeHashed API for breach data."""
        try:
            auth_str = base64.b64encode(f"{username}:{api_key}".encode()).decode()
            async with httpx.AsyncClient(
                base_url="https://api.dehashed.com",
                headers={"Accept": "application/json", "Authorization": f"Basic {auth_str}"},
                timeout=15.0,
            ) as client:
                query_field = "email" if target_type == "email" else "domain"
                resp = await client.get("/search", params={"query": f"{query_field}:{target}", "size": 100})
                if resp.status_code == 200:
                    data = resp.json()
                    entries = data.get("entries", [])
                    return {
                        "found": len(entries) > 0,
                        "result_count": data.get("total", len(entries)),
                        "entries": [
                            {
                                "email": e.get("email", ""),
                                "password": e.get("password", "")[:20] if e.get("password") else None,
                                "hash": e.get("hash", "")[:20] if e.get("hash") else None,
                                "database_name": e.get("database_name", ""),
                                "ip_address": e.get("ip_address", ""),
                                "username": e.get("username", ""),
                            }
                            for e in entries[:50]
                        ],
                    }
                else:
                    return {"error": f"DeHashed returned {resp.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    async def _check_intelx(self, target: str, target_type: str, api_key: str) -> dict[str, Any]:
        """Query IntelX API for breach/intelligence data."""
        try:
            selectors = {"email": "email", "domain": "domain", "phone": "phone", "username": "username"}
            selector = selectors.get(target_type, "email")
            async with httpx.AsyncClient(
                base_url="https://2.intelx.io",
                headers={"x-key": api_key, "Accept": "application/json", "User-Agent": "NexusRecon/1.0"},
                timeout=20.0,
            ) as client:
                resp = await client.get("/phonebook/search", params={"selector": target, "type": selector, "maxresults": 100})
                if resp.status_code == 200:
                    data = resp.json()
                    records = data.get("records", [])
                    return {
                        "found": len(records) > 0,
                        "result_count": data.get("total", len(records)),
                        "records": [
                            {
                                "key": r.get("key", ""),
                                "value": r.get("value", ""),
                            }
                            for r in records[:50]
                        ],
                    }
                else:
                    return {"error": f"IntelX returned {resp.status_code}"}
        except Exception as e:
            return {"error": str(e)}

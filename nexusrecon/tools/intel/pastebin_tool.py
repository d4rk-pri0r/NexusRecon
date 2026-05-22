"""Pastebin / GitHub Gist leak scanner — find exposed credentials referencing the target."""
from __future__ import annotations

import asyncio
import base64
import re
from typing import Any

import httpx

from nexusrecon.core.credential_harvester import CRED_PATTERNS
from nexusrecon.opsec.useragent import random_ua
from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool

_HEADERS = {
    "User-Agent": random_ua(),
    "Accept": "application/json",
}


def _scan_secrets(text: str) -> list[dict[str, str]]:
    found = []
    for cred_type, pattern in CRED_PATTERNS:
        if re.search(pattern, text):
            found.append({"type": cred_type, "pattern": pattern[:40]})
    return found


@register_tool
class PastebinTool(OSINTTool):
    name = "pastebin_scan"
    tier = Tier.T0
    category = Category.INFRASTRUCTURE
    requires_keys = []
    optional_keys = ["github_token"]
    description = "Search psbdmp.ws and GitHub Gists for target domain/email leaks"
    target_types = ["domain", "email"]
    dynamic_trigger_hints = ["paste leak found", "credentials in paste"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        pastes: list[dict[str, Any]] = []

        async with httpx.AsyncClient(headers=_HEADERS, timeout=15.0, follow_redirects=True) as client:
            psbdmp_pastes = await self._search_psbdmp(client, target)
            gist_pastes = await self._search_github_gists(client, target)
            pastes.extend(psbdmp_pastes)
            pastes.extend(gist_pastes)

        return ToolResult(
            success=True,
            source=self.name,
            data={"target": target, "paste_count": len(pastes), "pastes": pastes},
            result_count=len(pastes),
        )

    async def _search_psbdmp(self, client: httpx.AsyncClient, query: str) -> list[dict[str, Any]]:
        pastes = []
        try:
            resp = await client.get(f"https://psbdmp.ws/api/search/{query}")
            if resp.status_code != 200:
                return pastes
            data = resp.json()
            ids = [item.get("id") for item in (data if isinstance(data, list) else data.get("data", []))][:20]

            sem = asyncio.Semaphore(5)

            async def _fetch_body(paste_id: str) -> dict[str, Any] | None:
                async with sem:
                    try:
                        r = await client.get(f"https://psbdmp.ws/api/dump/get/{paste_id}", timeout=10.0)
                        if r.status_code != 200:
                            return None
                        body = r.text
                        return {
                            "source": "psbdmp",
                            "id": paste_id,
                            "url": f"https://psbdmp.ws/{paste_id}",
                            "leaked_secrets": _scan_secrets(body),
                            "context_excerpt": body[:200],
                        }
                    except Exception:
                        return None

            results = await asyncio.gather(*(_fetch_body(pid) for pid in ids if pid), return_exceptions=True)
            for r in results:
                if isinstance(r, dict):
                    pastes.append(r)
        except Exception:
            pass
        return pastes

    async def _search_github_gists(self, client: httpx.AsyncClient, query: str) -> list[dict[str, Any]]:
        pastes = []
        github_token = self.config.get_secret("github_token")
        headers = dict(_HEADERS)
        if github_token:
            headers["Authorization"] = f"token {github_token}"
        try:
            resp = await client.get(
                "https://api.github.com/search/code",
                params={"q": query, "per_page": 20},
                headers=headers,
            )
            if resp.status_code != 200:
                return pastes
            items = resp.json().get("items", [])
            for item in items[:20]:
                gist_url = item.get("html_url", "")
                raw_url = item.get("url", "")
                body = ""
                try:
                    if raw_url:
                        r = await client.get(raw_url, headers=headers, timeout=10.0)
                        if r.status_code == 200:
                            # ``/search/code`` items' ``url`` returns the
                            # GitHub Contents API response, which encodes
                            # the file body in base64. Decoding gives the
                            # real source text we want to scan; without
                            # this step every credential regex misses
                            # because base64 input doesn't match any
                            # ``CRED_PATTERNS`` we have.
                            payload = r.json()
                            encoded = payload.get("content", "")
                            encoding = payload.get("encoding", "")
                            if encoded and encoding == "base64":
                                try:
                                    body = base64.b64decode(encoded).decode(
                                        "utf-8", errors="replace"
                                    )
                                except Exception:
                                    body = ""
                            else:
                                # Older shapes (or non-base64 encodings)
                                # — pass through as-is.
                                body = encoded
                except Exception:
                    pass
                pastes.append({
                    "source": "github_gist",
                    "id": item.get("sha", ""),
                    "url": gist_url,
                    "leaked_secrets": _scan_secrets(body),
                    "context_excerpt": body[:200],
                })
        except Exception:
            pass
        return pastes

"""Holehe ── check which online services an email is registered with.

Wraps the ``holehe`` Python library, which ships ~121 modules (one per
checked service). Each module makes an HTTP request to a service-
specific endpoint (password reset, signup probe, etc.) and reports
whether the email is registered.

Two design points that changed during Day 6 OPSEC hardening:

  - ``_HEADERS`` used to be module-scope, freezing the User-Agent at
    import time. Every holehe invocation in the same Python process
    then sent the same UA, defeating the rotation pool. Headers are
    now built per-``run()`` so each campaign-time invocation gets a
    fresh UA.
  - The internal ``httpx.AsyncClient`` now spreads
    ``proxy_kwargs()`` so holehe's ~121 outbound requests route
    through the campaign proxy when one is bound. Previously they
    bypassed the proxy manager entirely.
"""
from __future__ import annotations

import asyncio
from typing import Any, Dict, List

import httpx

from nexusrecon.opsec.context import proxy_kwargs
from nexusrecon.opsec.useragent import random_ua
from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool


@register_tool
class HoloTool(OSINTTool):
    name = "holehe"
    tier = Tier.T0
    category = Category.IDENTITY
    requires_keys = []
    description = "Check ~120 online services for email registration via holehe"
    target_types = ["email"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        try:
            from holehe.core import get_functions, import_submodules
        except ImportError:
            return ToolResult(
                success=False,
                source=self.name,
                error="holehe library not installed ── run: pip install holehe",
            )

        try:
            modules = import_submodules("holehe.modules")
            funcs = get_functions(modules)
        except Exception as exc:
            return ToolResult(success=False, source=self.name, error=f"holehe init failed: {exc}")

        # Build headers per-run so each campaign-time invocation gets a
        # fresh User-Agent off the rotation pool. The old module-scope
        # ``_HEADERS = {"User-Agent": random_ua(), ...}`` froze the UA
        # at import, undermining the rotation across calls.
        headers = {
            "User-Agent": random_ua(),
            "Accept": "application/json",
        }

        out: List[Dict[str, Any]] = []
        async with httpx.AsyncClient(
            headers=headers,
            timeout=10.0,
            follow_redirects=True,
            **proxy_kwargs(),
        ) as client:
            tasks = [func(target, client, out) for func in funcs]
            await asyncio.gather(*tasks, return_exceptions=True)

        registered = [
            {"service": item["name"], "details": {
                k: v for k, v in item.items()
                if k not in ("name", "rateLimit") and v
            }}
            for item in out
            if item.get("exists") is True
        ]

        return ToolResult(
            success=True,
            source=self.name,
            data={
                "email": target,
                "registered_count": len(registered),
                "registered_services": registered,
            },
            result_count=len(registered),
        )

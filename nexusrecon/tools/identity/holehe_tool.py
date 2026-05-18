"""Holehe — check which online services an email is registered with."""
from __future__ import annotations

import asyncio
from typing import Any, Dict, List

import httpx

from nexusrecon.opsec.useragent import random_ua
from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool

_HEADERS = {
    "User-Agent": random_ua(),
    "Accept": "application/json",
}


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
                error="holehe library not installed — run: pip install holehe",
            )

        try:
            modules = import_submodules("holehe.modules")
            funcs = get_functions(modules)
        except Exception as exc:
            return ToolResult(success=False, source=self.name, error=f"holehe init failed: {exc}")

        out: List[Dict[str, Any]] = []
        async with httpx.AsyncClient(headers=_HEADERS, timeout=10.0, follow_redirects=True) as client:
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

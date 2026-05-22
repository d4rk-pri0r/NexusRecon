"""Postman public workspace enumeration tool."""
from __future__ import annotations

import re
from typing import Any

import httpx

from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool


@register_tool
class PostmanTool(OSINTTool):
    name = "postman"
    tier = Tier.T0
    category = Category.CODE
    requires_keys = []
    description = "Postman public workspace enumeration for leaked API configs"
    target_types = ["domain"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        try:
            client = httpx.AsyncClient(timeout=10.0, http2=True)
            org_name = target.split(".")[0].lower()

            # Search for public workspaces
            urls = [
                f"https://www.postman.com/{org_name}",
                f"https://www.postman.com/{target.replace('.', '-')}",
                f"https://www.postman.com/{org_name}-api",
            ]

            found = []
            for url in urls:
                try:
                    resp = await client.get(url)
                    if resp.status_code != 404:
                        # Extract workspace IDs and collection names
                        ws_matches = re.findall(r'workspace/([a-zA-Z0-9-]+)', resp.text)
                        found.append({
                            "url": url, "status": resp.status_code,
                            "workspaces": list(set(ws_matches)),
                        })
                except Exception:
                    continue

            await client.aclose()
            return ToolResult(
                success=True, source=self.name, data={"workspaces": found},
                result_count=sum(len(f.get("workspaces", [])) for f in found),
            )
        except Exception as e:
            return ToolResult(success=False, source=self.name, error=str(e))

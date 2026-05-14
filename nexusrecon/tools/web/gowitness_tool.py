"""gowitness screenshot tool (T2 stub)."""
from __future__ import annotations
from typing import Any, Optional
from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool


@register_tool
class GowitnessTool(OSINTTool):
    name = "gowitness"
    tier = Tier.T2
    category = Category.WEB
    requires_keys = []
    binary_required = "gowitness"
    description = "Screenshot triage at scale via gowitness (T2 stub)"
    target_types = ["domain", "subdomain"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        return ToolResult(success=True, source=self.name, data={"status": "stubbed — T2 requires gowitness binary"}, result_count=0)

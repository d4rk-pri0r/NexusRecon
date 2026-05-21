"""gowitness screenshot tool — stub awaiting real wrapping (T2).

The class is registered so the surface is discoverable (operators
can see "yes, a gowitness wrapper is planned") and so future
implementation lands without registration churn. But ``stubbed =
True`` keeps the tool out of ``available_tools()``; the dispatcher
and direct registry invocations skip it. Manual calls receive a
clean failure ToolResult rather than the previous misleading
``success=True, status=stubbed`` shape.
"""
from __future__ import annotations

from typing import Any

from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool


@register_tool
class GowitnessTool(OSINTTool):
    name = "gowitness"
    tier = Tier.T2
    category = Category.WEB
    requires_keys = []
    binary_required = "gowitness"
    description = "Screenshot triage at scale via gowitness"
    target_types = ["domain", "subdomain"]
    stubbed = True

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        return ToolResult(
            success=False,
            source=self.name,
            error=(
                "gowitness tool is stubbed — not implemented yet. "
                "Set stubbed = False and implement run() before invoking."
            ),
        )

"""Google/Bing dork automation tool: stub, SERP scraping is defeated (T0).

The class stays registered so the surface is discoverable (operators can
see a dork tool is planned) and a future real search backend lands without
registration churn. But the two SERP HTML scrapers it shipped are defeated
by 2026 consent walls and anti-bot markup, so there is no working search
path. ``stubbed = True`` keeps the tool out of ``available_tools()`` and the
dispatcher; manual calls receive a clean failure ToolResult instead of the
previous ``success=True, result_count=0`` shape, which reported a scraping
failure as a fake clean negative. Set ``stubbed = False`` and wire a real
search API before invoking.
"""
from __future__ import annotations

from typing import Any

from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool


@register_tool
class DorksTool(OSINTTool):
    name = "dorks"
    tier = Tier.T0
    category = Category.WEB
    requires_keys = []
    description = "Google dork automation (stubbed: SERP scraping defeated by consent walls)"
    target_types = ["domain"]
    stubbed = True

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        return ToolResult(
            success=False,
            source=self.name,
            error=(
                "dorks tool is stubbed: Google/Bing SERP HTML scraping is "
                "defeated by 2026 consent walls and anti-bot markup, so there "
                "is no working search backend. Set stubbed = False and wire a "
                "real search API before invoking."
            ),
        )

"""gau — URL discovery via GetAllUrls."""
from __future__ import annotations
from typing import Any, Optional
from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool


@register_tool
class GAUTool(OSINTTool):
    name = "gau"
    tier = Tier.T0
    category = Category.WEB
    requires_keys = []
    binary_required = "gau"
    description = "URL discovery via GetAllUrls binary (stubbed)"
    target_types = ["domain"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        if not self.is_available():
            return ToolResult(success=False, source=self.name, error="gau binary not found")
        try:
            cmd = ["gau", target, "--subs", "--providers", "wayback,commoncrawl,otx,urlscan"]
            result = self.run_subprocess(cmd, timeout_sec=300)
            urls = [u.strip() for u in result.stdout.strip().split("\n") if u.strip()]
            return ToolResult(success=True, source=self.name, data={"urls": urls}, result_count=len(urls))
        except Exception as e:
            return ToolResult(success=False, source=self.name, error=str(e))

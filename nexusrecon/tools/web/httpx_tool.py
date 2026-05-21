"""httpx tool — active web probing (T2 gated)."""
from __future__ import annotations

from typing import Any

from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool


@register_tool
class HTTPxTool(OSINTTool):
    name = "httpx"
    tier = Tier.T2
    category = Category.WEB
    requires_keys = []
    binary_required = "httpx"
    description = "Active HTTP probing via httpx binary (T2)"
    target_types = ["domain", "subdomain"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        if not self.is_available():
            return ToolResult(success=False, source=self.name, error="httpx binary not found")
        try:
            cmd = ["httpx", "-u", target, "-json", "-status-code", "-title", "-tech-detect", "-content-length", "-follow-redirects"]
            result = self.run_subprocess(cmd, timeout_sec=120)
            results = []
            for line in result.stdout.strip().split("\n"):
                if line.strip():
                    try:
                        import json
                        results.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
            return ToolResult(success=True, source=self.name, data={"results": results}, result_count=len(results))
        except Exception as e:
            return ToolResult(success=False, source=self.name, error=str(e))

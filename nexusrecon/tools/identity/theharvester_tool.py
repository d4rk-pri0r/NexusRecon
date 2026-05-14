"""theHarvester wrapper tool."""
from __future__ import annotations
import shutil
import subprocess
from typing import Any, Dict, List, Optional
from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool


@register_tool
class TheHarvesterTool(OSINTTool):
    name = "theharvester"
    tier = Tier.T0
    category = Category.EMAIL
    requires_keys = []
    description = "Email, subdomain, and name enumeration via theHarvester"
    target_types = ["domain"]
    dynamic_trigger_hints = ["email address discovered", "employee name found"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        try:
            # B21: support both camelCase and lowercase binary names
            harvester_bin = shutil.which("theHarvester") or shutil.which("theharvester")
            if not harvester_bin:
                return ToolResult(
                    success=False,
                    source=self.name,
                    error=(
                        "theHarvester binary not found in PATH "
                        "(tried 'theHarvester' and 'theharvester')"
                    ),
                )
            sources = kwargs.get("sources", "all")
            limit = kwargs.get("limit", 500)
            cmd = [
                harvester_bin, "-d", target,
                "-b", sources, "-l", str(limit),
                "-f", "/dev/stdout", "--format", "json",
            ]
            result = self.run_subprocess(cmd, timeout_sec=300)

            # Parse output
            data: Dict[str, Any] = {}
            if result.stdout.strip():
                try:
                    import json
                    data = json.loads(result.stdout)
                except json.JSONDecodeError:
                    # Fallback: parse text output
                    data = {"raw": result.stdout[:5000]}

            emails = data.get("emails", [])
            subdomains = data.get("hosts", [])

            return ToolResult(
                success=True, source=self.name, data=data,
                result_count=len(emails) + len(subdomains),
            )
        except Exception as e:
            return ToolResult(success=False, source=self.name, error=str(e))

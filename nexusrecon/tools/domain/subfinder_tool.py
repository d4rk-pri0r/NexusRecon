"""Subfinder tool — wraps the subfinder CLI binary."""
from __future__ import annotations
from typing import Any, Optional
from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool


@register_tool
class SubfinderTool(OSINTTool):
    name = "subfinder"
    tier = Tier.T0
    category = Category.SUBDOMAIN
    requires_keys = []
    binary_required = "subfinder"
    description = "Passive subdomain enumeration via subfinder binary"
    target_types = ["domain"]
    dynamic_trigger_hints = ["new subdomain found", "subdomain enumeration gap"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        if not self.is_available():
            return ToolResult(success=False, source=self.name, error="subfinder binary not found")

        try:
            recursive = kwargs.get("recursive", False)
            all_sources = kwargs.get("all_sources", True)
            cmd = ["subfinder", "-d", target, "-silent", "-json"]
            if all_sources:
                cmd.append("-all")
            if recursive:
                cmd.extend(["-recursive"])

            result = self.run_subprocess(cmd, timeout_sec=300)

            subdomains = []
            for line in result.stdout.strip().split("\n"):
                if line.strip():
                    try:
                        import json
                        entry = json.loads(line)
                        subdomains.append({
                            "subdomain": entry.get("host", ""),
                            "source": entry.get("source", ""),
                        })
                    except json.JSONDecodeError:
                        subdomains.append({"subdomain": line.strip(), "source": "unknown"})

            return ToolResult(
                success=True, source=self.name,
                data={"subdomains": subdomains},
                result_count=len(subdomains),
            )
        except Exception as e:
            return ToolResult(success=False, source=self.name, error=str(e))

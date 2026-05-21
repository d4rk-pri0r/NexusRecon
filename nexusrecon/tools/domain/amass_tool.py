"""Amass passive mode tool — wraps OWASP Amass CLI."""
from __future__ import annotations

from typing import Any

from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool


@register_tool
class AmassTool(OSINTTool):
    name = "amass"
    tier = Tier.T0
    category = Category.SUBDOMAIN
    requires_keys = []
    binary_required = "amass"
    description = "Passive subdomain enumeration via amass intel and enum"
    target_types = ["domain"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        if not self.is_available():
            return ToolResult(success=False, source=self.name, error="amass binary not found")

        try:
            cmd = [
                "amass", "enum",
                "-d", target,
                "-passive",
                "-nocolor",
                "-norecursive",
                "-json", "/dev/stdout",
            ]
            result = self.run_subprocess(cmd, timeout_sec=600)

            subdomains = []
            for line in result.stdout.strip().split("\n"):
                if line.strip():
                    try:
                        import json
                        entry = json.loads(line)
                        subdomains.append({
                            "subdomain": entry.get("name", ""),
                            "source": entry.get("source", ""),
                            "addresses": entry.get("addresses", []),
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

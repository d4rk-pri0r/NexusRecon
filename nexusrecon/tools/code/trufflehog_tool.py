"""TruffleHog v3 tool — wraps trufflehog CLI for deep secret scanning."""

from __future__ import annotations

import json
from typing import Any

from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool


@register_tool
class TruffleHogTool(OSINTTool):
    name = "trufflehog"
    tier = Tier.T0
    category = Category.SECRET
    requires_keys = []
    binary_required = "trufflehog"
    description = "Deep secret scanning via TruffleHog v3 binary"
    target_types = ["repository"]
    dynamic_trigger_hints = ["secret found in git", "credential leaked in repo"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        if not self.is_available():
            return ToolResult(success=False, source=self.name, error="trufflehog binary not found")

        try:
            if target.startswith("http"):
                # GitHub repo URL
                cmd = ["trufflehog", "github", "--repo", target, "--json"]
            elif "/" in target and not target.startswith("http"):
                # Local repo path
                cmd = ["trufflehog", "filesystem", "--directory", target, "--json"]
            else:
                # Treat as org name — search GitHub
                cmd = ["trufflehog", "github", "--org", target, "--json"]

            if kwargs.get("only_verified"):
                cmd.append("--only-verified")

            result = self.run_subprocess(cmd, timeout_sec=600)

            findings = []
            for line in result.stdout.strip().split("\n"):
                if line.strip():
                    try:
                        finding = json.loads(line)
                        findings.append(finding)
                    except json.JSONDecodeError:
                        continue

            return ToolResult(
                success=True, source=self.name,
                data={"findings": findings},
                result_count=len(findings),
            )
        except Exception as e:
            return ToolResult(success=False, source=self.name, error=str(e))

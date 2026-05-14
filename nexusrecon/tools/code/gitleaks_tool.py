"""gitleaks tool — wraps the gitleaks CLI binary for secret scanning."""

from __future__ import annotations
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Optional
from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool


@register_tool
class GitleaksTool(OSINTTool):
    name = "gitleaks"
    tier = Tier.T0
    category = Category.SECRET
    requires_keys = []
    binary_required = "gitleaks"
    description = "Secret scanning via gitleaks binary (local clone or git repo)"
    target_types = ["repository"]
    dynamic_trigger_hints = ["secret found in git", "api key leaked"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        if not self.is_available():
            return ToolResult(success=False, source=self.name, error="gitleaks binary not found")

        try:
            repo_path = kwargs.get("repo_path")
            cmd = [
                "gitleaks", "detect",
                "--source", repo_path or target,
                "--report-format", "json",
                "--report-path", "/dev/stdout",
                "--no-banner",
            ]
            if kwargs.get("all_branches"):
                cmd.append("--no-gitleaks-ignore")

            result = self.run_subprocess(cmd, timeout_sec=300)

            if result.returncode == 1 and not result.stdout.strip():
                # No leaks found (gitleaks returns 1 for no findings)
                return ToolResult(success=True, source=self.name, data={"leaks": []}, result_count=0)

            try:
                leaks = json.loads(result.stdout) if result.stdout.strip() else []
            except json.JSONDecodeError:
                leaks = []

            return ToolResult(
                success=True,
                source=self.name,
                data={"leaks": leaks},
                raw_output=result.stdout[:5000],
                result_count=len(leaks),
            )
        except Exception as e:
            return ToolResult(success=False, source=self.name, error=str(e))

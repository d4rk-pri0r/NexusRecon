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
            return ToolResult(
                success=True, source=self.name,
                data={
                    "results": results,
                    # Wave F-A1: keep the subprocess outcome so assess_result
                    # can tell a failed probe from a host that simply isn't
                    # serving HTTP.
                    "returncode": result.returncode,
                    "stderr_tail": (result.stderr or "")[-800:].strip(),
                },
                result_count=len(results),
            )
        except Exception as e:
            return ToolResult(success=False, source=self.name, error=str(e))

    def assess_result(self, result: ToolResult, target: str, target_type: str = "domain") -> str | None:
        # httpx emitting zero rows for a host that simply is not serving HTTP is
        # a legitimate negative (the binary still exits 0). Only a non-zero exit
        # proves the probe itself failed, so key strictly on the exit code and
        # never on emptiness alone, to avoid crying wolf on down hosts.
        if result.result_count > 0:
            return None
        d = result.data or {}
        if d.get("returncode", 0) != 0:
            detail = d.get("stderr_tail") or f"exit code {d.get('returncode')}"
            return (
                "httpx returned no probe results and exited non-zero; the probe "
                f"failed rather than the host being a clean negative: {detail[:200]}"
            )
        return None

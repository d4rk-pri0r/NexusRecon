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
            # Capture the process outcome instead of discarding it. httpx
            # exits 0 even when a host simply is not live (a legitimate
            # empty), but exits non-zero on flag or startup errors that
            # leave stdout empty; previously both looked like a clean "no
            # live host" result. A non-zero exit with nothing parsed is a
            # real failure the entity graph must not treat as an absence.
            returncode = result.returncode
            stderr_tail = (result.stderr or "")[-800:].strip()
            if returncode != 0 and not results:
                return ToolResult(
                    success=False, source=self.name,
                    error=(
                        f"httpx exited {returncode} with no probe results"
                        + (f": {stderr_tail}" if stderr_tail else "")
                    ),
                )
            return ToolResult(
                success=True, source=self.name,
                data={
                    "results": results,
                    "returncode": returncode,
                    "stderr_tail": stderr_tail,
                },
                result_count=len(results),
            )
        except Exception as e:
            return ToolResult(success=False, source=self.name, error=str(e))

    def assess_result(self, result: ToolResult, target: str, target_type: str = "domain") -> str | None:
        # A non-zero exit is an objective anomaly. run() already fails the empty
        # case (non-zero exit + no rows -> success=False), so reaching here
        # non-zero means httpx produced some rows but did not finish cleanly;
        # the probe set is likely incomplete.
        #
        # httpx's exit-0-but-empty failures (a dead proxy, an unresolvable
        # resolver, an all-timeout run) are deliberately NOT flagged via stderr
        # markers: empirically httpx writes those error strings only under -v,
        # which the command does not pass, so a marker check would be inert; and
        # at default verbosity an exit-0 empty is indistinguishable from a
        # genuinely down host, so flagging it would cry wolf. Once subprocess
        # tools are proxy-routed (ROADMAP #3 follow-up) the dead-proxy case is
        # better closed by a proxy-reachability preflight than by parsing httpx
        # output.
        d = result.data or {}
        if d.get("returncode", 0) != 0:
            detail = d.get("stderr_tail") or f"exit code {d.get('returncode')}"
            return (
                "httpx exited non-zero after emitting partial output; the probe set "
                f"is likely incomplete: {detail[:200]}"
            )
        return None

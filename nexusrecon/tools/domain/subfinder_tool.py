"""Subfinder tool — wraps the subfinder CLI binary."""
from __future__ import annotations

from typing import Any

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

            # Capture the process outcome instead of discarding it.
            # subfinder exits non-zero on resolver, network, or config
            # failures that leave stdout empty; previously that looked
            # identical to a clean "no subdomains" run, so a silent
            # enumeration failure was reported as a genuine negative. A
            # non-zero exit with nothing parsed is a real failure.
            returncode = result.returncode
            stderr_tail = (result.stderr or "")[-800:].strip()
            if returncode != 0 and not subdomains:
                return ToolResult(
                    success=False, source=self.name,
                    error=(
                        f"subfinder exited {returncode} with no subdomains"
                        + (f": {stderr_tail}" if stderr_tail else "")
                    ),
                )

            return ToolResult(
                success=True, source=self.name,
                data={
                    "subdomains": subdomains,
                    "returncode": returncode,
                    "stderr_tail": stderr_tail,
                },
                result_count=len(subdomains),
            )
        except Exception as e:
            return ToolResult(success=False, source=self.name, error=str(e))

    def assess_result(self, result: ToolResult, target: str, target_type: str = "domain") -> str | None:
        # A non-zero exit is an objective anomaly. run() already fails the
        # empty case (non-zero exit + no subdomains -> success=False), so
        # reaching here with a non-zero code means subfinder emitted some names
        # but did not finish cleanly, so the list is likely truncated. Never a
        # false positive: the exit code is real.
        #
        # subfinder's exit-0-but-empty failures (a dead proxy, blocked egress,
        # or every source throttled) are deliberately NOT guessed at here.
        # Empirically, under -silent subfinder writes nothing to stderr on any
        # exit-0 path, so there is no marker that separates "all sources failed"
        # from "genuinely no subdomains" -- flagging on stderr would either be
        # inert or cry wolf on a real empty. Closing that gap needs the
        # per-source -stats signal (a follow-up noted in ROADMAP #5), not a
        # returncode/stderr heuristic.
        d = result.data or {}
        if d.get("returncode", 0) != 0:
            detail = d.get("stderr_tail") or f"exit code {d.get('returncode')}"
            return (
                "subfinder exited non-zero after emitting partial output; the "
                f"subdomain list is likely incomplete: {detail[:200]}"
            )
        return None

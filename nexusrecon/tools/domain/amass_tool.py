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

            # Capture the process outcome instead of discarding it. amass
            # exits non-zero on config or datasource errors that leave
            # stdout empty; previously that was indistinguishable from a
            # clean "no subdomains" run, so a silent failure was reported
            # as a genuine negative. A non-zero exit with nothing parsed
            # is a real failure, not an empty result.
            returncode = result.returncode
            stderr_tail = (result.stderr or "")[-800:].strip()
            if returncode != 0 and not subdomains:
                return ToolResult(
                    success=False, source=self.name,
                    error=(
                        f"amass exited {returncode} with no subdomains"
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
        # A non-zero exit is an objective anomaly. run() already fails the empty
        # case (non-zero exit + no subdomains -> success=False), so reaching
        # here non-zero means amass emitted some names but did not finish
        # cleanly, so the list is likely truncated.
        #
        # amass's exit-0-but-empty failures (all passive sources throttled or
        # unreachable) are deliberately NOT flagged via stderr markers: amass is
        # a multi-source aggregator that logs per-source timeouts and throttles
        # to stderr on healthy runs too, so a substring match cannot separate
        # "one of fifty sources flapped" (a real empty) from "all sources
        # failed" without crying wolf. That distinction needs per-source
        # success counts, not a heuristic (a follow-up noted in ROADMAP #5).
        d = result.data or {}
        if d.get("returncode", 0) != 0:
            detail = d.get("stderr_tail") or f"exit code {d.get('returncode')}"
            return (
                "amass exited non-zero after emitting partial output; the subdomain "
                f"list is likely incomplete: {detail[:200]}"
            )
        return None

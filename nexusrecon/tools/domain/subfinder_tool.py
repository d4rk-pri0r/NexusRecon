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

    # Stderr fragments that mean subfinder could not actually enumerate even
    # if it exited cleanly (DNS/network failure). Distinct from "ran fine,
    # found nothing", which is a legitimate (if rare) negative we must not flag.
    _FAILURE_MARKERS = (
        "no such host",
        "could not resolve host",
        "context deadline exceeded",
        "connection refused",
        "i/o timeout",
    )

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
                data={
                    "subdomains": subdomains,
                    # Capture the subprocess outcome (Wave F-A1) instead of
                    # discarding it, so assess_result can tell a silent failure
                    # from a genuine empty enumeration.
                    "returncode": result.returncode,
                    "stderr_tail": (result.stderr or "")[-800:].strip(),
                },
                result_count=len(subdomains),
            )
        except Exception as e:
            return ToolResult(success=False, source=self.name, error=str(e))

    def assess_result(self, result: ToolResult, target: str, target_type: str = "domain") -> str | None:
        # subfinder finding zero subdomains is occasionally legitimate (a bare
        # domain with no passive footprint). Only flag the empty case when the
        # binary's own exit code or stderr proves the enumeration did not run,
        # so a clean domain is never mislabeled as a silent failure.
        if result.result_count > 0:
            return None
        d = result.data or {}
        stderr = (d.get("stderr_tail") or "").lower()
        if d.get("returncode", 0) != 0 or any(m in stderr for m in self._FAILURE_MARKERS):
            detail = d.get("stderr_tail") or f"exit code {d.get('returncode')}"
            return (
                "subfinder returned no subdomains and its output indicates the "
                f"enumeration did not run: {detail[:200]}"
            )
        return None

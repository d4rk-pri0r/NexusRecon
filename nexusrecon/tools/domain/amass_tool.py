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

    # Stderr fragments that mean amass could not actually enumerate even if it
    # exited cleanly (DNS/network failure). Distinct from "ran fine, found
    # nothing", a legitimate negative we must not flag.
    _FAILURE_MARKERS = (
        "no such host",
        "could not resolve host",
        "context deadline exceeded",
        "connection refused",
        "i/o timeout",
    )

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
                data={
                    "subdomains": subdomains,
                    # Wave F-A1: keep the subprocess outcome so assess_result can
                    # tell a silent failure from a genuine empty enumeration.
                    "returncode": result.returncode,
                    "stderr_tail": (result.stderr or "")[-800:].strip(),
                },
                result_count=len(subdomains),
            )
        except Exception as e:
            return ToolResult(success=False, source=self.name, error=str(e))

    def assess_result(self, result: ToolResult, target: str, target_type: str = "domain") -> str | None:
        # As with subfinder: zero subdomains is occasionally a true negative,
        # so only flag the empty case when amass's own exit code or stderr
        # proves the enumeration did not actually run.
        if result.result_count > 0:
            return None
        d = result.data or {}
        stderr = (d.get("stderr_tail") or "").lower()
        if d.get("returncode", 0) != 0 or any(m in stderr for m in self._FAILURE_MARKERS):
            detail = d.get("stderr_tail") or f"exit code {d.get('returncode')}"
            return (
                "amass returned no subdomains and its output indicates the "
                f"enumeration did not run: {detail[:200]}"
            )
        return None

"""Nuclei — active CVE and misconfiguration scanning via ProjectDiscovery templates."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool


@register_tool
class NucleiTool(OSINTTool):
    name = "nuclei"
    tier = Tier.T2
    category = Category.WEB
    requires_keys = []
    binary_required = "nuclei"
    description = (
        "Nuclei active vulnerability scanner — runs CVE/misconfig templates against live targets; "
        "the industry-standard tool for templated vulnerability detection"
    )
    target_types = ["domain", "ip"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        kwargs.get("target_type", "domain")
        url = target if target.startswith("http") else f"https://{target}"

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".jsonl", delete=False
        ) as out_f:
            output_path = out_f.name

        try:
            proc = self.run_subprocess(
                [
                    "nuclei",
                    "-u", url,
                    # Scan CVEs, exposures, misconfigs — skip fuzzing (too slow/noisy for recon)
                    "-tags", "cve,exposure,misconfig,default-login",
                    "-severity", "critical,high,medium",
                    "-json-export", output_path,
                    "-silent",
                    "-rate-limit", "150",
                    "-timeout", "5",
                    "-retries", "1",
                    "-no-color",
                ],
                timeout_sec=300,
            )

            findings: list[dict[str, Any]] = []
            out_file = Path(output_path)
            if out_file.exists():
                for line in out_file.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        parsed = json.loads(line)
                        # nuclei may output a JSON array on a single line or a plain object
                        items = parsed if isinstance(parsed, list) else [parsed]
                        for entry in items:
                            if not isinstance(entry, dict):
                                continue
                            findings.append({
                                "template_id": entry.get("template-id"),
                                "name": entry.get("info", {}).get("name"),
                                "severity": entry.get("info", {}).get("severity"),
                                "description": entry.get("info", {}).get("description", "")[:200],
                                "matched_at": entry.get("matched-at"),
                                "extracted": entry.get("extracted-results", []),
                                "cve_ids": entry.get("info", {}).get("classification", {}).get("cve-id", []),
                                "cvss_score": entry.get("info", {}).get("classification", {}).get("cvss-score"),
                                "tags": entry.get("info", {}).get("tags", []),
                                "reference": entry.get("info", {}).get("reference", [])[:3],
                            })
                    except json.JSONDecodeError:
                        pass
                out_file.unlink(missing_ok=True)

        except Exception as exc:
            Path(output_path).unlink(missing_ok=True)
            return ToolResult(success=False, source=self.name, error=str(exc))

        # Capture the subprocess outcome instead of discarding it. nuclei
        # exits non-zero on real failures (templates not installed, target
        # unresolvable, fatal config error); previously the return code and
        # stderr were thrown away, so a failed scan looked identical to a
        # clean "no vulnerabilities found" run. A non-zero exit with no
        # parsed findings is a genuine failure, not a negative result.
        returncode = proc.returncode
        stderr_tail = (proc.stderr or "")[-800:].strip()
        if returncode != 0 and not findings:
            return ToolResult(
                success=False,
                source=self.name,
                error=(
                    f"nuclei exited {returncode} with no findings"
                    + (f": {stderr_tail}" if stderr_tail else "")
                ),
            )

        critical = [f for f in findings if f["severity"] == "critical"]
        high = [f for f in findings if f["severity"] == "high"]

        data: dict[str, Any] = {
            "target": url,
            "total_findings": len(findings),
            "critical": len(critical),
            "high": len(high),
            "medium": len([f for f in findings if f["severity"] == "medium"]),
            "findings": findings,
            "returncode": returncode,
            "stderr_tail": stderr_tail,
        }
        return ToolResult(success=True, source=self.name, data=data, result_count=len(findings))

    # Stderr markers that mean nuclei could not actually perform the scan,
    # even when it managed to exit 0 (template store missing, the host
    # never resolved/connected). Distinct from "scanned fine, matched
    # nothing", which is a legitimate negative we must not flag.
    _FAILURE_MARKERS = (
        "no templates",
        "could not find any templates",
        "no such host",
        "could not resolve host",
        "connection refused",
        "context deadline exceeded",
        "could not run nuclei",
    )

    def assess_result(self, result: ToolResult, target: str, target_type: str = "domain") -> str | None:
        # nuclei finding nothing is common and valid: its CVE/misconfig
        # templates do not cover application-logic bugs, so 0 findings on a
        # live host is often a true (if unexciting) negative. Only flag the
        # empty case when the exit code or stderr proves the scan did not
        # actually run ── otherwise we would cry wolf on every clean target.
        d = result.data or {}
        if d.get("total_findings", 0) > 0:
            return None
        stderr = (d.get("stderr_tail") or "").lower()
        if d.get("returncode", 0) != 0 or any(m in stderr for m in self._FAILURE_MARKERS):
            detail = d.get("stderr_tail") or f"exit code {d.get('returncode')}"
            return (
                "nuclei produced no findings and its output indicates the "
                f"scan did not run: {detail[:200]}"
            )
        return None

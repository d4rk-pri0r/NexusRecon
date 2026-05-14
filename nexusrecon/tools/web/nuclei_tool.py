"""Nuclei — active CVE and misconfiguration scanning via ProjectDiscovery templates."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any, Dict, List

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
        target_type = kwargs.get("target_type", "domain")
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

            findings: List[Dict[str, Any]] = []
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

        critical = [f for f in findings if f["severity"] == "critical"]
        high = [f for f in findings if f["severity"] == "high"]

        data: Dict[str, Any] = {
            "target": url,
            "total_findings": len(findings),
            "critical": len(critical),
            "high": len(high),
            "medium": len([f for f in findings if f["severity"] == "medium"]),
            "findings": findings,
        }
        return ToolResult(success=True, source=self.name, data=data, result_count=len(findings))

"""Arjun — hidden HTTP parameter discovery."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any, Dict, List

from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool


@register_tool
class ArjunTool(OSINTTool):
    name = "arjun"
    tier = Tier.T2
    category = Category.WEB
    requires_keys = []
    binary_required = "arjun"
    description = "Arjun hidden parameter discovery — finds undocumented GET/POST parameters for IDOR/SSRF chains"
    target_types = ["domain"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        url = target if target.startswith("http") else f"https://{target}"

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as out_f:
            output_path = out_f.name

        try:
            proc = self.run_subprocess(
                [
                    "arjun",
                    "-u", url,
                    "-t", "10",
                    "--rate-limit", "10",
                    "-oJ", output_path,
                    "-q",
                ],
                timeout_sec=180,
            )

            parameters: List[Dict[str, Any]] = []
            out_file = Path(output_path)
            if out_file.exists():
                try:
                    raw = json.loads(out_file.read_text(encoding="utf-8"))
                    # Arjun output format: {url: {"GET": [...], "POST": [...]}}
                    for endpoint_url, methods in (raw.items() if isinstance(raw, dict) else []):
                        for method, params in (methods.items() if isinstance(methods, dict) else []):
                            for param in params:
                                parameters.append({
                                    "url": endpoint_url,
                                    "method": method,
                                    "parameter": param,
                                })
                except (json.JSONDecodeError, AttributeError):
                    pass
                out_file.unlink(missing_ok=True)

        except Exception as exc:
            Path(output_path).unlink(missing_ok=True)
            return ToolResult(success=False, source=self.name, error=str(exc))

        data: Dict[str, Any] = {
            "target": url,
            "parameter_count": len(parameters),
            "parameters": parameters,
            "unique_params": list({p["parameter"] for p in parameters}),
        }
        return ToolResult(success=True, source=self.name, data=data, result_count=len(parameters))

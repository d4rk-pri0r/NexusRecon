"""Katana — ProjectDiscovery modern web crawler for URL and endpoint discovery."""
from __future__ import annotations

import json
from typing import Any, Dict, List, Set

from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool


@register_tool
class KatanaTool(OSINTTool):
    name = "katana"
    tier = Tier.T2
    category = Category.WEB
    requires_keys = []
    binary_required = "katana"
    description = "Katana web crawler — discovers URLs, forms, JavaScript endpoints, and API paths"
    target_types = ["domain"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        url = target if target.startswith("http") else f"https://{target}"

        try:
            proc = self.run_subprocess(
                [
                    "katana",
                    "-u", url,
                    "-depth", "3",
                    "-jc",           # JavaScript crawling
                    "-kf", "all",    # Known files
                    "-json",
                    "-silent",
                    "-rate-limit", "150",
                    "-timeout", "10",
                    "-no-color",
                ],
                timeout_sec=180,
            )

            urls: Set[str] = set()
            forms: List[Dict[str, Any]] = []
            js_files: List[str] = []
            api_paths: List[str] = []

            for line in proc.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    endpoint = entry.get("endpoint", "")
                    if endpoint:
                        urls.add(endpoint)
                        if endpoint.endswith(".js"):
                            js_files.append(endpoint)
                        if any(seg in endpoint for seg in ["/api/", "/v1/", "/v2/", "/graphql", "/rest/"]):
                            api_paths.append(endpoint)

                    # Form data
                    if entry.get("request", {}).get("method") == "POST":
                        forms.append({
                            "url": endpoint,
                            "method": "POST",
                            "body": entry.get("request", {}).get("body", "")[:200],
                        })
                except json.JSONDecodeError:
                    pass

        except Exception as exc:
            return ToolResult(success=False, source=self.name, error=str(exc))

        data: Dict[str, Any] = {
            "target": url,
            "url_count": len(urls),
            "js_files": sorted(js_files)[:50],
            "api_paths": sorted(api_paths)[:50],
            "forms": forms[:20],
            "urls": sorted(urls)[:200],
        }
        return ToolResult(success=True, source=self.name, data=data, result_count=len(urls))

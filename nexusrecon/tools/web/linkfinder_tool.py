"""LinkFinder — JavaScript endpoint extraction (pure Python, no binary required)."""
from __future__ import annotations

import re
from typing import Any, Dict, List, Set
from urllib.parse import urljoin, urlparse

import httpx

from nexusrecon.opsec.useragent import random_ua
from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool

# Endpoint patterns extracted from JS source
_ENDPOINT_PATTERNS = [
    re.compile(r'''["'`]((?:/[a-zA-Z0-9_\-/.{}:?=&%]+){2,})["'`]'''),
    re.compile(r'''(?:fetch|axios\.(?:get|post|put|delete|patch)|\.(?:get|post|put|delete))\s*\(\s*["'`]([^"'`\n]{5,})["'`]'''),
    re.compile(r'''(?:url|path|endpoint|href|action)\s*[:=]\s*["'`]([^"'`\n]{5,})["'`]'''),
]

_INTERESTING_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx"}
_SCRIPT_SRC = re.compile(r'<script[^>]+src=["\'](.*?)["\']', re.I)


@register_tool
class LinkFinderTool(OSINTTool):
    name = "linkfinder"
    tier = Tier.T1
    category = Category.WEB
    requires_keys = []
    description = "LinkFinder — extracts API endpoints from JavaScript files without a binary"
    target_types = ["domain"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        base_url = target if target.startswith("http") else f"https://{target}"
        parsed_base = urlparse(base_url)

        endpoints: Set[str] = set()
        js_files_scanned: List[str] = []

        headers = {
            "User-Agent": random_ua(),
            "Accept": "text/html,application/xhtml+xml,application/javascript,*/*;q=0.9",
        }

        try:
            async with httpx.AsyncClient(
                headers=headers,
                timeout=15.0,
                follow_redirects=True,
            ) as client:
                # Step 1: fetch main page and find script tags
                page_resp = await client.get(base_url)
                if page_resp.status_code != 200:
                    return ToolResult(success=False, source=self.name, error=f"Target returned {page_resp.status_code}")

                html = page_resp.text
                script_srcs: List[str] = []
                for src in _SCRIPT_SRC.findall(html):
                    full_url = urljoin(base_url, src) if not src.startswith("http") else src
                    if any(full_url.endswith(ext) for ext in _INTERESTING_EXTENSIONS) or ".js" in full_url.split("?")[0]:
                        script_srcs.append(full_url)

                # Also scan inline scripts
                inline_blocks = re.findall(r'<script[^>]*>(.*?)</script>', html, re.S | re.I)
                for block in inline_blocks[:5]:
                    _extract_endpoints(block, base_url, parsed_base.netloc, endpoints)

                # Step 2: fetch and analyze each JS file (up to 20)
                for js_url in script_srcs[:20]:
                    try:
                        js_resp = await client.get(js_url)
                        if js_resp.status_code == 200:
                            js_files_scanned.append(js_url)
                            _extract_endpoints(js_resp.text, base_url, parsed_base.netloc, endpoints)
                    except Exception:
                        continue

        except Exception as exc:
            return ToolResult(success=False, source=self.name, error=str(exc))

        # Filter out obviously non-endpoint matches
        clean_endpoints = sorted({
            e for e in endpoints
            if len(e) > 3 and not e.endswith((".png", ".jpg", ".gif", ".css", ".ico", ".woff", ".woff2"))
        })

        data: Dict[str, Any] = {
            "target": base_url,
            "js_files_scanned": len(js_files_scanned),
            "endpoint_count": len(clean_endpoints),
            "endpoints": clean_endpoints[:300],
            "api_endpoints": [e for e in clean_endpoints if any(seg in e for seg in ["/api/", "/v1/", "/v2/", "/graphql", "/rest/"])][:50],
        }
        return ToolResult(success=True, source=self.name, data=data, result_count=len(clean_endpoints))


def _extract_endpoints(source: str, base_url: str, base_host: str, out: Set[str]) -> None:
    for pattern in _ENDPOINT_PATTERNS:
        for match in pattern.findall(source):
            endpoint = match.strip()
            if endpoint.startswith("http"):
                # Only keep same-origin endpoints to reduce noise
                if base_host in endpoint:
                    out.add(endpoint)
            elif endpoint.startswith("/"):
                out.add(endpoint)

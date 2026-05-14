"""Google dork automation — queries via HTTP search with rate limiting and fallback."""
from __future__ import annotations
import asyncio
import re
from typing import Any, Dict, List, Optional
import httpx
from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool

GOOGLE_DORKS = [
    ('site:{target} ext:pdf', 'PDF documents'),
    ('site:{target} ext:doc OR ext:docx', 'Word documents'),
    ('site:{target} ext:xls OR ext:xlsx', 'Excel spreadsheets'),
    ('site:{target} ext:ppt OR ext:pptx', 'PowerPoint files'),
    ('site:{target} ext:csv', 'CSV data files'),
    ('site:{target} ext:sql OR ext:db OR ext:sqlite', 'Database files'),
    ('site:{target} ext:env OR ext:log OR ext:cfg OR ext:conf', 'Config and log files'),
    ('site:{target} ext:xml OR ext:json OR ext:yaml', 'Structured data files'),
    ('site:{target} ext:bak OR ext:old OR ext:backup', 'Backup files'),
    ('site:{target} intitle:"index of"', 'Directory listings'),
    ('site:{target} intext:"password"', 'Hardcoded passwords'),
    ('site:{target} intext:"api_key" OR intext:"api-key" OR intext:"apikey"', 'API key leaks'),
    ('site:{target} intext:"secret"', 'Secret leaks'),
    ('site:{target} intext:"aws_access_key"', 'AWS key leaks'),
    ('site:{target} intext:"-----BEGIN"', 'Private key leaks'),
    ('site:{target} inurl:admin', 'Admin pages'),
    ('site:{target} inurl:login', 'Login pages'),
    ('site:{target} inurl:wp-admin', 'WordPress admin'),
    ('site:{target} inurl:phpinfo', 'PHP info pages'),
    ('site:{target} inurl:.git', 'Git repository exposure'),
    ('site:{target} inurl:.env', 'Environment file exposure'),
]

USER_AGENTS = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
]


@register_tool
class DorksTool(OSINTTool):
    name = "dorks"
    tier = Tier.T0
    category = Category.WEB
    requires_keys = []
    description = "Google dork automation via HTTP search with scraping fallback"
    target_types = ["domain"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        results = []
        total_found = 0

        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            for dork_template, description in GOOGLE_DORKS:
                dork_query = dork_template.format(target=target)
                urls = await self._search_google(client, dork_query)
                if urls is None:
                    urls = await self._search_bing(client, dork_query)
                result_entry = {
                    "dork": dork_query,
                    "description": description,
                    "results": urls or [],
                    "status": "success" if urls else "no_results",
                }
                results.append(result_entry)
                if urls:
                    total_found += len(urls)
                await asyncio.sleep(1.5)

        return ToolResult(
            success=True, source=self.name,
            data={"dork_results": results},
            result_count=total_found,
        )

    async def _search_google(self, client: httpx.AsyncClient, query: str) -> Optional[List[str]]:
        headers = {
            "User-Agent": USER_AGENTS[0],
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }
        params = {"q": query, "num": 10, "hl": "en"}
        try:
            resp = await client.get("https://www.google.com/search", params=params, headers=headers)
            if resp.status_code != 200:
                return None
            urls = re.findall(r'<a[^>]*href="(https?://[^"]+)"[^>]*>', resp.text)
            clean = []
            for u in urls:
                if u.startswith("http") and "/search?" not in u and "google.com" not in u:
                    clean.append(u)
            return clean[:10]
        except Exception:
            return None

    async def _search_bing(self, client: httpx.AsyncClient, query: str) -> Optional[List[str]]:
        headers = {"User-Agent": USER_AGENTS[1], "Accept": "text/html"}
        params = {"q": query, "count": 10}
        try:
            resp = await client.get("https://www.bing.com/search", params=params, headers=headers)
            if resp.status_code != 200:
                return None
            urls = re.findall(r'<cite[^>]*>(.*?)</cite>', resp.text, re.DOTALL)
            clean = [re.sub(r'<[^>]+>', '', u).strip() for u in urls if u.strip()]
            return clean[:10]
        except Exception:
            return None

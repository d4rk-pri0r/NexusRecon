"""Favicon hash computation + Shodan/Censys correlation."""
from __future__ import annotations
import base64
from typing import Any, Dict, List, Optional
import httpx
from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool

USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"

COMMON_FAVICON_PATHS = [
    "/favicon.ico",
    "/favicon.png",
    "/favicon.svg",
    "/static/favicon.ico",
    "/assets/favicon.ico",
    "/assets/images/favicon.ico",
    "/images/favicon.ico",
    "/uploads/favicon.ico",
    "/apple-touch-icon.png",
]


@register_tool
class FaviconTool(OSINTTool):
    name = "favicon"
    tier = Tier.T2
    category = Category.WEB
    requires_keys = []
    description = "Favicon mmh3 hash with Shodan correlation"
    target_types = ["domain", "subdomain"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        base_url = f"https://{target}" if not target.startswith("http") else target
        results: Dict[str, Any] = {}
        icons_found = []

        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True, verify=False) as client:
            for path in COMMON_FAVICON_PATHS:
                url = f"{base_url}{path}"
                try:
                    resp = await client.get(url, headers={"User-Agent": USER_AGENT})
                    if resp.status_code == 200 and len(resp.content) > 50:
                        fav_hash = self._compute_mmh3_hash(resp.content)
                        icons_found.append({
                            "url": url,
                            "size": len(resp.content),
                            "content_type": resp.headers.get("content-type", ""),
                            "mmh3_hash": fav_hash,
                            "mmh3_hash_str": str(fav_hash) if fav_hash is not None else None,
                        })
                except Exception:
                    continue

        if icons_found:
            results["icons"] = icons_found

            # Shodan query for this hash
            shodan_key = kwargs.get("shodan_api_key")
            if shodan_key and icons_found[0].get("mmh3_hash_str"):
                try:
                    h = icons_found[0]["mmh3_hash_str"]
                    async with httpx.AsyncClient(timeout=10.0) as client:
                        shodan_resp = await client.get(
                            f"https://api.shodan.io/shodan/host/search",
                            params={"key": shodan_key, "query": f"http.favicon.hash:{h}"},
                        )
                        if shodan_resp.status_code == 200:
                            shodan_data = shodan_resp.json()
                            results["shodan"] = {
                                "total": shodan_data.get("total", 0),
                                "matches": [
                                    {"ip": m.get("ip_str"), "port": m.get("port"), "org": m.get("org")}
                                    for m in shodan_data.get("matches", [])[:10]
                                ],
                            }
                except Exception:
                    pass

            results["count"] = len(icons_found)

        return ToolResult(
            success=True, source=self.name, data=results,
            result_count=len(icons_found),
        )

    @staticmethod
    def _compute_mmh3_hash(data: bytes) -> Optional[int]:
        try:
            import mmh3
            encoded = base64.b64encode(data)
            return mmh3.hash(encoded.decode("utf-8"))
        except ImportError:
            return None
        except Exception:
            return None

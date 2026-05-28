"""Certificate Transparency parsing via crt.sh."""
from __future__ import annotations

from typing import Any

import httpx

from nexusrecon.tools.base import (
    Category,
    OSINTTool,
    Tier,
    ToolResult,
    http_get_with_retry,
)
from nexusrecon.tools.registry import register_tool


@register_tool
class CRTShTool(OSINTTool):
    name = "crtsh"
    tier = Tier.T0
    category = Category.CERTIFICATE
    requires_keys = []
    description = "Certificate Transparency log search via crt.sh"
    target_types = ["domain"]
    dynamic_trigger_hints = ["new subdomain found", "wildcard certificate issued"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        try:
            # Deduplicate: use identity column which is a hash of the certificate
            url = f"https://crt.sh/?q=%.{target}&output=json&deduplicate=y"
            async with httpx.AsyncClient(timeout=15.0, http2=True) as client:
                # crt.sh flaps with 502s; retry transient failures so one
                # upstream hiccup doesn't silently gut subdomain enumeration.
                resp = await http_get_with_retry(client, url)

                if resp.status_code == 200:
                    try:
                        certs = resp.json()
                    except Exception:
                        return ToolResult(success=False, source=self.name, error="Invalid JSON from crt.sh")

                    subdomains = set()
                    results = []
                    for cert in certs[:500]:
                        name = cert.get("name_value", "")
                        if name and name != target:
                            subdomains.add(name)
                        results.append({
                            "common_name": cert.get("common_name"),
                            "issuer": cert.get("issuer_name", "")[:100],
                            "not_before": cert.get("not_before"),
                            "not_after": cert.get("not_after"),
                            "name_value": name,
                        })

                    return ToolResult(
                        success=True, source=self.name,
                        data={"subdomains": sorted(subdomains), "certs": results[:100]},
                        result_count=len(subdomains),
                    )

                return ToolResult(success=False, source=self.name, error=f"crt.sh returned {resp.status_code}")

        except Exception as e:
            return ToolResult(success=False, source=self.name, error=str(e))

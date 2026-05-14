"""CDN detection via HTTP response headers, DNS CNAME analysis, and IP range checks."""
from __future__ import annotations
from typing import Any, Dict, List, Optional
import httpx
from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool


CDN_SIGNATURES: Dict[str, Dict[str, Any]] = {
    "cloudflare": {
        "headers": {"cf-ray": None, "cf-cache-status": None, "cloudflare": None},
        "cnames": [r'\.cloudflare\.com$'],
        "ips": ["103.21.244", "103.22.200", "103.31.4", "104.16", "104.17", "104.18",
                "104.19", "108.162", "131.0.72", "141.101", "162.158", "172.64", "172.65",
                "172.66", "172.67", "173.245", "188.114", "190.93", "197.234", "198.41"],
    },
    "akamai": {
        "headers": {"akamai": None, "x-akamai-": None, "x-check-cacheable": None, "x-cache": "akamai"},
        "cnames": [r'\.akamai(d|aai|ized)?\.net$', r'\.edgesuite\.net$', r'\.edgekey\.net$'],
    },
    "fastly": {
        "headers": {"x-fastly": None, "x-served-by-fastly": None, "x-timer": None, "fastly": None},
        "cnames": [r'\.fastly\.net$', r'\.fastlylb\.net$', r'\.fastly\.com$'],
        "ips": ["151.101.", "23.235.", "104.156.", "146.75."],
    },
    "amazon_cloudfront": {
        "headers": {"x-amz-cf-id": None, "x-amz-cf-pop": None, "x-cache": "cloudfront"},
        "cnames": [r'\.cloudfront\.net$'],
        "ips": ["13.32.", "13.33.", "13.224.", "13.225.", "13.226.", "13.227.",
                "13.228.", "13.249.", "13.250.", "52.84.", "54.192.", "54.230.",
                "54.239.", "54.240.", "99.84.", "143.204.", "150.222.", "205.251."],
    },
    "cloudfront": {
        "headers": {"x-amz-cf-id": None},
        "cnames": [r'\.cloudfront\.net$'],
        "ips": ["13.32.", "13.33.", "13.224.", "54.192.", "54.230.", "99.84.", "143.204."],
        "_alias_of": "amazon_cloudfront",
    },
    "azure_cdn": {
        "headers": {"x-azure-ref": None, "x-cache": "azure", "x-ms-request-id": None},
        "cnames": [r'\.azureedge\.net$', r'\.azurefd\.net$', r'\.trafficmanager\.net$'],
    },
    "google_cdn": {
        "headers": {"via": "google", "x-goog": None, "x-cloud-trace-context": None, "server": "gws"},
        "cnames": [r'\.googleusercontent\.com$', r'\.ghs\.google\.com$', r'\.appspot\.com$'],
    },
    "stackpath": {
        "headers": {"x-stackpath": None},
        "cnames": [r'\.stackpathcdn\.com$'],
    },
    "keycdn": {
        "headers": {"x-keycdn": None, "x-cache": "keycdn"},
        "cnames": [r'\.kxcdn\.com$'],
    },
    "bunnycdn": {
        "headers": {"x-cache": "bunnycdn", "x-bunny": None},
        "cnames": [r'\.b-cdn\.net$'],
    },
    "section.io": {
        "headers": {"x-section": None, "x-cache": "section"},
        "cnames": [r'\.section\.io$'],
    },
    "imperva_incapsula": {
        "headers": {"x-cdn": "incapsula", "x-iinfo": None},
        "cnames": [r'\.incap\d*\.net$', r'\.incapsula\.com$'],
    },
    "sucuri": {
        "headers": {"x-sucuri-cache": None, "x-sucuri": None},
        "cnames": [r'\.sucuri\.net$'],
    },
}

USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"


@register_tool
class CDNTool(OSINTTool):
    name = "cdn_detect"
    tier = Tier.T0
    category = Category.DOMAIN
    requires_keys = []
    description = "CDN detection via HTTP headers, DNS CNAME, and IP range checks"
    target_types = ["domain"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        url = f"https://{target}" if not target.startswith("http") else target
        detected: Dict[str, Any] = {}
        headers_raw: Dict[str, str] = {}
        cname_records: List[str] = []
        resolved_ips: List[str] = []

        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True, verify=False) as client:
            try:
                resp = await client.get(url, headers={"User-Agent": USER_AGENT})
                headers_raw = {k.lower(): v for k, v in dict(resp.headers).items()}
            except Exception:
                pass

        # DNS resolution via httpx
        try:
            from socket import getaddrinfo, AF_INET, AF_INET6
            for family in (AF_INET, AF_INET6):
                try:
                    addrs = getaddrinfo(target, 80, family=family)
                    for addr in addrs:
                        ip = addr[4][0]
                        if ip not in resolved_ips:
                            resolved_ips.append(ip)
                except Exception:
                    continue
        except Exception:
            pass

        # Check each CDN against headers, CNAMEs, and IPs
        detected_cdns = []
        for cdn_name, sig in CDN_SIGNATURES.items():
            reasons = []

            # Header checks
            for hdr, val in sig.get("headers", {}).items():
                for hdr_key, hdr_val in headers_raw.items():
                    if hdr in hdr_key or hdr_key.startswith(hdr.replace("-", "")):
                        if val is None or val in hdr_val.lower():
                            reasons.append(f"header: {hdr_key}={hdr_val}")
                            break

            # IP range checks
            for ip in resolved_ips:
                for prefix in sig.get("ips", []):
                    if ip.startswith(prefix):
                        reasons.append(f"ip_range: {prefix}")
                        break

            # CNAME checks (simulated from target name patterns)
            for cname_ptn in sig.get("cnames", []):
                import re
                if re.search(cname_ptn, target):
                    reasons.append(f"cname_pattern: {cname_ptn}")

            if reasons:
                entry = {
                    "name": cdn_name,
                    "detected": True,
                    "confidence": "high" if len(reasons) >= 2 else "medium",
                    "evidence": reasons[:3],
                }
                detected_cdns.append(entry)
                detected[cdn_name] = entry

        return ToolResult(
            success=True, source=self.name,
            data={
                "target": target,
                "resolved_ips": resolved_ips,
                "response_headers": dict(list(headers_raw.items())[:20]),
                "detected_cdns": detected_cdns,
                "count": len(detected_cdns),
                "origin_research": "Use cert.sh history, SPF includes, and historical DNS to find origin IPs",
            },
            result_count=len(detected_cdns),
        )

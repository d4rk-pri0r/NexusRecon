"""Web technology fingerprinting via HTTP headers and HTML analysis."""
from __future__ import annotations

import re
from typing import Any

import httpx

from nexusrecon.opsec.useragent import random_ua
from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool

TECH_SIGNATURES: dict[str, dict[str, Any]] = {
    "nginx": {"headers": {"server": "nginx"}, "cats": ["web server"]},
    "apache": {"headers": {"server": "apache"}, "cats": ["web server"]},
    "cloudflare": {"headers": {"server": "cloudflare", "cf-ray": ""}, "cats": ["cdn"]},
    "wordpress": {"html": [r'wp-content', r'wp-includes', r'wordpress', r'xmlrpc\.php'], "cats": ["cms"]},
    "drupal": {"html": [r'drupal', r'Drupal\.settings'], "cats": ["cms"]},
    "joomla": {"html": [r'joomla', r'com_content', r'JRoute'], "cats": ["cms"]},
    "magento": {"headers": {"x-magento": ""}, "html": [r'mage/', r'Magento'], "cats": ["ecommerce"]},
    "shopify": {"html": [r'shopify', r'Shopify\.sale'], "cats": ["ecommerce"]},
    "laravel": {"headers": {"set-cookie": "laravel_session"}, "cats": ["framework"]},
    "django": {"html": [r'csrfmiddlewaretoken', r'django\.'], "cats": ["framework"]},
    "flask": {"headers": {"set-cookie": "session"}, "html": [r'flask'], "cats": ["framework"]},
    "express": {"headers": {"x-powered-by": "express"}, "cats": ["framework"]},
    "next.js": {"html": [r'__NEXT_DATA__', r'/_next/static/'], "cats": ["framework"]},
    "nuxt.js": {"html": [r'__NUXT__', r'/_nuxt/'], "cats": ["framework"]},
    "gatsby": {"html": [r'___gatsby'], "cats": ["framework"]},
    "vite": {"html": [r'/assets/index-[a-z0-9]+\.js', r'vite'], "cats": ["framework"]},
    "react": {"html": [r'react\.js', r'react-dom', r'__REACT_DEVTOOLS_'], "cats": ["library"]},
    "vue": {"html": [r'vue\.js', r'__VUE__', r'v-cloak', r'v-bind'], "cats": ["library"]},
    "angular": {"html": [r'ng-app', r'ng-controller', r'angular\.js', r'_angular'], "cats": ["library"]},
    "jquery": {"html": [r'jquery\.js', r'jquery-'], "cats": ["library"]},
    "bootstrap": {"html": [r'bootstrap\.min\.css', r'bootstrap\.js', r'col-md-'], "cats": ["ui framework"]},
    "tailwind": {"html": [r'tailwindcss', r'class="[^"]*text-[a-z]+-[0-9]'], "cats": ["ui framework"]},
    "php": {"headers": {"x-powered-by": "php", "set-cookie": "phpsessid"}, "cats": ["language"]},
    "asp.net": {"headers": {"x-powered-by": "asp.net", "x-aspnet-version": ""}, "cats": ["language"]},
    "java": {"headers": {"x-powered-by": "java", "set-cookie": "jsessionid"}, "cats": ["language"]},
    "python": {"headers": {"server": "python"}, "cats": ["language"]},
    "ruby": {"headers": {"server": "ruby", "x-powered-by": "ruby"}, "cats": ["language"]},
    "iis": {"headers": {"server": "microsoft-iis", "x-powered-by": "asp.net"}, "cats": ["web server"]},
    "caddy": {"headers": {"server": "caddy"}, "cats": ["web server"]},
    "traefik": {"headers": {"server": "traefik"}, "cats": ["reverse proxy"]},
    "haproxy": {"headers": {"server": "haproxy"}, "cats": ["reverse proxy"]},
    "sucuri": {"headers": {"x-sucuri": "", "x-sucuri-cache": ""}, "cats": ["waf"]},
    "modsecurity": {"headers": {"server": "mod_security"}, "cats": ["waf"]},
    "google analytics": {"html": [r'google-analytics\.com/ga\.js', r'googletagmanager\.com/gtag'], "cats": ["analytics"]},
    "hotjar": {"html": [r'hotjar\.com', r'hj-'], "cats": ["analytics"]},
    "facebook pixel": {"html": [r'fbq\(', r'connect\.facebook\.net'], "cats": ["analytics"]},
    "stripe": {"html": [r'js\.stripe\.com', r'stripe\.'], "cats": ["payment"]},
    "reCaptcha": {"html": [r'google\.com/recaptcha', r'recaptcha/api'], "cats": ["security"]},
    "hsts": {"headers": {"strict-transport-security": ""}, "cats": ["security"]},
}

USER_AGENT = random_ua()


@register_tool
class WebTechTool(OSINTTool):
    name = "webtech"
    tier = Tier.T2
    category = Category.WEB
    requires_keys = []
    description = "Web technology fingerprinting via HTTP headers and HTML patterns"
    target_types = ["domain", "subdomain"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        url = f"https://{target}" if not target.startswith("http") else target
        found: dict[str, Any] = {}

        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True, verify=False) as client:
            try:
                resp = await client.get(url, headers={"User-Agent": USER_AGENT})
                headers = {k.lower(): v.lower() for k, v in dict(resp.headers).items()}
                body = resp.text
                status = resp.status_code

                for tech_name, sig in TECH_SIGNATURES.items():
                    matched = False
                    reasons = []

                    # Check headers
                    for hdr, val_pattern in sig.get("headers", {}).items():
                        hdr_val = headers.get(hdr, "")
                        if val_pattern:
                            if val_pattern in hdr_val:
                                matched = True
                                reasons.append(f"header {hdr}={hdr_val}")
                        elif hdr_val:
                            matched = True
                            reasons.append(f"header {hdr} present")

                    # Check HTML patterns
                    html_patterns = sig.get("html", [])
                    body_lower = body.lower()
                    for pattern in html_patterns:
                        if re.search(pattern, body_lower):
                            matched = True
                            reasons.append(f"html pattern {pattern}")

                    if matched:
                        cats = sig.get("cats", [])
                        categories = cats if isinstance(cats, list) else [cats]
                        if tech_name not in found:
                            found[tech_name] = {
                                "name": tech_name,
                                "categories": categories,
                                "confidence": "high" if reasons else "medium",
                                "evidence": reasons[:3],
                            }
                        else:
                            existing = found[tech_name]
                            existing["evidence"].extend(reasons[:2])

            except Exception as e:
                return ToolResult(
                    success=False, source=self.name,
                    data={"url": url, "error": str(e)}, result_count=0,
                )

        return ToolResult(
            success=True, source=self.name,
            data={
                "url": url,
                "http_status": status,
                "technologies": list(found.values()),
                "count": len(found),
            },
            result_count=len(found),
        )

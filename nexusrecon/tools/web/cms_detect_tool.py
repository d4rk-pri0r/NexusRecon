"""CMS and framework detection via HTTP fingerprinting."""
from __future__ import annotations

import re
from typing import Any

import httpx

from nexusrecon.opsec.useragent import random_ua
from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool

# Each entry: (name, confidence_weight, probe_path, [body_patterns], [header_patterns])
_SIGNATURES: list[tuple] = [
    ("WordPress", 0.9, "/wp-login.php", [r"WordPress", r"wp-content", r"wp-includes"], ["X-Powered-By: W3 Total Cache", "link: <.*wp-json"]),
    ("WordPress", 0.8, "/wp-json/", [r'"description"', r'"name"', r'"url"'], []),
    ("Joomla", 0.9, "/administrator/", [r"Joomla!", r"com_login"], ["X-Content-Encoded-By: Joomla"]),
    ("Drupal", 0.9, "/user/login", [r"Drupal\.settings", r"sites/default/files"], ["X-Generator: Drupal"]),
    ("Drupal", 0.7, "/CHANGELOG.txt", [r"Drupal \d"], []),
    ("Magento", 0.9, "/skin/frontend/", [], []),
    ("Magento", 0.8, "/mage/", [r"Mage\.Cookies", r"var SKIN_URL"], []),
    ("Shopify", 0.95, "/", [r"cdn\.shopify\.com", r"Shopify\.Checkout"], []),
    ("Squarespace", 0.9, "/", [r"squarespace\.com", r"static\.squarespace\.com"], []),
    ("Ghost", 0.9, "/ghost/", [r"Ghost", r"ghost-sdk"], ["X-Powered-By: Express"]),
    ("Django", 0.8, "/", [r"csrfmiddlewaretoken", r"django"], ["X-Frame-Options: SAMEORIGIN"]),
    ("Laravel", 0.8, "/", [r"laravel_session", r"XSRF-TOKEN"], ["X-Powered-By: PHP"]),
    ("Rails", 0.7, "/", [r"_rails_session", r"data-turbolinks"], []),
    ("ASP.NET", 0.9, "/", [], ["X-Powered-By: ASP.NET", "X-AspNet-Version"]),
    ("Confluence", 0.95, "/login.action", [r"Confluence", r"atlassian"], []),
    ("GitLab", 0.95, "/users/sign_in", [r"GitLab", r"gl-button"], []),
    ("Jenkins", 0.95, "/login", [r"Jenkins", r"j_username"], ["X-Hudson"]),
]


@register_tool
class CMSDetectTool(OSINTTool):
    name = "cms_detect"
    tier = Tier.T1
    category = Category.WEB
    requires_keys = []
    description = "CMS and framework fingerprinting — detects WordPress, Joomla, Drupal, Shopify, Django, Rails, and more"
    target_types = ["domain"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        base_url = target if target.startswith("http") else f"https://{target}"
        detected: list[dict[str, Any]] = []

        headers = {
            "User-Agent": random_ua(),
            "Accept": "text/html,*/*;q=0.9",
        }

        probed_paths: dict[str, tuple] = {}  # path -> (body, response_headers)

        # Deduplicate probes — same path may appear for multiple CMS
        for cms, confidence, path, body_pats, header_pats in _SIGNATURES:
            probed_paths[path] = ([], [])

        try:
            async with httpx.AsyncClient(
                headers=headers,
                timeout=10.0,
                follow_redirects=True,
            ) as client:
                for path in probed_paths:
                    url = base_url.rstrip("/") + path
                    try:
                        resp = await client.get(url)
                        body = resp.text[:5000]
                        resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                        probed_paths[path] = (body, resp_headers)
                    except Exception:
                        pass

        except Exception as exc:
            return ToolResult(success=False, source=self.name, error=str(exc))

        # Evaluate signatures against probed responses
        cms_scores: dict[str, float] = {}
        cms_evidence: dict[str, list[str]] = {}

        for cms, confidence, path, body_pats, header_pats in _SIGNATURES:
            body, resp_headers = probed_paths.get(path, ("", {}))
            if not body and not resp_headers:
                continue

            matched: list[str] = []
            for pat in body_pats:
                if re.search(pat, body, re.I):
                    matched.append(f"body:{pat}")
            for hpat in header_pats:
                hname, _, hval = hpat.partition(":")
                if hname.lower() in resp_headers:
                    if not hval or hval.strip().lower() in resp_headers[hname.lower()].lower():
                        matched.append(f"header:{hpat}")

            if matched:
                current = cms_scores.get(cms, 0.0)
                cms_scores[cms] = min(1.0, current + confidence * len(matched) / max(len(body_pats) + len(header_pats), 1))
                cms_evidence.setdefault(cms, []).extend(matched)

        for cms, score in sorted(cms_scores.items(), key=lambda x: -x[1]):
            detected.append({
                "cms": cms,
                "confidence": round(score, 2),
                "evidence": list(set(cms_evidence.get(cms, [])))[:5],
            })

        data: dict[str, Any] = {
            "target": base_url,
            "detected": detected,
            "primary_cms": detected[0]["cms"] if detected else None,
            "primary_confidence": detected[0]["confidence"] if detected else 0.0,
        }
        return ToolResult(success=True, source=self.name, data=data, result_count=len(detected))

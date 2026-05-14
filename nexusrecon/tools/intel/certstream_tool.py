"""CertStream — recent crt.sh certificates (last 7 days) with phishing-infra detection."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

import httpx
from dateutil import parser as dateutil_parser

from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool

_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Accept": "application/json",
}


def _levenshtein(a: str, b: str) -> int:
    """Simple iterative Levenshtein distance."""
    try:
        import Levenshtein
        return Levenshtein.distance(a, b)
    except ImportError:
        pass
    m, n = len(a), len(b)
    dp = list(range(n + 1))
    for i in range(1, m + 1):
        prev, dp[0] = dp[0], i
        for j in range(1, n + 1):
            temp = dp[j]
            dp[j] = prev if a[i - 1] == b[j - 1] else 1 + min(prev, dp[j], dp[j - 1])
            prev = temp
    return dp[n]


@register_tool
class CertStreamTool(OSINTTool):
    name = "certstream_recent"
    tier = Tier.T0
    category = Category.CERTIFICATE
    requires_keys = []
    description = "Fetch crt.sh certs issued in the last 7 days; flag typosquatting / phishing infra"
    target_types = ["domain"]
    dynamic_trigger_hints = ["certificate issued for new domain", "typosquat domain detected"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        cutoff = datetime.now(timezone.utc) - timedelta(days=7)
        recent: List[Dict[str, Any]] = []
        potential_phishing: List[Dict[str, Any]] = []

        try:
            async with httpx.AsyncClient(headers=_HEADERS, timeout=30.0, follow_redirects=True) as client:
                resp = await client.get(
                    "https://crt.sh/",
                    params={"q": f"%.{target}", "output": "json"},
                )
                if resp.status_code != 200:
                    return ToolResult(
                        success=False,
                        source=self.name,
                        error=f"crt.sh returned HTTP {resp.status_code}",
                    )
                entries = resp.json()
        except Exception as exc:
            return ToolResult(success=False, source=self.name, error=str(exc))

        for entry in entries:
            ts_str = entry.get("entry_timestamp") or entry.get("not_before", "")
            try:
                ts = dateutil_parser.parse(ts_str)
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                if ts < cutoff:
                    continue
            except Exception:
                continue

            name_value = entry.get("name_value", "")
            ca_name = entry.get("issuer_name", "")
            cert_entry = {
                "domain": name_value,
                "issued": ts_str,
                "ca": ca_name,
            }
            recent.append(cert_entry)

            # Typosquatting check: compare against seed domain (without TLD)
            seed_base = target.rsplit(".", 1)[0] if "." in target else target
            for line in name_value.splitlines():
                candidate = line.strip().lstrip("*.")
                if not candidate or candidate == target or candidate.endswith(f".{target}"):
                    continue
                cand_base = candidate.rsplit(".", 1)[0] if "." in candidate else candidate
                dist = _levenshtein(seed_base.lower(), cand_base.lower())
                if 1 <= dist <= 3:
                    potential_phishing.append({
                        "domain": candidate,
                        "edit_distance": dist,
                        "issued": ts_str,
                        "ca": ca_name,
                    })

        return ToolResult(
            success=True,
            source=self.name,
            data={
                "target": target,
                "recent_certs": recent[:100],
                "potential_phishing_infra": potential_phishing,
            },
            result_count=len(recent),
        )

"""dnsx — active DNS resolution with built-in common-subdomain wordlist."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool

# Compact high-value wordlist covering the most common subdomains found in real engagements
_WORDLIST = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2", "smtp",
    "secure", "vpn", "m", "shop", "ftp", "api", "dev", "staging", "prod", "app",
    "admin", "portal", "login", "dashboard", "test", "beta", "alpha", "demo",
    "internal", "intranet", "corp", "office", "hr", "finance", "helpdesk",
    "support", "status", "docs", "wiki", "confluence", "jira", "git", "gitlab",
    "github", "jenkins", "ci", "build", "deploy", "docker", "k8s", "grafana",
    "kibana", "splunk", "monitor", "metrics", "logs", "elk", "vault",
    "auth", "oauth", "sso", "id", "idp", "ldap", "cdn", "static", "assets",
    "media", "img", "images", "upload", "files", "download", "archive",
    "backup", "old", "legacy", "v1", "v2", "api2", "ws", "socket", "push",
    "mobile", "ios", "android", "pay", "checkout", "billing", "account",
    "my", "customer", "partner", "vendor", "supplier", "extranet",
    "db", "database", "mysql", "redis", "mongo", "elastic",
    "dev1", "dev2", "staging1", "prod1", "uat", "qa", "sandbox",
    "mx", "mx1", "mx2", "smtp1", "smtp2", "pop", "imap", "exchange",
]


@register_tool
class DNSXTool(OSINTTool):
    name = "dnsx"
    tier = Tier.T1
    category = Category.DNS
    requires_keys = []
    binary_required = "dnsx"
    description = "dnsx active DNS resolution — brute-forces common subdomains using a curated wordlist"
    target_types = ["domain"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        resolved: list[dict[str, Any]] = []
        subdomains: list[str] = []

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as wf:
            wf.write("\n".join(_WORDLIST))
            wordlist_path = wf.name

        try:
            proc = self.run_subprocess(
                [
                    "dnsx",
                    "-d", target,
                    "-w", wordlist_path,
                    "-resp",
                    "-json",
                    "-silent",
                    "-rate-limit", "500",
                    "-retry", "2",
                ],
                timeout_sec=120,
            )
            Path(wordlist_path).unlink(missing_ok=True)

            for line in proc.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    host = entry.get("host", "")
                    if host:
                        subdomains.append(host)
                        resolved.append({
                            "host": host,
                            "a": entry.get("a", []),
                            "aaaa": entry.get("aaaa", []),
                            "cname": entry.get("cname", []),
                            "status": entry.get("status_code"),
                        })
                except json.JSONDecodeError:
                    pass

        except Exception as exc:
            Path(wordlist_path).unlink(missing_ok=True)
            return ToolResult(success=False, source=self.name, error=str(exc))

        data: dict[str, Any] = {
            "domain": target,
            "resolved_count": len(resolved),
            "subdomains": sorted(subdomains),
            "records": resolved,
        }
        return ToolResult(success=True, source=self.name, data=data, result_count=len(resolved))

"""Metadata extraction from publicly accessible documents (PDF, DOCX, XLSX, images)."""
from __future__ import annotations
import re
from typing import Any, Dict, List, Optional
import httpx
from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool

USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"

FILE_EXTENSIONS = {
    "pdf": "application/pdf",
    "doc": "application/msword",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "xls": "application/vnd.ms-excel",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "ppt": "application/vnd.ms-powerpoint",
    "pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "csv": "text/csv",
    "json": "application/json",
    "xml": "application/xml",
    "txt": "text/plain",
    "md": "text/markdown",
}

FILE_PATTERNS = [
    (f"site:{{target}} filetype:{ext}", desc, ext)
    for ext, desc in [
        ("pdf", "PDF documents"),
        ("docx", "Word documents"),
        ("xlsx", "Excel spreadsheets"),
        ("pptx", "PowerPoint presentations"),
        ("csv", "CSV data"),
        ("json", "JSON data"),
        ("xml", "XML data"),
    ]
]

COMMON_DOC_PATHS = [
    "/sitemap.xml",
    "/robots.txt",
    "/security.txt",
    "/.well-known/security.txt",
    "/.env",
    "/README.md",
    "/CHANGELOG.md",
    "/package.json",
    "/Dockerfile",
    "/docker-compose.yml",
    "/.gitignore",
    "/composer.json",
    "/requirements.txt",
    "/Gemfile",
    "/Cargo.toml",
    "/go.mod",
]


@register_tool
class MetadataTool(OSINTTool):
    name = "metadata"
    tier = Tier.T0
    category = Category.WEB
    requires_keys = []
    description = "Metadata extraction from public files (PDF, DOCX, XLSX, configs)"
    target_types = ["domain"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        base_url = f"https://{target}" if not target.startswith("http") else target
        discovered_files: List[Dict[str, Any]] = []
        env_leaks: List[str] = []
        sensitive_findings: List[str] = []

        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True, verify=False) as client:
            # Scan common sensitive paths
            for path in COMMON_DOC_PATHS:
                url = f"{base_url}{path}"
                try:
                    resp = await client.get(url, headers={"User-Agent": USER_AGENT})
                    if resp.status_code == 200 and len(resp.text) > 20:
                        entry = {
                            "url": url,
                            "path": path,
                            "size": len(resp.content),
                            "content_type": resp.headers.get("content-type", ""),
                            "type": path.split(".")[-1] if "." in path else "unknown",
                        }

                        # Check for sensitive content
                        text_lower = resp.text.lower()
                        sensitive_indicators = [
                            "password", "api_key", "secret", "token", "credentials",
                            "aws_access_key", "AKIA", "-----BEGIN", "private_key",
                            "connection_string", "jdbc:", "mongodb://", "redis://",
                            "postgres://", "mysql://",
                        ]
                        matched = [ind for ind in sensitive_indicators if ind in text_lower]
                        if matched:
                            entry["sensitive_matches"] = matched
                            sensitive_findings.append(f"{path}: matched {', '.join(matched)}")

                        # Check for environment variables
                        env_vars = re.findall(r'^([A-Z_]+)=(.+)$', resp.text, re.MULTILINE)
                        if env_vars:
                            entry["env_vars_found"] = len(env_vars)
                            env_leaks.append(f"{path}: {len(env_vars)} env vars exposed")

                        discovered_files.append(entry)
                except Exception:
                    continue

            # Extract metadata from PDF files
            for f in discovered_files:
                if f.get("type") == "pdf" or f.get("content_type", "").startswith("application/pdf"):
                    try:
                        pdf_resp = await client.get(f["url"], headers={"User-Agent": USER_AGENT})
                        if pdf_resp.status_code == 200 and len(pdf_resp.content) > 100:
                            meta = self._extract_pdf_text_meta(pdf_resp.content)
                            if meta:
                                f["metadata"] = meta
                    except Exception:
                        continue

        return ToolResult(
            success=True, source=self.name,
            data={
                "base_url": base_url,
                "total_files": len(discovered_files),
                "files": discovered_files,
                "sensitive_findings": sensitive_findings,
                "env_leaks": env_leaks,
            },
            result_count=len(discovered_files),
        )

    @staticmethod
    def _extract_pdf_text_meta(data: bytes) -> Dict[str, Any]:
        meta: Dict[str, Any] = {}
        try:
            text = data.decode("latin-1")
            patterns = {
                "author": r'/Author\(([^)]*)\)',
                "creator": r'/Creator\(([^)]*)\)',
                "producer": r'/Producer\(([^)]*)\)',
                "title": r'/Title\(([^)]*)\)',
                "subject": r'/Subject\(([^)]*)\)',
            }
            for key, pattern in patterns.items():
                m = re.search(pattern, text)
                if m:
                    meta[key] = m.group(1)
            return meta
        except Exception:
            return meta

"""APK Analyzer — download APK from APKMirror and scan for secrets/endpoints."""
from __future__ import annotations

import asyncio
import hashlib
import importlib.util
import re
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx

from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool

_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Accept": "text/html,application/xhtml+xml,*/*",
}

APK_CRED_PATTERNS: List[tuple[str, str]] = [
    ("aws_access_key", r"AKIA[0-9A-Z]{16}"),
    ("github_token", r"gh[pousr]_[A-Za-z0-9]{36,}"),
    ("google_api_key", r"AIza[0-9A-Za-z_\-]{35}"),
    ("firebase_url", r"https://[a-z0-9\-]+\.firebaseio\.com"),
    ("jwt", r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
    ("database_url", r"(?i)(?:postgres|mysql|mongodb)(?:\+\w+)?://[^:]+:[^@]+@[^/\s'\"]+"),
    ("s3_bucket", r"(?i)s3\.amazonaws\.com/[a-z0-9\-\.]+"),
    ("private_key", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
]

MAX_APK_BYTES = 200 * 1024 * 1024  # 200 MB

_APKMIRROR_WARNING = (
    "⚠ APK fetched from APKMirror (third-party mirror). The build may differ from the production "
    "Play Store version. Verify checksum against an authoritative source before relying on findings "
    "for client deliverables. APKMirror downloads are subject to their ToS; verify your engagement "
    "scope permits third-party APK retrieval."
)

_APKPURE_WARNING = (
    "⚠ APK fetched from APKPure (third-party mirror). Build may differ from production. "
    "Verify scope permits third-party APK retrieval."
)


def _scan_text(text: str) -> List[Dict[str, str]]:
    found = []
    for cred_type, pattern in APK_CRED_PATTERNS:
        matches = re.findall(pattern, text)
        for m in set(matches):
            val = m if isinstance(m, str) else m[0]
            found.append({"type": cred_type, "value_prefix": val[:20] + "..."})
    return found


def _extract_version(manifest_bytes: bytes) -> Optional[str]:
    """Parse versionName from AndroidManifest.xml bytes using ElementTree."""
    import xml.etree.ElementTree as ET
    try:
        root = ET.fromstring(manifest_bytes)
        # versionName is in the Android namespace
        version = (
            root.get("{http://schemas.android.com/apk/res/android}versionName")
            or root.get("versionName")
        )
        return version if version else None
    except Exception:
        return None


def _scan_apk(apk_path: Path) -> tuple[Optional[str], Dict[str, Any]]:
    """Scan APK for secrets, endpoints, permissions. Returns (version, scan_data)."""
    secrets: List[Dict[str, str]] = []
    endpoints: List[str] = []
    permissions: List[str] = []
    libs: List[str] = []
    version: Optional[str] = None

    try:
        with zipfile.ZipFile(apk_path) as zf:
            names = zf.namelist()
            for name in names:
                # Permissions + version from manifest
                if name == "AndroidManifest.xml":
                    try:
                        raw_bytes = zf.read(name)
                        if version is None:
                            version = _extract_version(raw_bytes)
                        raw = raw_bytes.decode("utf-8", errors="replace")
                        for perm in re.findall(r'android\.permission\.[A-Z_]+', raw):
                            permissions.append(perm)
                    except Exception:
                        pass

                # String files and smali
                if name.endswith((".xml", ".json", ".properties", ".smali", ".js")):
                    try:
                        content = zf.read(name).decode("utf-8", errors="replace")
                        secrets.extend(_scan_text(content))
                        for url in re.findall(r'https?://[^\s\'"<>]+', content):
                            if len(url) < 200:
                                endpoints.append(url)
                    except Exception:
                        pass

                # Third-party libraries from lib/
                if name.startswith("lib/") and name.endswith(".so"):
                    libs.append(Path(name).name)

    except zipfile.BadZipFile:
        pass

    unique_secrets = [dict(t) for t in {tuple(sorted(d.items())) for d in secrets}]
    unique_endpoints = list(dict.fromkeys(endpoints))[:50]
    unique_permissions = sorted(set(permissions))
    unique_libs = sorted(set(libs))

    return version, {
        "extracted_secrets": unique_secrets,
        "extracted_endpoints": unique_endpoints,
        "permissions": unique_permissions,
        "third_party_libs": unique_libs[:30],
    }


async def _fetch_apkmirror(package: str, client: httpx.AsyncClient) -> Optional[bytes]:
    """Try to fetch APK from APKMirror. Returns raw bytes or None."""
    try:
        from bs4 import BeautifulSoup

        search_url = f"https://www.apkmirror.com/?post_type=app_release&searchtype=apk&s={package}"
        resp = await client.get(search_url)
        if resp.status_code != 200:
            return None
        soup = BeautifulSoup(resp.text, "lxml")

        # Find first app release link
        link = soup.select_one("a.fontBlack")
        if not link:
            return None
        release_path = link.get("href", "")
        if not release_path.startswith("/"):
            return None

        release_resp = await client.get(f"https://www.apkmirror.com{release_path}")
        if release_resp.status_code != 200:
            return None
        release_soup = BeautifulSoup(release_resp.text, "lxml")

        # Find download page link
        dl_link = release_soup.select_one("a.accent_bg[href*='download']") or \
                  release_soup.select_one("a[href*='download-apk']")
        if not dl_link:
            return None
        dl_path = dl_link.get("href", "")

        dl_page_resp = await client.get(f"https://www.apkmirror.com{dl_path}")
        if dl_page_resp.status_code != 200:
            return None
        dl_soup = BeautifulSoup(dl_page_resp.text, "lxml")

        # Find final download link
        final_link = dl_soup.select_one("a[href*='?key=']")
        if not final_link:
            return None
        final_path = final_link.get("href", "")

        # HEAD check for size
        head_resp = await client.head(f"https://www.apkmirror.com{final_path}")
        content_length = int(head_resp.headers.get("content-length", 0))
        if content_length > MAX_APK_BYTES:
            return None

        apk_resp = await client.get(f"https://www.apkmirror.com{final_path}")
        if apk_resp.status_code == 200:
            return apk_resp.content
    except Exception:
        pass
    return None


async def _fetch_apkpure(package: str, client: httpx.AsyncClient) -> Optional[bytes]:
    """Try to fetch APK from APKPure. Returns raw bytes or None."""
    try:
        from bs4 import BeautifulSoup

        search_url = f"https://apkpure.com/search?q={package}"
        resp = await client.get(search_url)
        if resp.status_code != 200:
            return None
        soup = BeautifulSoup(resp.text, "lxml")

        # Find first result link that contains the package name
        app_link: Optional[str] = None
        for a in soup.select("a[href]"):
            href = str(a.get("href", ""))
            if f"/{package}" in href:
                app_link = href
                break
        if not app_link:
            result = soup.select_one(".search-res-name a, .name a")
            if result:
                app_link = str(result.get("href", ""))
        if not app_link:
            return None

        if not app_link.startswith("http"):
            app_link = f"https://apkpure.com{app_link}"

        # Navigate to the /download sub-page
        dl_page_url = app_link.rstrip("/") + "/download"
        dl_resp = await client.get(dl_page_url)
        if dl_resp.status_code != 200:
            return None
        dl_soup = BeautifulSoup(dl_resp.text, "lxml")

        # Find the direct APK link
        final_link: Optional[str] = None
        for a in dl_soup.select("a[href*='.apk'], a[href*='download.apkpure']"):
            final_link = str(a.get("href", ""))
            break
        if not final_link:
            meta = dl_soup.find("meta", {"http-equiv": "refresh"})
            if meta:
                content = str(meta.get("content", ""))
                m = re.search(r"url=(.+)", content, re.IGNORECASE)
                if m:
                    final_link = m.group(1).strip("'\"")
        if not final_link:
            return None

        # Size guard
        try:
            head_resp = await client.head(final_link)
            content_length = int(head_resp.headers.get("content-length", 0))
            if content_length > MAX_APK_BYTES:
                return None
        except Exception:
            pass

        apk_resp = await client.get(final_link)
        if apk_resp.status_code == 200 and len(apk_resp.content) > 1000:
            return apk_resp.content
    except Exception:
        pass
    return None


@register_tool
class APKAnalyzerTool(OSINTTool):
    name = "apk_analyzer"
    tier = Tier.T1
    category = Category.MOBILE
    requires_keys = []
    description = "Download APK from APKMirror and scan for hardcoded secrets, endpoints, permissions"
    target_types = ["package"]
    dynamic_trigger_hints = ["android app discovered", "play store app found"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        warnings: List[str] = []
        source = "metadata_only"
        version: Optional[str] = None
        checksum_sha256: Optional[str] = None
        scan_results: Dict[str, Any] = {
            "extracted_secrets": [],
            "extracted_endpoints": [],
            "permissions": [],
            "third_party_libs": [],
        }

        async with httpx.AsyncClient(headers=_HEADERS, timeout=30.0, follow_redirects=True) as client:
            apk_bytes = await _fetch_apkmirror(target, client)

            if apk_bytes:
                source = "apkmirror"
                warnings.append(_APKMIRROR_WARNING)
            else:
                apk_bytes = await _fetch_apkpure(target, client)
                if apk_bytes:
                    source = "apkpure"
                    warnings.append(_APKPURE_WARNING)
                else:
                    warnings.append(
                        "⚠ APK unavailable from APKMirror and APKPure — metadata-only mode"
                    )

            if apk_bytes:
                checksum_sha256 = hashlib.sha256(apk_bytes).hexdigest()
                with tempfile.TemporaryDirectory() as tmpdir:
                    apk_path = Path(tmpdir) / "app.apk"
                    apk_path.write_bytes(apk_bytes)
                    version, scan_results = _scan_apk(apk_path)

        return ToolResult(
            success=True,
            source=self.name,
            data={
                "package": target,
                "version": version,
                "source": source,
                "warnings": warnings,
                "checksum_sha256": checksum_sha256,
                **scan_results,
            },
            result_count=len(scan_results.get("extracted_secrets", [])),
            metadata={"warnings": warnings},
        )

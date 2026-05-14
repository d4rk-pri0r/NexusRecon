"""Cloud storage bucket enumeration — S3, Azure Blob, and GCS open bucket detection."""
from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional

import httpx

from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool

_SUFFIXES = [
    "", "-backup", "-backups", "-bak", "-files", "-file", "-data", "-assets",
    "-static", "-media", "-images", "-img", "-uploads", "-upload", "-dev",
    "-development", "-staging", "-stage", "-prod", "-production", "-test",
    "-testing", "-qa", "-uat", "-sandbox", "-public", "-private", "-internal",
    "-logs", "-log", "-reports", "-report", "-archive", "-archives", "-old",
    "-new", "-temp", "-tmp", "-web", "-www", "-site", "-app", "-api",
    ".backup", ".data", ".files",
]


def _bucket_names(domain: str) -> List[str]:
    stem = domain.split(".")[0].lower()
    company = domain.rsplit(".", 1)[0].lower().replace(".", "-")
    bases = {stem, company}
    names: List[str] = []
    for base in bases:
        for suffix in _SUFFIXES:
            names.append(f"{base}{suffix}")
    return list(dict.fromkeys(names))  # preserve order, deduplicate


@register_tool
class BucketEnumTool(OSINTTool):
    name = "bucket_enum"
    tier = Tier.T2
    category = Category.CLOUD_AWS
    requires_keys = []
    description = (
        "Cloud storage bucket enumeration — probes S3, Azure Blob, and GCS for "
        "open/misconfigured buckets using domain-derived name permutations"
    )
    target_types = ["domain"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        names = _bucket_names(target)
        open_buckets: List[Dict[str, Any]] = []
        checked = 0

        sem = asyncio.Semaphore(20)

        async def _probe(client: httpx.AsyncClient, url: str, bucket: str, provider: str) -> Optional[Dict[str, Any]]:
            try:
                async with sem:
                    r = await client.head(url, follow_redirects=True)
                    if r.status_code in (200, 403):
                        return {
                            "bucket": bucket,
                            "provider": provider,
                            "url": url,
                            "status": r.status_code,
                            "public": r.status_code == 200,
                            "accessible": r.status_code == 200,
                            "note": "200=public read; 403=exists but access denied",
                        }
            except Exception:
                pass
            return None

        try:
            async with httpx.AsyncClient(
                timeout=8.0,
                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"},
            ) as client:
                tasks = []
                for name in names[:60]:
                    tasks.append(_probe(client, f"https://{name}.s3.amazonaws.com", name, "s3"))
                    tasks.append(_probe(client, f"https://{name}.blob.core.windows.net", name, "azure_blob"))
                    tasks.append(_probe(client, f"https://storage.googleapis.com/{name}", name, "gcs"))

                checked = len(tasks)
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for r in results:
                    if isinstance(r, dict):
                        open_buckets.append(r)

        except Exception as exc:
            return ToolResult(success=False, source=self.name, error=str(exc))

        data: Dict[str, Any] = {
            "domain": target,
            "names_tested": len(names[:60]),
            "endpoints_probed": checked,
            "open_count": len(open_buckets),
            "open_buckets": open_buckets,
            "attribution_confidence": 0.2,
            "attribution_signals": ["name_permutation_enumeration"],
        }
        return ToolResult(success=True, source=self.name, data=data, result_count=len(open_buckets))

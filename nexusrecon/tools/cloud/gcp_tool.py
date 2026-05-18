"""GCP cloud reconnaissance tool (stubbed — implements GCS + App Engine)."""

from __future__ import annotations
from typing import Any, Dict, List, Optional
import httpx
from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool

GCS_PERMUTATIONS = [
    "{name}", "{name}-data", "{name}-storage", "{name}-bucket",
    "{name}-assets", "{name}-static", "{name}-media", "{name}-public",
    "{name}-files", "{name}-backup", "{name}-dev", "{name}-prod",
]


@register_tool
class GCPReconTool(OSINTTool):
    name = "gcp_recon"
    tier = Tier.T0
    category = Category.CLOUD_GCP
    requires_keys = []
    description = "GCP cloud asset enumeration (GCS, App Engine, Firebase, Cloud Run) — stubbed"
    target_types = ["domain"]

    def __init__(self) -> None:
        super().__init__()
        self._http: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._http is None:
            self._http = httpx.AsyncClient(timeout=5.0, http2=True)
        return self._http

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        results: Dict[str, Any] = {}
        try:
            client = await self._get_client()
            base = target.split(".")[0].lower().replace("-", "")

            # GCS bucket enumeration
            results["gcs_buckets"] = await self._enumerate_gcs(client, base)

            # App Engine
            results["app_engine"] = await self._enumerate_appengine(client, base)

            # TODO: Firebase project enumeration
            results["firebase"] = {"status": "stubbed"}

            # TODO: Cloud Run service discovery
            results["cloud_run"] = {"status": "stubbed"}

            await self._http.aclose() if self._http else None
            return ToolResult(
                success=True, source=self.name, data=results,
                result_count=len(results.get("gcs_buckets", [])) + len(results.get("app_engine", [])),
            )
        except Exception as e:
            return ToolResult(success=False, source=self.name, error=str(e))

    async def _enumerate_gcs(self, client: httpx.AsyncClient, base: str) -> List[Dict[str, Any]]:
        found = []
        for perm in GCS_PERMUTATIONS:
            name = perm.format(name=base).lower()
            if not name or len(name) < 3:
                continue
            url = f"https://storage.googleapis.com/{name}/"
            try:
                resp = await client.get(url, timeout=3.0)
                if resp.status_code in (200, 403):
                    found.append({"name": name, "url": url, "public": resp.status_code == 200})
            except Exception:
                continue
        return found

    async def _enumerate_appengine(self, client: httpx.AsyncClient, base: str) -> List[Dict[str, Any]]:
        names = [base, f"{base}-api", f"{base}-app"]
        found = []
        for name in names:
            url = f"https://{name}.appspot.com"
            try:
                resp = await client.get(url, timeout=3.0)
                # Previous revision treated ``status != 404`` as "found",
                # which reported 500-class errors (provider hiccups,
                # blocked-by-WAF, TLS handshake failures) as legitimate
                # hits. App Engine returns 200 for accessible apps and
                # 403 for "exists but auth required" — those are the
                # two states that genuinely mean the app exists. Match
                # the GCS bucket-probe convention next door.
                if resp.status_code in (200, 403):
                    found.append({
                        "url": url,
                        "status": resp.status_code,
                        "name": name,
                        "public": resp.status_code == 200,
                    })
            except Exception:
                continue
        return found

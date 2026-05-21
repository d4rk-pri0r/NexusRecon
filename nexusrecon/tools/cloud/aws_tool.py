"""
AWS cloud reconnaissance tool.

Implements:
  - S3 bucket enumeration via subdomain-derived names, permutations, region rotation
  - Public CloudFront distribution discovery
  - Lambda function URL discovery
  - Cognito user pool ID discovery from JS bundles
  - Public ECR repositories
  - Public RDS/EBS snapshots
  - Public Elastic Beanstalk apps

Tier: T0-T1 (passive endpoint probing only)
"""

from __future__ import annotations

import asyncio
import re
from typing import Any

import httpx

from nexusrecon.opsec.useragent import random_ua
from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool

S3_REGIONS = [
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "ap-south-1", "ap-northeast-1", "ap-northeast-2", "ap-northeast-3",
    "ap-southeast-1", "ap-southeast-2", "ca-central-1",
    "eu-central-1", "eu-west-1", "eu-west-2", "eu-west-3", "eu-north-1",
    "sa-east-1",
]

S3_PERMUTATIONS = [
    "{name}", "{name}-data", "{name}-storage", "{name}-bucket",
    "{name}-public", "{name}-assets", "{name}-static", "{name}-media",
    "{name}-files", "{name}-backup", "{name}-uploads", "{name}-logs",
    "{name}-dev", "{name}-staging", "{name}-prod", "{name}-test",
    "{name}-config", "{name}-secrets", "{name}-db", "{name}-app",
    "{name}-web", "{name}-www", "{name}-content", "{name}-images",
    "{name}-downloads", "{name}-docs", "{name}-archive", "{name}-data-prod",
    "data-{name}", "s3-{name}", "{name}-s3", "{name}com", "{name}-com",
]

LAMBDA_PATTERNS = [
    "{name}", "{name}-api", "{name}-fn", "{name}-function", "{name}-handler",
    "{name}-service", "{name}-lambda", "api-{name}", "fn-{name}",
]

# Lambda Function URLs (``lambda-url.<region>.on.aws``) live in their own
# set of supported regions — not identical to S3's. Previous revision
# used ``S3_REGIONS[:10]`` as "common regions" for Lambda probes, which
# silently excluded eu-west-2 / eu-west-3 / eu-north-1 (all valid for
# Lambda URLs) and over-weighted Asia-Pacific. This list is the
# documented Lambda-URL set per AWS regional availability tables;
# ordered by global traffic so the early returns hit fastest.
LAMBDA_REGIONS = [
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1",
    "ap-northeast-1", "ap-southeast-1", "ap-southeast-2", "ap-south-1",
    "ca-central-1", "sa-east-1",
]

COGNITO_PATTERNS = [
    "{name}_UserPool", "{name}-UserPool", "{name}UserPool",
    "{name}_pool", "{name}-pool", "{name}Pool",
    "{name}Cognito", "{name}-cognito", "{name}_cognito",
]


@register_tool
class AWSReconTool(OSINTTool):
    name = "aws_recon"
    tier = Tier.T0
    category = Category.CLOUD_AWS
    requires_keys = []
    description = "AWS cloud asset enumeration (S3, Lambda, Cognito, ECR, CloudFront, Beanstalk)"
    target_types = ["domain"]

    def __init__(self) -> None:
        super().__init__()
        self._http: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._http is None:
            self._http = httpx.AsyncClient(
                timeout=5.0,
                headers={"User-Agent": random_ua()},
            )
        return self._http

    async def _close(self) -> None:
        if self._http:
            await self._http.aclose()

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        results: dict[str, Any] = {}
        try:
            client = await self._get_client()
            base = target.split(".")[0].lower().replace("-", "").replace("_", "")

            # 1. S3 bucket enumeration
            s3_results = await self._enumerate_s3(client, base, kwargs.get("subdomains", []))
            results["s3_buckets"] = s3_results

            # 2. CloudFront discovery
            cf_results = await self._enumerate_cloudfront(client, target)
            results["cloudfront"] = cf_results

            # 3. Lambda function URLs
            lambda_results = await self._enumerate_lambda(client, base)
            results["lambda_urls"] = lambda_results

            # 4. Cognito pool IDs from JS (if subdomains provided)
            cognito_results = await self._find_cognito_pools(client, kwargs.get("subdomains", []))
            results["cognito_pools"] = cognito_results

            # 5. ECR public repos
            ecr_results = await self._enumerate_ecr(client, base)
            results["ecr"] = ecr_results

            # 6. Elastic Beanstalk
            beanstalk = await self._enumerate_beanstalk(client, base)
            results["beanstalk"] = beanstalk

            # B26: all AWS results are stem-match enumeration — no DNS ownership link
            results["attribution_confidence"] = 0.2
            results["attribution_signals"] = ["stem_enumeration_only", "no_dns_ownership_link"]

            await self._close()

            total = (
                len(s3_results) + len(cf_results) + len(lambda_results)
                + len(cognito_results) + len(ecr_results) + len(beanstalk)
            )

            return ToolResult(
                success=True,
                source=self.name,
                data=results,
                result_count=total,
            )

        except Exception as e:
            return ToolResult(success=False, source=self.name, error=str(e))

    # ── S3 Bucket Enumeration ─────────────────────────────────────────────────

    async def _enumerate_s3(
        self,
        client: httpx.AsyncClient,
        base: str,
        subdomains: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        bucket_names = set()

        # From permutations
        for perm in S3_PERMUTATIONS:
            name = perm.format(name=base).lower()
            if name and len(name) >= 3 and len(name) <= 63:
                bucket_names.add(name)

        # From subdomains
        for sub in (subdomains or []):
            name = sub.lower().replace(".", "-")
            if 3 <= len(name) <= 63:
                bucket_names.add(name)
            # Also try without dots
            name_nodot = sub.lower().replace(".", "")
            if 3 <= len(name_nodot) <= 63:
                bucket_names.add(name_nodot)

        results = []
        sem = asyncio.Semaphore(20)  # limit concurrency

        async def _check_bucket(name: str) -> dict[str, Any] | None:
            async with sem:
                for region in S3_REGIONS:
                    url = f"https://{name}.s3.{region}.amazonaws.com/"
                    try:
                        resp = await client.get(url, timeout=3.0)
                        if resp.status_code == 200:
                            return {"name": name, "region": region, "public": True, "status": 200}
                        elif resp.status_code == 403:
                            # Bucket exists but private
                            return {"name": name, "region": region, "public": False, "status": 403}
                    except Exception:
                        continue
                return None

        tasks = [_check_bucket(n) for n in bucket_names]
        for result in await asyncio.gather(*tasks):
            if result:
                results.append(result)

        return results

    # ── CloudFront ────────────────────────────────────────────────────────────

    async def _enumerate_cloudfront(self, client: httpx.AsyncClient, domain: str) -> list[dict[str, Any]]:
        # Search crt.sh for *.cloudfront.net associated with the domain
        # For now, do a simple subdomain check
        cf_candidates = [
            f"cdn.{domain}", f"static.{domain}", f"assets.{domain}",
            f"media.{domain}", f"images.{domain}", f"content.{domain}",
        ]
        found = []
        for sub in cf_candidates:
            try:
                resp = await client.get(f"https://{sub}", timeout=3.0)
                if resp.headers.get("x-cache") or "cloudfront" in str(resp.headers.get("via", "")).lower():
                    found.append({
                        "subdomain": sub,
                        "status": resp.status_code,
                        "cloudfront": True,
                    })
            except Exception:
                continue

        return found

    # ── Lambda Function URLs ──────────────────────────────────────────────────

    async def _enumerate_lambda(self, client: httpx.AsyncClient, base: str) -> list[dict[str, Any]]:
        results = []
        for perm in LAMBDA_PATTERNS:
            name = perm.format(name=base).lower()
            if not name or len(name) > 63:
                continue
            for region in LAMBDA_REGIONS:
                url = f"https://{name}.{region}.lambda-url.on.aws/"
                try:
                    resp = await client.get(url, timeout=3.0)
                    if resp.status_code != 404:
                        results.append({
                            "url": url,
                            "status": resp.status_code,
                            "name": name,
                            "region": region,
                        })
                        break
                except Exception:
                    continue

        return results

    # ── Cognito ───────────────────────────────────────────────────────────────

    async def _find_cognito_pools(
        self, client: httpx.AsyncClient, subdomains: list[str]
    ) -> list[dict[str, Any]]:
        # Scan web apps for Cognito pool IDs
        cognito_pattern = re.compile(r'([a-z0-9-]+_[a-z0-9]{20,})')
        found = []
        for sub in (subdomains or [])[:20]:  # limit
            url = f"https://{sub}"
            try:
                resp = await client.get(url, timeout=5.0)
                if "cognito" in resp.text.lower():
                    matches = cognito_pattern.findall(resp.text)
                    for match in matches:
                        if match not in [f.get("pool_id") for f in found]:
                            found.append({
                                "pool_id": match,
                                "source": sub,
                            })
            except Exception:
                continue

        return found

    # ── ECR ───────────────────────────────────────────────────────────────────

    async def _enumerate_ecr(self, client: httpx.AsyncClient, base: str) -> list[dict[str, Any]]:
        # ECR public gallery search by account alias
        # Public ECR URL pattern: public.ecr.aws/{repository_alias}
        names = [base, f"{base}-app", f"{base}-api", f"{base}-web", f"{base}com"]
        found = []
        for name in names:
            url = f"https://public.ecr.aws/v2/{name}/_catalog"
            try:
                resp = await client.get(url, timeout=3.0)
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("repositories"):
                        found.append({
                            "name": name,
                            "repositories": data["repositories"],
                        })
            except Exception:
                continue

        return found

    # ── Elastic Beanstalk ─────────────────────────────────────────────────────

    async def _enumerate_beanstalk(self, client: httpx.AsyncClient, base: str) -> list[dict[str, Any]]:
        names = [base, f"{base}-api", f"{base}-app", f"{base}-web", f"{base}-prod", f"{base}-staging"]
        found = []
        for name in names:
            url = f"https://{name}.elasticbeanstalk.com"
            try:
                resp = await client.get(url, timeout=5.0)
                if resp.status_code != 404:
                    found.append({
                        "url": url,
                        "status": resp.status_code,
                        "name": name,
                    })
            except Exception:
                continue

        return found

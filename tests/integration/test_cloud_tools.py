"""Integration tests for the cloud-probe tool category.

Each tool follows the same four-test pattern used across every category:

  1. **Happy path** — provider endpoints return the canonical documented
     responses; tool parses them and returns ``ToolResult(success=True)``
     with the expected ``data`` shape.
  2. **Empty result** — every probe returns "not found" (404, NoSuchBucket,
     etc.); tool returns ``success=True, result_count=0`` rather than
     treating "nothing found" as an error.
  3. **Error path** — provider returns 500 / connection-level error;
     tool either reports failure cleanly or, where the source code
     swallows per-endpoint errors, still returns ``success=True`` with
     an empty result set. The assertions match each tool's documented
     behavior.
  4. **Schema drift** — provider returns malformed JSON, HTML, or
     unexpected XML; tool fails gracefully (no traceback escapes).

Cloud tools probe many endpoints per run (S3 region rotation, name
permutations, multi-provider sweeps), so we use ``url__regex`` /
``host__regex`` catchalls rather than enumerating every URL by hand.
``assert_all_called=False`` is used because some routes (e.g., the
"happy bucket" override) may or may not fire depending on probe
ordering.

Tools covered: ``aws_recon``, ``bucket_enum``, ``azure_m365_recon``,
``azure_tenant_enum``, ``gcp_recon``.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx
from httpx import Response

from tests.fixtures import load_fixture, load_text_fixture

from nexusrecon.tools.cloud.aws_tool import AWSReconTool
from nexusrecon.tools.cloud.azure_tenant_tool import AzureTenantTool
from nexusrecon.tools.cloud.azure_tool import AzureM365Tool
from nexusrecon.tools.cloud.bucket_enum_tool import BucketEnumTool
from nexusrecon.tools.cloud.gcp_tool import GCPReconTool


# ────────────────────────────────────────────────────────────────────────
# Helpers
# ────────────────────────────────────────────────────────────────────────

_S3_404 = load_text_fixture("aws_recon/s3_no_such_bucket.xml")
_S3_200 = load_text_fixture("aws_recon/s3_public_listing.xml")
_S3_403 = load_text_fixture("aws_recon/s3_access_denied.xml")
_ECR_JSON = load_fixture("aws_recon/ecr_catalog.json")


# ════════════════════════════════════════════════════════════════════════
# AWS recon — aws_recon
# ════════════════════════════════════════════════════════════════════════

class TestAWSReconTool:
    """AWS public asset enumeration: S3, CloudFront, Lambda, ECR, Beanstalk."""

    async def test_happy_path(self) -> None:
        """One S3 bucket public (200), one CloudFront subdomain with
        ``x-cache`` header, one Lambda 200, one ECR 200 with repos, one
        Beanstalk 200. Everything else returns 404."""
        tool = AWSReconTool()
        with respx.mock(assert_all_called=False) as r:
            # Specific overrides must be registered BEFORE the catchall —
            # respx evaluates routes in registration order.
            # One bucket in us-east-1 is public (the tool stops at the
            # first hit per name, so this is enough for at least 1 match).
            r.get(url__regex=r"https://example\.s3\.us-east-1\.amazonaws\.com/.*").mock(
                return_value=Response(200, text=_S3_200)
            )
            # A second bucket name returns 403 (exists but private).
            r.get(url__regex=r"https://example-data\.s3\.us-east-1\.amazonaws\.com/.*").mock(
                return_value=Response(403, text=_S3_403)
            )
            # CloudFront-fronted subdomain — header detection.
            r.get("https://cdn.example.com").mock(
                return_value=Response(
                    200,
                    text="<html>cdn</html>",
                    headers={"x-cache": "Hit from cloudfront", "via": "1.1 cloudfront.net"},
                )
            )
            # Lambda function URL.
            r.get(url__regex=r"https://example\.us-east-1\.lambda-url\.on\.aws/.*").mock(
                return_value=Response(200, text="ok")
            )
            # ECR public catalog.
            r.get("https://public.ecr.aws/v2/example/_catalog").mock(
                return_value=Response(200, json=_ECR_JSON)
            )
            # Elastic Beanstalk.
            r.get("https://example.elasticbeanstalk.com").mock(
                return_value=Response(200, text="<html>beanstalk</html>")
            )
            # Catchall: every other amazonaws.com / aws / .net / .com host
            # the tool may probe returns 404.
            r.get(url__regex=r".*amazonaws\.com.*").mock(
                return_value=Response(404, text=_S3_404)
            )
            r.get(url__regex=r".*lambda-url\.on\.aws.*").mock(
                return_value=Response(404)
            )
            r.get(url__regex=r".*public\.ecr\.aws.*").mock(
                return_value=Response(404)
            )
            r.get(url__regex=r".*elasticbeanstalk\.com.*").mock(
                return_value=Response(404)
            )
            r.get(url__regex=r"https://.+\.example\.com.*").mock(
                return_value=Response(404)
            )

            result = await tool.run("example.com")

        assert result.success is True
        # At least the explicitly-public bucket should be present.
        bucket_names = [b["name"] for b in result.data["s3_buckets"]]
        assert "example" in bucket_names
        # The public bucket should be marked public=True.
        public = next(b for b in result.data["s3_buckets"] if b["name"] == "example")
        assert public["public"] is True
        assert public["status"] == 200
        # CloudFront detected.
        cf_subs = [c["subdomain"] for c in result.data["cloudfront"]]
        assert "cdn.example.com" in cf_subs
        # Lambda found.
        assert any(l["name"] == "example" for l in result.data["lambda_urls"])
        # ECR found.
        assert any(e["name"] == "example" for e in result.data["ecr"])
        # Beanstalk found.
        assert any(b["name"] == "example" for b in result.data["beanstalk"])
        # Attribution gate: AWS results are stem-enumeration only.
        assert result.data["attribution_confidence"] == 0.2
        assert "stem_enumeration_only" in result.data["attribution_signals"]

    async def test_empty_response(self) -> None:
        """Every probe returns 404. Tool should succeed with empty lists."""
        tool = AWSReconTool()
        with respx.mock(assert_all_called=False) as r:
            r.get(url__regex=r".*").mock(return_value=Response(404, text=_S3_404))

            result = await tool.run("example.com")

        assert result.success is True
        assert result.result_count == 0
        assert result.data["s3_buckets"] == []
        assert result.data["cloudfront"] == []
        assert result.data["lambda_urls"] == []
        assert result.data["ecr"] == []
        assert result.data["beanstalk"] == []

    async def test_connection_error_path(self) -> None:
        """All probes raise ConnectError. Per-endpoint try/except swallows
        each one, so the tool returns success with empty results — that's
        the documented behavior for "the whole world is unreachable"."""
        tool = AWSReconTool()
        with respx.mock(assert_all_called=False) as r:
            r.get(url__regex=r".*").mock(
                side_effect=httpx.ConnectError("connection refused")
            )

            result = await tool.run("example.com")

        # Tool catches every per-endpoint exception, so it still succeeds
        # with empty buckets/lambdas/etc. No traceback escapes.
        assert result.success is True
        assert result.result_count == 0

    async def test_malformed_ecr_json(self) -> None:
        """ECR returns invalid JSON. Per-name try/except swallows the
        parse error, so the tool still succeeds (just with no ECR repos)."""
        tool = AWSReconTool()
        with respx.mock(assert_all_called=False) as r:
            r.get(url__regex=r".*public\.ecr\.aws.*").mock(
                return_value=Response(200, text="not valid json{{{")
            )
            r.get(url__regex=r".*").mock(return_value=Response(404, text=_S3_404))

            result = await tool.run("example.com")

        assert result.success is True
        assert result.data["ecr"] == []


# ════════════════════════════════════════════════════════════════════════
# Bucket enum — bucket_enum (T2)
# ════════════════════════════════════════════════════════════════════════

class TestBucketEnumTool:
    """Multi-provider bucket sweep — S3 + Azure Blob + GCS via HEAD probes."""

    async def test_happy_path(self) -> None:
        """One S3 public (200), one Azure 403 (exists), one GCS public (200).
        Everything else 404."""
        tool = BucketEnumTool()
        with respx.mock(assert_all_called=False) as r:
            r.head("https://example.s3.amazonaws.com").mock(
                return_value=Response(200)
            )
            r.head("https://example.blob.core.windows.net").mock(
                return_value=Response(403)
            )
            r.head("https://storage.googleapis.com/example").mock(
                return_value=Response(200)
            )
            # Catchall
            r.head(url__regex=r".*\.s3\.amazonaws\.com.*").mock(
                return_value=Response(404)
            )
            r.head(url__regex=r".*\.blob\.core\.windows\.net.*").mock(
                return_value=Response(404)
            )
            r.head(url__regex=r".*storage\.googleapis\.com.*").mock(
                return_value=Response(404)
            )

            result = await tool.run("example.com")

        assert result.success is True
        assert result.data["domain"] == "example.com"
        assert result.data["open_count"] >= 3
        providers = {b["provider"] for b in result.data["open_buckets"]}
        assert "s3" in providers
        assert "azure_blob" in providers
        assert "gcs" in providers
        # Public/accessible flag derived from status code.
        s3_hit = next(
            b for b in result.data["open_buckets"]
            if b["provider"] == "s3" and b["bucket"] == "example"
        )
        assert s3_hit["public"] is True
        assert s3_hit["status"] == 200
        azure_hit = next(
            b for b in result.data["open_buckets"]
            if b["provider"] == "azure_blob" and b["bucket"] == "example"
        )
        assert azure_hit["public"] is False
        assert azure_hit["status"] == 403
        assert result.data["attribution_confidence"] == 0.2
        assert "name_permutation_enumeration" in result.data["attribution_signals"]

    async def test_empty_response(self) -> None:
        """Every HEAD returns 404. Tool succeeds with zero open buckets."""
        tool = BucketEnumTool()
        with respx.mock(assert_all_called=False) as r:
            r.head(url__regex=r".*").mock(return_value=Response(404))

            result = await tool.run("example.com")

        assert result.success is True
        assert result.result_count == 0
        assert result.data["open_count"] == 0
        assert result.data["open_buckets"] == []
        # The endpoints_probed count should still be > 0 — we did probe,
        # just nothing came back open.
        assert result.data["endpoints_probed"] > 0

    async def test_connection_error_path(self) -> None:
        """All HEAD probes raise. Per-probe try/except swallows, so tool
        reports success with no open buckets."""
        tool = BucketEnumTool()
        with respx.mock(assert_all_called=False) as r:
            r.head(url__regex=r".*").mock(
                side_effect=httpx.ConnectError("connection refused")
            )

            result = await tool.run("example.com")

        assert result.success is True
        assert result.result_count == 0
        assert result.data["open_buckets"] == []

    async def test_server_error_path(self) -> None:
        """Every probe returns 500. 500 is not in (200, 403), so the tool
        treats them all as "not open" and returns empty success."""
        tool = BucketEnumTool()
        with respx.mock(assert_all_called=False) as r:
            r.head(url__regex=r".*").mock(return_value=Response(500))

            result = await tool.run("example.com")

        assert result.success is True
        assert result.result_count == 0
        assert result.data["open_buckets"] == []


# ════════════════════════════════════════════════════════════════════════
# Azure M365 recon — azure_m365_recon
# ════════════════════════════════════════════════════════════════════════

class TestAzureM365ReconTool:
    """Azure / Entra ID / M365 tenant enumeration via public endpoints."""

    async def test_happy_path(self) -> None:
        """OpenID + getuserrealm both return canonical responses; storage
        and app services and ADFS all 404 (since they're independent
        signals). Verify tenant_id is extracted and federation type
        flagged as Managed."""
        tool = AzureM365Tool()
        openid_fixture = load_fixture("azure_m365_recon/openid_config.json")
        realm_xml = load_text_fixture("azure_m365_recon/getuserrealm_managed.xml")
        # Stub the DNS resolver — DKIM check uses dns.asyncresolver which
        # would otherwise attempt a real DNS query.
        with patch("dns.asyncresolver.Resolver.resolve", new_callable=AsyncMock) as dns_mock:
            dns_mock.side_effect = Exception("no DNS records")
            with respx.mock(assert_all_called=False) as r:
                r.get(
                    url__regex=r"https://login\.microsoftonline\.com/example\.com/\.well-known/openid-configuration"
                ).mock(return_value=Response(200, json=openid_fixture))
                r.get(
                    url__regex=r"https://login\.microsoftonline\.com/getuserrealm\.srf.*"
                ).mock(return_value=Response(200, text=realm_xml))
                # Every other OpenID candidate (onmicrosoft variants) returns 404.
                r.get(
                    url__regex=r"https://login\.microsoftonline\.com/.*"
                ).mock(return_value=Response(404))
                # Storage HEAD probes — all not found.
                r.head(url__regex=r".*\.core\.windows\.net.*").mock(
                    return_value=Response(404)
                )
                # App service + DevOps + ADFS GETs — all not found.
                r.get(url__regex=r".*\.azurewebsites\.net.*").mock(
                    return_value=Response(404)
                )
                r.get(url__regex=r".*\.scm\.azurewebsites\.net.*").mock(
                    return_value=Response(404)
                )
                r.get(url__regex=r".*dev\.azure\.com.*").mock(
                    return_value=Response(404)
                )
                r.get(url__regex=r".*\.visualstudio\.com.*").mock(
                    return_value=Response(404)
                )
                r.get(url__regex=r"https://(adfs|sts|login|sso)\.example\.com.*").mock(
                    return_value=Response(404)
                )

                result = await tool.run("example.com")

        assert result.success is True
        # OpenID config parsed.
        openid = result.data["openid_config"]
        assert openid["found"] is True
        assert openid["tenant_id"] == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        assert openid["issuer"].startswith("https://login.microsoftonline.com/")
        # User realm parsed from XML.
        realm = result.data["user_realm"]
        assert realm["found"] is True
        assert realm["is_federated"] is False  # state=4 → not state=3
        assert realm["federation_type"] == "Managed"
        assert realm["federation_brand_name"] == "Example Corp"
        # Attribution gate: openid verified → confidence 1.0.
        assert result.data["attribution_confidence"] == 1.0
        assert "openid_config_verified" in result.data["attribution_signals"]

    async def test_happy_path_federated(self) -> None:
        """Same shape but ADFS-federated tenant; verify federation_protocol
        is set and is_federated=True."""
        tool = AzureM365Tool()
        openid_fixture = load_fixture("azure_m365_recon/openid_config.json")
        realm_xml = load_text_fixture("azure_m365_recon/getuserrealm_federated.xml")
        with patch("dns.asyncresolver.Resolver.resolve", new_callable=AsyncMock) as dns_mock:
            dns_mock.side_effect = Exception("no DNS records")
            with respx.mock(assert_all_called=False) as r:
                r.get(
                    url__regex=r"https://login\.microsoftonline\.com/example\.com/\.well-known/openid-configuration"
                ).mock(return_value=Response(200, json=openid_fixture))
                r.get(
                    url__regex=r"https://login\.microsoftonline\.com/getuserrealm\.srf.*"
                ).mock(return_value=Response(200, text=realm_xml))
                r.get(url__regex=r"https://login\.microsoftonline\.com/.*").mock(
                    return_value=Response(404)
                )
                r.head(url__regex=r".*\.core\.windows\.net.*").mock(
                    return_value=Response(404)
                )
                r.get(url__regex=r".*\.azurewebsites\.net.*").mock(
                    return_value=Response(404)
                )
                r.get(url__regex=r".*\.scm\.azurewebsites\.net.*").mock(
                    return_value=Response(404)
                )
                r.get(url__regex=r".*dev\.azure\.com.*").mock(
                    return_value=Response(404)
                )
                r.get(url__regex=r".*\.visualstudio\.com.*").mock(
                    return_value=Response(404)
                )
                r.get(url__regex=r"https://(adfs|sts|login|sso)\.example\.com.*").mock(
                    return_value=Response(404)
                )

                result = await tool.run("example.com")

        assert result.success is True
        realm = result.data["user_realm"]
        assert realm["is_federated"] is True  # state=3 → federated
        assert realm["federation_type"] == "Federated (ADFS)"
        assert realm["federation_protocol"] == "WSTrust"

    async def test_empty_response(self) -> None:
        """Domain has no Azure presence — every endpoint 404. Tool still
        succeeds (no exception), confidence drops to 0.2."""
        tool = AzureM365Tool()
        with patch("dns.asyncresolver.Resolver.resolve", new_callable=AsyncMock) as dns_mock:
            dns_mock.side_effect = Exception("no DNS records")
            with respx.mock(assert_all_called=False) as r:
                r.get(url__regex=r".*").mock(return_value=Response(404))
                r.head(url__regex=r".*").mock(return_value=Response(404))

                result = await tool.run("example.com")

        assert result.success is True
        assert result.data["openid_config"]["found"] is False
        assert result.data["user_realm"]["found"] is False
        assert result.data["attribution_confidence"] == 0.2
        assert "no_openid_config" in result.data["attribution_signals"]

    async def test_malformed_openid_json(self) -> None:
        """OpenID endpoint returns garbage. Per-method try/except catches
        the JSON parse error and returns ``found=False`` — the run as a
        whole still succeeds."""
        tool = AzureM365Tool()
        with patch("dns.asyncresolver.Resolver.resolve", new_callable=AsyncMock) as dns_mock:
            dns_mock.side_effect = Exception("no DNS records")
            with respx.mock(assert_all_called=False) as r:
                r.get(
                    url__regex=r"https://login\.microsoftonline\.com/example\.com/\.well-known/openid-configuration"
                ).mock(return_value=Response(200, text="not valid json{{"))
                r.get(url__regex=r".*").mock(return_value=Response(404))
                r.head(url__regex=r".*").mock(return_value=Response(404))

                result = await tool.run("example.com")

        assert result.success is True
        assert result.data["openid_config"]["found"] is False
        # error field is set inside the sub-dict when parsing failed
        assert result.data["openid_config"].get("error") == "request_failed"


# ════════════════════════════════════════════════════════════════════════
# Azure tenant enum — azure_tenant_enum
# ════════════════════════════════════════════════════════════════════════

class TestAzureTenantEnumTool:
    """Tenant-ID + federation discovery via openid-config and getuserrealm."""

    async def test_happy_path(self) -> None:
        """OpenID returns issuer with tenant ID; getuserrealm returns
        Managed JSON; sharepoint HEAD returns 200 for the stem."""
        tool = AzureTenantTool()
        openid_fixture = load_fixture("azure_tenant_enum/openid_config.json")
        realm_fixture = load_fixture("azure_tenant_enum/getuserrealm_managed.json")
        common_fixture = load_fixture("azure_tenant_enum/common_discovery.json")
        with respx.mock(assert_all_called=False) as r:
            r.get(
                url__regex=r"https://login\.microsoftonline\.com/example\.com/\.well-known/openid-configuration"
            ).mock(return_value=Response(200, json=openid_fixture))
            r.get(
                url__regex=r"https://login\.microsoftonline\.com/getuserrealm\.srf.*"
            ).mock(return_value=Response(200, json=realm_fixture))
            r.get(
                url__regex=r"https://login\.microsoftonline\.com/common/discovery/instance.*"
            ).mock(return_value=Response(200, json=common_fixture))
            # First sharepoint HEAD hit returns 200 → match.
            r.head("https://example.sharepoint.com").mock(
                return_value=Response(200)
            )
            r.head(url__regex=r".*\.sharepoint\.com.*").mock(
                return_value=Response(404)
            )

            result = await tool.run("example.com")

        assert result.success is True
        assert result.data["domain"] == "example.com"
        assert result.data["tenant_id"] == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        assert result.data["issuer"].startswith("https://sts.windows.net/")
        assert result.data["namespace_type"] == "Managed"
        assert result.data["is_federated"] is False
        assert result.data["federation_brand"] == "Example Corp"
        assert "example.onmicrosoft.com" in result.data["onmicrosoft_domains"]
        assert result.data["sharepoint_url"] == "https://example.sharepoint.com"
        assert result.data["attribution_confidence"] == 1.0
        assert "openid_config_verified" in result.data["attribution_signals"]
        # result_count = 1 when tenant_id found
        assert result.result_count == 1

    async def test_happy_path_federated(self) -> None:
        """Same shape but realm is Federated. Verify is_federated flips
        and AuthURL passes through."""
        tool = AzureTenantTool()
        openid_fixture = load_fixture("azure_tenant_enum/openid_config.json")
        realm_fixture = load_fixture("azure_tenant_enum/getuserrealm_federated.json")
        with respx.mock(assert_all_called=False) as r:
            r.get(
                url__regex=r"https://login\.microsoftonline\.com/example\.com/\.well-known/openid-configuration"
            ).mock(return_value=Response(200, json=openid_fixture))
            r.get(
                url__regex=r"https://login\.microsoftonline\.com/getuserrealm\.srf.*"
            ).mock(return_value=Response(200, json=realm_fixture))
            r.get(
                url__regex=r"https://login\.microsoftonline\.com/common/discovery/instance.*"
            ).mock(return_value=Response(200, json={}))
            r.head(url__regex=r".*\.sharepoint\.com.*").mock(
                return_value=Response(404)
            )

            result = await tool.run("example.com")

        assert result.success is True
        assert result.data["namespace_type"] == "Federated"
        assert result.data["is_federated"] is True
        assert result.data["adfs_auth_url"].startswith("https://adfs.example.com")

    async def test_empty_response(self) -> None:
        """No openid-config → no tenant_id → result_count=0 but success
        is still True. Tool only returns failure on uncaught exception."""
        tool = AzureTenantTool()
        with respx.mock(assert_all_called=False) as r:
            r.get(url__regex=r".*").mock(return_value=Response(404))
            r.head(url__regex=r".*").mock(return_value=Response(404))

            result = await tool.run("example.com")

        assert result.success is True
        assert result.result_count == 0
        assert "tenant_id" not in result.data or result.data.get("tenant_id") is None
        assert result.data["onmicrosoft_domains"] == []
        assert result.data["attribution_confidence"] == 0.2

    async def test_connection_error(self) -> None:
        """The OpenID request raises ConnectError before any other probe
        runs. The outer try/except wraps the whole flow, so the tool
        returns ``success=False`` with an error message."""
        tool = AzureTenantTool()
        with respx.mock(assert_all_called=False) as r:
            r.get(url__regex=r".*").mock(
                side_effect=httpx.ConnectError("dns lookup failed")
            )
            r.head(url__regex=r".*").mock(
                side_effect=httpx.ConnectError("dns lookup failed")
            )

            result = await tool.run("example.com")

        assert result.success is False
        assert result.error

    async def test_malformed_json(self) -> None:
        """OpenID returns HTML instead of JSON. The outer try/except
        catches the JSON parse failure, so this propagates as a tool-level
        failure (the parse happens outside per-endpoint try/except)."""
        tool = AzureTenantTool()
        with respx.mock(assert_all_called=False) as r:
            r.get(
                url__regex=r"https://login\.microsoftonline\.com/example\.com/\.well-known/openid-configuration"
            ).mock(return_value=Response(200, text="<html>not json</html>"))
            r.get(url__regex=r".*").mock(return_value=Response(404))
            r.head(url__regex=r".*").mock(return_value=Response(404))

            result = await tool.run("example.com")

        # Tool's outer try/except wraps the .json() call, so malformed
        # JSON propagates as a hard failure.
        assert result.success is False
        assert result.error


# ════════════════════════════════════════════════════════════════════════
# GCP recon — gcp_recon (partial stub: GCS + App Engine implemented,
# Firebase/Cloud Run return ``{"status": "stubbed"}``)
# ════════════════════════════════════════════════════════════════════════

class TestGCPReconTool:
    """Stubbed cloud-probe — only GCS + App Engine are implemented."""

    async def test_happy_path(self) -> None:
        """One GCS bucket public (200), one App Engine app 200."""
        tool = GCPReconTool()
        with respx.mock(assert_all_called=False) as r:
            r.get(url__regex=r"https://storage\.googleapis\.com/example/.*").mock(
                return_value=Response(200, text="<ListBucketResult></ListBucketResult>")
            )
            r.get(url__regex=r"https://storage\.googleapis\.com/.*").mock(
                return_value=Response(404)
            )
            r.get("https://example.appspot.com").mock(
                return_value=Response(200, text="hello world")
            )
            r.get(url__regex=r".*\.appspot\.com.*").mock(
                return_value=Response(404)
            )

            result = await tool.run("example.com")

        assert result.success is True
        # GCS hit
        gcs = result.data["gcs_buckets"]
        assert any(b["name"] == "example" and b["public"] is True for b in gcs)
        # App Engine hit
        appengine = result.data["app_engine"]
        assert any(a["name"] == "example" for a in appengine)
        # Stubbed parts: tool source says ``{"status": "stubbed"}``.
        assert result.data["firebase"] == {"status": "stubbed"}
        assert result.data["cloud_run"] == {"status": "stubbed"}
        # result_count = len(gcs) + len(app_engine) — stubs not counted.
        assert result.result_count == len(gcs) + len(appengine)

    async def test_empty_response(self) -> None:
        """Every probe 404. Tool succeeds with empty GCS + App Engine,
        stub fields still present."""
        tool = GCPReconTool()
        with respx.mock(assert_all_called=False) as r:
            r.get(url__regex=r".*").mock(return_value=Response(404))

            result = await tool.run("example.com")

        assert result.success is True
        assert result.result_count == 0
        assert result.data["gcs_buckets"] == []
        assert result.data["app_engine"] == []
        # Stubs still present even on empty run.
        assert result.data["firebase"] == {"status": "stubbed"}
        assert result.data["cloud_run"] == {"status": "stubbed"}

    async def test_connection_error_path(self) -> None:
        """Each per-endpoint call raises. Per-call try/except swallows,
        so tool reports success with empty results."""
        tool = GCPReconTool()
        with respx.mock(assert_all_called=False) as r:
            r.get(url__regex=r".*").mock(
                side_effect=httpx.ConnectError("connection refused")
            )

            result = await tool.run("example.com")

        assert result.success is True
        assert result.result_count == 0
        assert result.data["gcs_buckets"] == []
        assert result.data["app_engine"] == []
        # Stubs still present.
        assert result.data["firebase"] == {"status": "stubbed"}
        assert result.data["cloud_run"] == {"status": "stubbed"}

    async def test_server_error_path(self) -> None:
        """500 is not in (200, 403); tool treats it as "not open" and
        returns empty success."""
        tool = GCPReconTool()
        with respx.mock(assert_all_called=False) as r:
            r.get(url__regex=r".*").mock(return_value=Response(500))

            result = await tool.run("example.com")

        assert result.success is True
        assert result.data["gcs_buckets"] == []
        # App Engine treats != 404 as "found" — 500 IS found. This is the
        # documented behavior of the source code (intentional or not).
        assert all(a["status"] == 500 for a in result.data["app_engine"])

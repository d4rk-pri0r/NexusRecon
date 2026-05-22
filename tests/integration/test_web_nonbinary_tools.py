"""Integration tests for the web tool category — pure-Python (non-binary) tools.

Same four-test pattern as ``test_subdomain_tools.py``:

  1. **Happy path** — provider/library returns the canonical documented
     response; tool parses it and returns ``ToolResult(success=True)``
     with the expected ``data`` shape.
  2. **Empty result** — provider/library returns empty data; tool returns
     ``success=True, result_count=0`` rather than treating empty as
     an error.
  3. **Error path** — provider returns 4xx/5xx or the library raises;
     tool returns ``success=False`` with a useful ``error`` string.
  4. **Schema drift / malformed** — provider returns malformed JSON or an
     unexpected shape; tool fails gracefully (no traceback escapes).

Tools covered:
  - ``wayback``           — wraps ``waybackpy.WaybackMachineCDXServerAPI``
                            (mocked at the library level since the library
                            speaks its own protocol).
  - ``cms_detect``        — pure-HTTP fingerprinting scrape.
  - ``linkfinder``        — pure-HTTP JS endpoint extractor.
  - ``sslyze``            — wraps the ``sslyze`` Python library; mocked
                            at the library level (sockets, not HTTP).
  - ``subdomain_takeover``— wraps both dnspython (CNAME) and httpx (body
                            probe); mock both.
  - ``wafw00f``           — pure-HTTP WAF signature scrape.

These tools live under ``nexusrecon/tools/web/`` and do *not* shell out
to a binary; the binary-wrapping web tools (gowitness, katana, nuclei,
gau, arjun, webtech) are covered separately under ``test_tools_binary``.
"""
from __future__ import annotations

from collections.abc import Iterable
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import httpx
import respx
from httpx import Response

from nexusrecon.tools.web.cms_detect_tool import CMSDetectTool
from nexusrecon.tools.web.linkfinder_tool import LinkFinderTool
from nexusrecon.tools.web.sslyze_tool import SSLyzeTool
from nexusrecon.tools.web.subdomain_takeover_tool import SubdomainTakeoverTool
from nexusrecon.tools.web.wafw00f_tool import WafW00fTool
from nexusrecon.tools.web.wayback_tool import WaybackTool
from tests.fixtures import load_fixture, load_text_fixture

# ────────────────────────────────────────────────────────────────────────
# Wayback Machine — waybackpy.WaybackMachineCDXServerAPI
#
# The tool wraps the library, which speaks the CDX server protocol; we
# mock the library class itself rather than respx-mocking the HTTP layer.
# The tool reads ``snapshot.original`` (the captured URL),
# ``snapshot.timestamp``, ``snapshot.statuscode`` and
# ``snapshot.mimetype`` off each yielded snapshot — the same attribute
# names ``waybackpy.CDXSnapshot`` actually exposes (see
# ``venv/lib/.../waybackpy/cdx_snapshot.py``). The fake snapshots mirror
# those names via SimpleNamespace so we'd catch any drift if the tool
# ever started reading mis-named attributes again.
# ────────────────────────────────────────────────────────────────────────

def _fake_snapshots(records: Iterable[dict]) -> list[SimpleNamespace]:
    """Convert raw CDX-style dicts into objects with the attributes
    the wayback tool reads off each snapshot.

    Attribute names match the real ``waybackpy.CDXSnapshot`` API
    (``original`` / ``timestamp`` / ``statuscode`` / ``mimetype``).
    If the tool's reads ever drift back to the old ``.url`` / ``.status``
    spelling, these mocks won't satisfy the read and the test will fail
    loudly with ``AttributeError`` — which is the point.
    """
    out = []
    for rec in records:
        out.append(SimpleNamespace(
            original=rec["original"],
            timestamp=rec["timestamp"],
            statuscode=rec["statuscode"],
            mimetype=rec["mimetype"],
        ))
    return out


class TestWaybackTool:
    """``wayback`` wraps ``waybackpy.WaybackMachineCDXServerAPI``; we
    patch the class in the tool module so no real HTTP fires."""

    async def test_happy_path(self) -> None:
        fixture = load_fixture("wayback/cdx_snapshots.json")
        fake_snaps = _fake_snapshots(fixture)

        fake_cdx = MagicMock()
        fake_cdx.snapshots.return_value = iter(fake_snaps)

        with patch(
            "nexusrecon.tools.web.wayback_tool.WaybackMachineCDXServerAPI",
            return_value=fake_cdx,
        ):
            tool = WaybackTool()
            result = await tool.run("example.com")

        assert result.success is True
        urls = result.data["urls"]
        assert "https://example.com/" in urls
        assert "https://example.com/about" in urls
        assert "https://example.com/api/users" in urls
        assert "https://example.com/contact" in urls
        # urls are deduplicated and sorted; result_count tracks unique urls
        assert result.result_count == len(urls)
        # snapshots list carries timestamp/status/mimetype
        snaps = result.data["snapshots"]
        assert len(snaps) == len(fixture)
        sample = next(s for s in snaps if s["url"] == "https://example.com/api/users")
        assert sample["timestamp"] == "20220607093015"
        assert sample["status"] == "200"
        assert sample["mimetype"] == "application/json"

    async def test_empty_response(self) -> None:
        fake_cdx = MagicMock()
        fake_cdx.snapshots.return_value = iter([])

        with patch(
            "nexusrecon.tools.web.wayback_tool.WaybackMachineCDXServerAPI",
            return_value=fake_cdx,
        ):
            tool = WaybackTool()
            result = await tool.run("example.com")

        assert result.success is True
        assert result.result_count == 0
        assert result.data["urls"] == []
        assert result.data["snapshots"] == []

    async def test_error_path(self) -> None:
        """waybackpy raises on connection/CDX errors — tool catches and
        returns ``success=False`` with the exception text."""
        fake_cdx = MagicMock()
        fake_cdx.snapshots.side_effect = RuntimeError("CDX server unreachable")

        with patch(
            "nexusrecon.tools.web.wayback_tool.WaybackMachineCDXServerAPI",
            return_value=fake_cdx,
        ):
            tool = WaybackTool()
            result = await tool.run("example.com")

        assert result.success is False
        assert "CDX server unreachable" in result.error

    async def test_malformed_snapshot(self) -> None:
        """A snapshot record missing the attributes the tool reads should
        raise AttributeError inside the iteration loop; the tool's
        ``except Exception`` catches it and returns failure."""
        MagicMock()
        # ``broken.url`` returns another MagicMock (fine), but iterating
        # the list and adding to ``set`` requires hashable items — make
        # the snapshot generator itself blow up partway through.
        fake_cdx = MagicMock()

        def _bad_gen():
            yield SimpleNamespace(
                original="https://example.com/",
                timestamp="x",
                statuscode="200",
                mimetype="text/html",
            )
            raise ValueError("malformed snapshot row from CDX")

        fake_cdx.snapshots.return_value = _bad_gen()

        with patch(
            "nexusrecon.tools.web.wayback_tool.WaybackMachineCDXServerAPI",
            return_value=fake_cdx,
        ):
            tool = WaybackTool()
            result = await tool.run("example.com")

        assert result.success is False
        assert result.error


# ────────────────────────────────────────────────────────────────────────
# CMSDetect — HTTP fingerprinting against a homepage + per-CMS probe
# paths. Mock every path the tool probes by matching the base URL prefix.
# ────────────────────────────────────────────────────────────────────────

class TestCMSDetectTool:
    BASE = "https://example.com"

    async def test_happy_path_wordpress(self) -> None:
        tool = CMSDetectTool()
        wp_home = load_text_fixture("cms_detect/wordpress_home.html")
        wp_json = load_fixture("cms_detect/wp_json.json")

        with respx.mock(assert_all_called=False) as router:
            router.get("https://example.com/wp-login.php").mock(
                return_value=Response(200, text=wp_home)
            )
            router.get("https://example.com/wp-json/").mock(
                return_value=Response(200, json=wp_json)
            )
            # All other CMS probes return innocuous 404s
            router.get(url__startswith=self.BASE).mock(
                return_value=Response(404, text="Not Found")
            )
            result = await tool.run("example.com")

        assert result.success is True
        assert result.data["primary_cms"] == "WordPress"
        assert result.data["primary_confidence"] > 0
        # detected list is sorted by score desc; WordPress should be first
        assert result.data["detected"][0]["cms"] == "WordPress"
        evidence = result.data["detected"][0]["evidence"]
        # Evidence strings look like "body:<pattern>" or "header:<name>:<val>"
        assert any("wp-content" in e or "wp-includes" in e or "WordPress" in e for e in evidence)
        assert result.result_count >= 1

    async def test_empty_response(self) -> None:
        """All probes return 404 with empty bodies — no CMS detected."""
        tool = CMSDetectTool()
        with respx.mock:
            respx.get(url__startswith=self.BASE).mock(
                return_value=Response(404, text="")
            )
            result = await tool.run("example.com")

        assert result.success is True
        assert result.result_count == 0
        assert result.data["detected"] == []
        assert result.data["primary_cms"] is None
        assert result.data["primary_confidence"] == 0.0

    async def test_error_path(self) -> None:
        """Every probe fails with a connection error — the tool's
        per-probe try/except swallows each one, so the outer call still
        finishes with success=True and no detections."""
        tool = CMSDetectTool()
        with respx.mock:
            respx.get(url__startswith=self.BASE).mock(
                side_effect=httpx.ConnectError("connection refused")
            )
            result = await tool.run("example.com")

        # Per-probe errors are caught individually; tool returns success
        # with zero detections rather than failing the whole scan.
        assert result.success is True
        assert result.result_count == 0
        assert result.data["detected"] == []

    async def test_malformed_response(self) -> None:
        """Probe returns binary garbage that doesn't match any pattern —
        tool returns success=True with empty detections (no traceback)."""
        tool = CMSDetectTool()
        with respx.mock:
            respx.get(url__startswith=self.BASE).mock(
                return_value=Response(200, text="\x00\x01\x02 not html and not json")
            )
            result = await tool.run("example.com")

        assert result.success is True
        # Body has no recognizable CMS markers — empty detection list
        assert result.data["detected"] == []


# ────────────────────────────────────────────────────────────────────────
# LinkFinder — fetch homepage, find <script src>, fetch each, regex out
# API endpoints.
# ────────────────────────────────────────────────────────────────────────

class TestLinkFinderTool:
    BASE = "https://example.com"

    async def test_happy_path(self) -> None:
        tool = LinkFinderTool()
        homepage = load_text_fixture("linkfinder/homepage.html")
        app_js = load_text_fixture("linkfinder/app_bundle.js")
        vendor_js = load_text_fixture("linkfinder/vendor.js")

        with respx.mock(assert_all_called=False) as router:
            # Register specific routes first — respx matches by declaration
            # order, and a plain-string URL pattern matches by prefix.
            router.get("https://example.com/static/js/app.bundle.js").mock(
                return_value=Response(200, text=app_js)
            )
            router.get("https://example.com/static/js/vendor.js").mock(
                return_value=Response(200, text=vendor_js)
            )
            router.get(url__eq="https://example.com").mock(
                return_value=Response(200, text=homepage)
            )
            result = await tool.run("example.com")

        assert result.success is True
        endpoints = result.data["endpoints"]
        # Endpoints from app_bundle.js — pattern 1 (path-only), pattern 2
        # (fetch/axios), and pattern 3 (keyword colon) each contribute.
        assert "/api/v2/orders" in endpoints       # pattern 1
        assert "/api/v1/profile" in endpoints      # pattern 2 (fetch)
        assert "/rest/inventory/list" in endpoints # pattern 2 (axios.get)
        assert "/api/v1/sessions" in endpoints     # pattern 2 (fetch)
        assert "/graphql" in endpoints             # pattern 3 (endpoint:)
        # Inline endpoints from the homepage <script> block
        assert "/api/inline/config" in endpoints
        assert "/api/inline/users" in endpoints
        # api_endpoints sub-list keeps only /api/, /v1/, /v2/, /graphql, /rest/
        api_eps = result.data["api_endpoints"]
        assert any("/api/" in e for e in api_eps)
        assert "/graphql" in api_eps
        assert result.data["js_files_scanned"] == 2
        assert result.data["endpoint_count"] >= 6
        assert result.result_count == len(endpoints)

    async def test_empty_response(self) -> None:
        """Homepage returns 200 with no scripts and no inline endpoints —
        tool returns success with empty endpoint list."""
        tool = LinkFinderTool()
        with respx.mock:
            respx.get("https://example.com").mock(
                return_value=Response(200, text="<html><body>no scripts here</body></html>")
            )
            result = await tool.run("example.com")

        assert result.success is True
        assert result.result_count == 0
        assert result.data["endpoints"] == []
        assert result.data["js_files_scanned"] == 0

    async def test_error_path(self) -> None:
        """Homepage returns a non-200; tool bails with success=False."""
        tool = LinkFinderTool()
        with respx.mock:
            respx.get("https://example.com").mock(
                return_value=Response(500, text="server error")
            )
            result = await tool.run("example.com")

        assert result.success is False
        assert "500" in result.error

    async def test_malformed_response(self) -> None:
        """Homepage fetch raises at the transport layer — tool catches and
        returns failure."""
        tool = LinkFinderTool()
        with respx.mock:
            respx.get("https://example.com").mock(
                side_effect=httpx.ConnectError("connection reset")
            )
            result = await tool.run("example.com")

        assert result.success is False
        assert result.error


# ────────────────────────────────────────────────────────────────────────
# SSLyze — wraps the ``sslyze`` Python library. The library speaks raw
# TLS sockets, so we cannot respx-mock it; instead we patch the names
# the tool imports inside ``_run_sslyze_sync`` (Scanner, ServerNetwork-
# Location, ServerScanRequest) and feed a fake scan result.
# ────────────────────────────────────────────────────────────────────────

def _make_fake_cipher_result(cipher_names: list[str]) -> MagicMock:
    """Return a fake per-protocol scan result with ``accepted_cipher_suites``."""
    suites = []
    for name in cipher_names:
        cs = MagicMock()
        cs.cipher_suite.name = name
        suites.append(cs)
    r = MagicMock()
    r.accepted_cipher_suites = suites
    return r


def _make_fake_scan_result(
    protocols: dict,
    heartbleed: bool = False,
    ccs_injection: bool = False,
    cert_subject: str = "CN=example.com",
) -> MagicMock:
    """Build the fake ``ServerScanResult`` shape the tool reads.

    Vulnerability sub-results use ``SimpleNamespace`` rather than
    ``MagicMock`` because the tool's vuln-detection loop falls back
    through ``getattr(r, "is_vulnerable_to_heartbleed", None)`` on every
    plugin result; bare ``MagicMock`` auto-generates a truthy attribute
    for whatever name is accessed, falsely flagging vulnerabilities.
    """
    scan = MagicMock()
    # Per-protocol cipher suite results — empty list means "protocol not
    # supported" in the tool's logic.
    scan.ssl_2_0_cipher_suites = _make_fake_cipher_result(protocols.get("SSLv2", []))
    scan.ssl_3_0_cipher_suites = _make_fake_cipher_result(protocols.get("SSLv3", []))
    scan.tls_1_0_cipher_suites = _make_fake_cipher_result(protocols.get("TLSv1.0", []))
    scan.tls_1_1_cipher_suites = _make_fake_cipher_result(protocols.get("TLSv1.1", []))
    scan.tls_1_2_cipher_suites = _make_fake_cipher_result(protocols.get("TLSv1.2", []))
    scan.tls_1_3_cipher_suites = _make_fake_cipher_result(protocols.get("TLSv1.3", []))

    # Heartbleed result — only ``is_vulnerable_to_heartbleed`` exposed.
    scan.heartbleed = SimpleNamespace(is_vulnerable_to_heartbleed=heartbleed)

    # Robot result — exposes ``robot_result`` only; the tool then maps
    # via RobotScanResultEnum. We skip mapping by leaving robot_result
    # absent (None) so the tool concludes "not vulnerable".
    scan.robot = SimpleNamespace()

    # CCS injection — only ``is_vulnerable_to_ccs_injection`` exposed.
    scan.openssl_ccs_injection = SimpleNamespace(is_vulnerable_to_ccs_injection=ccs_injection)

    # Certificate info — nested chain
    leaf = MagicMock()
    leaf.subject.rfc4514_string.return_value = cert_subject
    leaf.issuer.rfc4514_string.return_value = "CN=Let's Encrypt R3"
    leaf.not_valid_before_utc = "2026-01-01 00:00:00+00:00"
    leaf.not_valid_after_utc = "2026-04-01 00:00:00+00:00"
    deployment = MagicMock()
    deployment.verified_certificate_chain = [leaf]
    cert = MagicMock()
    cert.certificate_deployments = [deployment]
    scan.certificate_info = cert

    # Top-level scan result wrapper
    sr = MagicMock()
    sr.scan_status.name = "COMPLETED"
    sr.scan_result = scan
    return sr


class TestSSLyzeTool:
    """``sslyze`` uses sockets, not HTTP — mock the library directly."""

    async def test_happy_path_modern_tls(self) -> None:
        tool = SSLyzeTool()
        # Modern: TLS 1.2 + 1.3 only, no vulns
        sr = _make_fake_scan_result(
            protocols={"TLSv1.2": ["TLS_AES_128_GCM_SHA256"], "TLSv1.3": ["TLS_AES_256_GCM_SHA384"]},
        )
        scanner_instance = MagicMock()
        scanner_instance.get_results.return_value = iter([sr])

        with patch("sslyze.Scanner", return_value=scanner_instance), \
             patch("sslyze.ServerNetworkLocation"), \
             patch("sslyze.ServerScanRequest"):
            result = await tool.run("example.com")

        assert result.success is True
        protos = result.data["supported_protocols"]
        assert "TLSv1.2" in protos
        assert "TLSv1.3" in protos
        assert "SSLv2" not in protos
        assert result.data["vulnerabilities"] == []
        assert result.data["weak_ciphers"] == []
        assert result.data["grade"] == "A"
        assert result.data["cert_chain"]["subject"] == "CN=example.com"
        assert result.data["target"] == "example.com"

    async def test_happy_path_legacy_and_vulns(self) -> None:
        """Heartbleed + SSLv3 enabled → grade F."""
        tool = SSLyzeTool()
        sr = _make_fake_scan_result(
            protocols={
                "SSLv3": ["SSL_RSA_WITH_RC4_128_SHA"],
                "TLSv1.0": ["TLS_RSA_WITH_AES_128_CBC_SHA"],
                "TLSv1.2": ["TLS_AES_128_GCM_SHA256"],
            },
            heartbleed=True,
        )
        scanner_instance = MagicMock()
        scanner_instance.get_results.return_value = iter([sr])

        with patch("sslyze.Scanner", return_value=scanner_instance), \
             patch("sslyze.ServerNetworkLocation"), \
             patch("sslyze.ServerScanRequest"):
            result = await tool.run("example.com")

        assert result.success is True
        assert "heartbleed" in result.data["vulnerabilities"]
        assert result.data["grade"] == "F"
        # Weak ciphers from legacy protocols
        assert any("SSLv3" in wc for wc in result.data["weak_ciphers"])
        assert any("TLSv1.0" in wc for wc in result.data["weak_ciphers"])
        # result_count = vulns + weak_ciphers
        assert result.result_count == len(result.data["vulnerabilities"]) + len(result.data["weak_ciphers"])

    async def test_empty_response(self) -> None:
        """Connectivity failure — scan_status is ERROR_NO_CONNECTIVITY."""
        tool = SSLyzeTool()
        sr = MagicMock()
        sr.scan_status.name = "ERROR_NO_CONNECTIVITY"
        scanner_instance = MagicMock()
        scanner_instance.get_results.return_value = iter([sr])

        with patch("sslyze.Scanner", return_value=scanner_instance), \
             patch("sslyze.ServerNetworkLocation"), \
             patch("sslyze.ServerScanRequest"):
            result = await tool.run("offline.example.com")

        assert result.success is False
        assert "Cannot connect" in result.error
        assert "offline.example.com" in result.error

    async def test_error_path(self) -> None:
        """Scanner construction raises — tool catches and returns failure."""
        tool = SSLyzeTool()
        with patch("sslyze.Scanner", side_effect=RuntimeError("sslyze internal failure")), \
             patch("sslyze.ServerNetworkLocation"), \
             patch("sslyze.ServerScanRequest"):
            result = await tool.run("example.com")

        assert result.success is False
        assert "sslyze internal failure" in result.error


# ────────────────────────────────────────────────────────────────────────
# Subdomain Takeover — patches ``_resolve_cname`` (dnspython) and
# respx-mocks the HTTP body probe.
# ────────────────────────────────────────────────────────────────────────

class TestSubdomainTakeoverTool:

    async def test_happy_path_github_pages(self) -> None:
        """CNAME points to github.io + body matches the GitHub Pages
        takeover signature → reported as vulnerable."""
        tool = SubdomainTakeoverTool()
        body = load_text_fixture("subdomain_takeover/github_pages_404.html")

        async def fake_resolve(subdomain: str):
            return "abandoned-org.github.io"

        with patch(
            "nexusrecon.tools.web.subdomain_takeover_tool._resolve_cname",
            side_effect=fake_resolve,
        ), respx.mock:
            respx.get("https://orphan.example.com").mock(
                return_value=Response(404, text=body)
            )
            result = await tool.run(
                "example.com",
                subdomains=["orphan.example.com"],
            )

        assert result.success is True
        assert result.result_count == 1
        vuln = result.data["vulnerable"][0]
        assert vuln["subdomain"] == "orphan.example.com"
        assert vuln["service"] == "GitHub Pages"
        assert vuln["cname"] == "abandoned-org.github.io"
        assert "GitHub Pages site here" in vuln["evidence"]
        assert result.data["tested_count"] == 1

    async def test_happy_path_heroku(self) -> None:
        """Second-provider sanity check — Heroku CNAME + matching body."""
        tool = SubdomainTakeoverTool()
        body = load_text_fixture("subdomain_takeover/heroku_no_app.html")

        async def fake_resolve(subdomain: str):
            return "stale-app.herokuapp.com"

        with patch(
            "nexusrecon.tools.web.subdomain_takeover_tool._resolve_cname",
            side_effect=fake_resolve,
        ), respx.mock:
            respx.get("https://app.example.com").mock(
                return_value=Response(404, text=body)
            )
            result = await tool.run(
                "example.com",
                subdomains=["app.example.com"],
            )

        assert result.success is True
        assert result.result_count == 1
        assert result.data["vulnerable"][0]["service"] == "Heroku"

    async def test_empty_response(self) -> None:
        """No CNAME (NXDOMAIN / no record) → no takeover candidates."""
        tool = SubdomainTakeoverTool()

        async def fake_resolve(subdomain: str):
            return None

        with patch(
            "nexusrecon.tools.web.subdomain_takeover_tool._resolve_cname",
            side_effect=fake_resolve,
        ):
            result = await tool.run(
                "example.com",
                subdomains=["a.example.com", "b.example.com"],
            )

        assert result.success is True
        assert result.result_count == 0
        assert result.data["vulnerable"] == []
        assert result.data["tested_count"] == 2

    async def test_error_path(self) -> None:
        """CNAME hits a takeover provider but the HTTP body does NOT
        contain the expected fingerprint → not flagged as vulnerable."""
        tool = SubdomainTakeoverTool()

        async def fake_resolve(subdomain: str):
            return "live-site.github.io"

        with patch(
            "nexusrecon.tools.web.subdomain_takeover_tool._resolve_cname",
            side_effect=fake_resolve,
        ), respx.mock:
            respx.get("https://live.example.com").mock(
                return_value=Response(200, text="<html><body>real content</body></html>")
            )
            result = await tool.run(
                "example.com",
                subdomains=["live.example.com"],
            )

        # Tool runs cleanly, but no vulnerability flagged
        assert result.success is True
        assert result.result_count == 0
        assert result.data["vulnerable"] == []

    async def test_malformed_response(self) -> None:
        """HTTPS connect fails AND HTTP fallback also fails — tool's
        nested try/except produces empty body, which won't match any
        signature; success=True, zero results."""
        tool = SubdomainTakeoverTool()

        async def fake_resolve(subdomain: str):
            return "abandoned.github.io"

        with patch(
            "nexusrecon.tools.web.subdomain_takeover_tool._resolve_cname",
            side_effect=fake_resolve,
        ), respx.mock:
            respx.get("https://broken.example.com").mock(
                side_effect=httpx.ConnectError("https refused")
            )
            respx.get("http://broken.example.com").mock(
                side_effect=httpx.ConnectError("http refused")
            )
            result = await tool.run(
                "example.com",
                subdomains=["broken.example.com"],
            )

        assert result.success is True
        assert result.data["vulnerable"] == []


# ────────────────────────────────────────────────────────────────────────
# WafW00f — HTTP scrape, custom signature logic (no library wrap).
# ────────────────────────────────────────────────────────────────────────

class TestWafW00fTool:
    BASE = "https://example.com"

    async def test_happy_path_cloudflare(self) -> None:
        """Cloudflare headers on both benign and malicious probes →
        Cloudflare detected with confidence ≥ 0.3."""
        tool = WafW00fTool()
        body = load_text_fixture("wafw00f/cloudflare_block.html")
        cf_headers = {
            "Server": "cloudflare",
            "cf-ray": "8abcd1234efgh567-DFW",
        }

        with respx.mock(assert_all_called=False) as router:
            router.get(url__startswith=self.BASE).mock(
                return_value=Response(200, text=body, headers=cf_headers)
            )
            result = await tool.run("example.com")

        assert result.success is True
        names = {w["name"] for w in result.data["wafs_detected"]}
        assert "Cloudflare" in names
        cf = next(w for w in result.data["wafs_detected"] if w["name"] == "Cloudflare")
        assert cf["confidence"] >= 0.3
        assert "cloudflare" in cf["evidence"].lower() or "cf-ray" in cf["evidence"].lower()
        assert result.result_count >= 1

    async def test_empty_response(self) -> None:
        """Benign 200 with no WAF-indicative headers/body → no WAF
        detected; tool still returns success."""
        tool = WafW00fTool()
        with respx.mock(assert_all_called=False) as router:
            router.get(url__startswith=self.BASE).mock(
                return_value=Response(
                    200,
                    text="<html><body>hello world</body></html>",
                    headers={"Server": "nginx/1.25.0"},
                )
            )
            result = await tool.run("example.com")

        assert result.success is True
        assert result.result_count == 0
        assert result.data["wafs_detected"] == []

    async def test_error_path(self) -> None:
        """Both benign and malicious probes fail at the transport layer.
        The outer try/except for AsyncClient setup does NOT wrap the
        per-probe try/except — failures inside the client zero out body
        and headers, so the tool returns success=True with no detections."""
        tool = WafW00fTool()
        with respx.mock:
            respx.get(url__startswith=self.BASE).mock(
                side_effect=httpx.ConnectError("connection refused")
            )
            result = await tool.run("example.com")

        # Per-probe errors are swallowed; tool returns clean empty result.
        assert result.success is True
        assert result.result_count == 0
        assert result.data["wafs_detected"] == []

    async def test_malformed_response(self) -> None:
        """Provider returns binary garbage with no WAF indicators —
        no detection, no traceback."""
        tool = WafW00fTool()
        with respx.mock(assert_all_called=False) as router:
            router.get(url__startswith=self.BASE).mock(
                return_value=Response(200, text="\x00\xff garbage payload \xde\xad")
            )
            result = await tool.run("example.com")

        assert result.success is True
        assert result.data["wafs_detected"] == []

"""Integration tests for the free / no-key intel-tool category.

Each HTTP-based tool gets the four-test pattern this PR uses as its
standard across every category:

  1. **Happy path** — provider returns the canonical documented JSON
     (or HTML, for scrape tools); tool parses it and returns
     ``ToolResult(success=True)`` with the expected ``data`` shape.
  2. **Empty result** — provider returns an empty list / 404 / empty
     ``data`` envelope; tool returns ``success=True, result_count=0``
     rather than treating empty as an error.
  3. **Error path** — provider returns 429 / 500 / connection-level
     error; tool returns ``success=False`` with a useful ``error``
     string (or, for tools that swallow errors by design, an empty
     success result; documented per-tool below).
  4. **Schema drift** — provider returns malformed JSON or an
     unexpected shape; tool fails gracefully (no traceback escapes).

Tools covered: ``abuseipdb``, ``ipinfo``, ``urlscan``, ``leakix``,
``asn_bgp``, ``ahmia``, ``ransomwatch``, ``pastebin_scan``. The first
also gets a ``test_missing_key`` since it's the only tool in this
group that requires a key.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest
import respx
from httpx import Response

from tests.fixtures import load_fixture, load_text_fixture

from nexusrecon.tools.domain.asn_bgp_tool import ASNBGPTool
from nexusrecon.tools.intel.abuseipdb_tool import AbuseIPDBTool
from nexusrecon.tools.intel.ahmia_tool import AhmiaTool
from nexusrecon.tools.intel.ipinfo_tool import IPInfoTool
from nexusrecon.tools.intel.leakix_tool import LeakIXTool
from nexusrecon.tools.intel.pastebin_tool import PastebinTool
from nexusrecon.tools.intel.ransomwatch_tool import RansomwatchTool
from nexusrecon.tools.intel.urlscan_tool import URLScanTool


# ────────────────────────────────────────────────────────────────────────
# AbuseIPDB — docs.abuseipdb.com (requires key)
# ────────────────────────────────────────────────────────────────────────

class TestAbuseIPDBTool:
    URL = "https://api.abuseipdb.com/api/v2/check"

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-key")
    async def test_happy_path(self, _secret) -> None:
        tool = AbuseIPDBTool()
        fixture = load_fixture("abuseipdb/check.json")
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, json=fixture)
            )
            result = await tool.run("118.25.6.39")
        assert result.success is True
        assert result.result_count == 1
        assert result.data["ip"] == "118.25.6.39"
        assert result.data["abuse_score"] == 100
        assert result.data["total_reports"] == 89
        assert result.data["country"] == "CN"
        assert result.data["isp"] == "Tencent Cloud Computing"
        assert result.data["is_whitelisted"] is False
        # Reports are capped at 10 and trimmed to the fields the tool selects
        assert len(result.data["reports"]) == 2
        assert "SSH brute force" in result.data["reports"][0]["comment"]

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-key")
    async def test_empty_response(self, _secret) -> None:
        """AbuseIPDB returns 200 with an empty data envelope for unseen IPs."""
        tool = AbuseIPDBTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, json={"data": {}})
            )
            result = await tool.run("1.1.1.1")
        # Tool still returns success — empty data dict is a valid response
        assert result.success is True
        assert result.result_count == 1
        assert result.data["ip"] is None
        assert result.data["abuse_score"] is None
        assert result.data["reports"] == []

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-key")
    async def test_error_path(self, _secret) -> None:
        """Non-200 responses leave data as ``{}`` and the tool still reports success.

        AbuseIPDB tool swallows HTTP errors by design — it only fails on exceptions.
        Documented behaviour: data is an empty dict on non-200."""
        tool = AbuseIPDBTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(return_value=Response(429))
            result = await tool.run("118.25.6.39")
        assert result.success is True
        # No parsing happens on non-200, so data stays empty
        assert result.data == {}

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-key")
    async def test_malformed_json(self, _secret) -> None:
        tool = AbuseIPDBTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, text="not valid json")
            )
            result = await tool.run("118.25.6.39")
        assert result.success is False
        assert result.error

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value=None)
    async def test_missing_key(self, _secret) -> None:
        tool = AbuseIPDBTool()
        result = await tool.run("118.25.6.39")
        assert result.success is False
        assert "ABUSEIPDB_API_KEY" in result.error


# ────────────────────────────────────────────────────────────────────────
# IPinfo — ipinfo.io/developers (no key needed for free tier)
# ────────────────────────────────────────────────────────────────────────

class TestIPInfoTool:
    URL = "https://ipinfo.io/"

    async def test_happy_path(self) -> None:
        tool = IPInfoTool()
        fixture = load_fixture("ipinfo/lookup.json")
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, json=fixture)
            )
            result = await tool.run("8.8.8.8")
        assert result.success is True
        assert result.result_count == 1
        assert result.data["ip"] == "8.8.8.8"
        assert result.data["hostname"] == "dns.google"
        assert result.data["city"] == "Mountain View"
        assert result.data["country"] == "US"
        # ASN is parsed out of the org field
        assert result.data["asn"] == "AS15169"
        assert result.data["org_name"] == "Google LLC"
        # Privacy fields default to False when no paid token
        assert result.data["vpn"] is False
        assert result.data["proxy"] is False
        assert result.data["tor"] is False
        assert result.data["hosting"] is False

    async def test_empty_response(self) -> None:
        """An empty JSON object is a valid 'no info' response."""
        tool = IPInfoTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(return_value=Response(200, json={}))
            result = await tool.run("0.0.0.0")
        assert result.success is True
        assert result.result_count == 1
        assert result.data["ip"] is None
        assert result.data["asn"] == ""

    async def test_rate_limited(self) -> None:
        tool = IPInfoTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(return_value=Response(429))
            result = await tool.run("8.8.8.8")
        assert result.success is False
        assert "rate limit" in result.error.lower()

    async def test_malformed_json(self) -> None:
        tool = IPInfoTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, text="not valid json")
            )
            result = await tool.run("8.8.8.8")
        assert result.success is False
        assert result.error


# ────────────────────────────────────────────────────────────────────────
# urlscan.io — urlscan.io/docs/api (no key needed for search)
# ────────────────────────────────────────────────────────────────────────

class TestURLScanTool:
    URL = "https://urlscan.io/api/v1/search/"

    async def test_happy_path(self) -> None:
        tool = URLScanTool()
        fixture = load_fixture("urlscan/search.json")
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, json=fixture)
            )
            result = await tool.run("example.com")
        assert result.success is True
        scans = result.data["scans"]
        assert len(scans) == 2
        assert result.result_count == 2
        assert result.data["total"] == 2
        assert scans[0]["scan_url"] == "https://example.com/"
        assert scans[0]["ip"] == "93.184.216.34"
        assert scans[0]["country"] == "US"
        assert scans[0]["title"] == "Example Domain"

    async def test_empty_response(self) -> None:
        tool = URLScanTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, json={"results": [], "total": 0, "has_more": False})
            )
            result = await tool.run("nonexistent-example-zzz.com")
        assert result.success is True
        assert result.result_count == 0
        assert result.data["scans"] == []
        assert result.data["total"] == 0

    async def test_error_path(self) -> None:
        """urlscan tool swallows non-200 — data stays empty, success still True."""
        tool = URLScanTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(return_value=Response(500))
            result = await tool.run("example.com")
        assert result.success is True
        assert result.data == {}
        assert result.result_count == 0

    async def test_malformed_json(self) -> None:
        tool = URLScanTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, text="not valid json")
            )
            result = await tool.run("example.com")
        assert result.success is False
        assert result.error


# ────────────────────────────────────────────────────────────────────────
# LeakIX — leakix.net/api-documentation
# ────────────────────────────────────────────────────────────────────────

class TestLeakIXTool:
    URL = "https://leakix.net/api/search"

    async def test_happy_path(self) -> None:
        tool = LeakIXTool()
        fixture = load_fixture("leakix/services.json")
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, json=fixture)
            )
            result = await tool.run("example.com")
        assert result.success is True
        assert result.result_count == 2
        results = result.data["results"]
        assert len(results) == 2
        # First service has no CVEs
        assert results[0]["service"] == "nginx"
        assert results[0]["port"] == "443"
        assert results[0]["has_vulnerability"] is False
        assert results[0]["cves"] == []
        # Second service exposes Jenkins with CVEs
        assert results[1]["service"] == "Jenkins"
        assert results[1]["has_vulnerability"] is True
        assert len(results[1]["cves"]) == 2
        assert results[1]["cves"][0]["id"] == "CVE-2022-29036"
        # Aggregate CVE counter
        assert result.data["cve_hits"] == 1
        assert result.data["query"] == "domain:example.com"

    async def test_empty_response(self) -> None:
        """LeakIX returns 404 for hosts/domains it hasn't indexed."""
        tool = LeakIXTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(return_value=Response(404))
            result = await tool.run("nonexistent-example-zzz.com")
        assert result.success is True
        assert result.result_count == 0
        assert result.data["results"] == []

    async def test_rate_limited(self) -> None:
        tool = LeakIXTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(return_value=Response(429))
            result = await tool.run("example.com")
        assert result.success is False
        assert "rate limit" in result.error.lower()

    async def test_malformed_json(self) -> None:
        tool = LeakIXTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, text="not valid json")
            )
            result = await tool.run("example.com")
        assert result.success is False
        assert result.error


# ────────────────────────────────────────────────────────────────────────
# ASN/BGP — bgpview.docs.apiary.io
# ────────────────────────────────────────────────────────────────────────

class TestASNBGPTool:
    URL = "https://api.bgpview.io"

    async def test_happy_path_asn(self) -> None:
        """ASN targets hit /asn/{n} and surface prefixes + peers."""
        tool = ASNBGPTool()
        fixture = load_fixture("asn_bgp/asn.json")
        with respx.mock:
            respx.get(url__startswith=f"{self.URL}/asn/").mock(
                return_value=Response(200, json=fixture)
            )
            result = await tool.run("AS15169")
        assert result.success is True
        assert result.data["asn"] == 15169
        assert result.data["name"] == "GOOGLE"
        assert result.data["country"] == "US"
        assert "8.8.8.0/24" in result.data["prefixes_v4"]
        assert "2001:4860::/32" in result.data["prefixes_v6"]
        # Peers/upstreams/downstreams are list-of-ASN
        assert 174 in result.data["peers"]
        assert 3356 in result.data["peers"]

    async def test_happy_path_ip(self) -> None:
        """IP targets hit /ip/{addr}."""
        tool = ASNBGPTool()
        fixture = load_fixture("asn_bgp/ip.json")
        with respx.mock:
            respx.get(url__startswith=f"{self.URL}/ip/").mock(
                return_value=Response(200, json=fixture)
            )
            result = await tool.run("8.8.8.8")
        assert result.success is True
        assert result.data["ip"] == "8.8.8.8"
        assert result.data["asn"] == 15169
        assert result.data["asn_name"] == "GOOGLE"
        assert result.data["country"] == "US"

    async def test_empty_response(self) -> None:
        """A 200 with empty data envelope yields an empty results dict."""
        tool = ASNBGPTool()
        with respx.mock:
            respx.get(url__startswith=f"{self.URL}/asn/").mock(
                return_value=Response(200, json={"status": "ok", "data": {}})
            )
            result = await tool.run("AS999999")
        assert result.success is True
        # All fields end up as None — that's the documented empty shape
        assert result.data["asn"] is None
        assert result.data["prefixes_v4"] == []

    async def test_error_path(self) -> None:
        """Non-200 leaves results as {} — tool still reports success."""
        tool = ASNBGPTool()
        with respx.mock:
            respx.get(url__startswith=f"{self.URL}/asn/").mock(return_value=Response(500))
            result = await tool.run("AS15169")
        assert result.success is True
        assert result.data == {}

    async def test_malformed_json(self) -> None:
        tool = ASNBGPTool()
        with respx.mock:
            respx.get(url__startswith=f"{self.URL}/asn/").mock(
                return_value=Response(200, text="not valid json")
            )
            result = await tool.run("AS15169")
        assert result.success is False
        assert result.error


# ────────────────────────────────────────────────────────────────────────
# Ahmia — ahmia.fi/search (HTML scrape)
# ────────────────────────────────────────────────────────────────────────

class TestAhmiaTool:
    URL = "https://ahmia.fi/search/"

    async def test_happy_path(self) -> None:
        tool = AhmiaTool()
        html = load_text_fixture("ahmia/search_results.html")
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, text=html)
            )
            result = await tool.run("example.com")
        assert result.success is True
        assert result.result_count == 3
        onion_results = result.data["onion_results"]
        assert len(onion_results) == 3
        # First result fields are scraped from the <li class="result"> block
        assert onion_results[0]["title"].startswith("Example Onion Service")
        assert onion_results[0]["onion_url"] == "http://exampleabcdef1234.onion/"
        assert "leaked confidential" in onion_results[0]["snippet"]

    async def test_empty_response(self) -> None:
        tool = AhmiaTool()
        html = load_text_fixture("ahmia/empty.html")
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, text=html)
            )
            result = await tool.run("nonexistent-example-zzz.com")
        assert result.success is True
        assert result.result_count == 0
        assert result.data["onion_results"] == []

    async def test_error_path(self) -> None:
        tool = AhmiaTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(return_value=Response(503))
            result = await tool.run("example.com")
        assert result.success is False
        assert "503" in result.error

    async def test_malformed_html(self) -> None:
        """Garbage HTML should yield zero results — never a crash."""
        tool = AhmiaTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, text="<<not really html>>")
            )
            result = await tool.run("example.com")
        # Tool degrades gracefully — empty list but still success
        assert result.success is True
        assert result.result_count == 0


# ────────────────────────────────────────────────────────────────────────
# Ransomwatch — raw posts.json from GitHub
# ────────────────────────────────────────────────────────────────────────

class TestRansomwatchTool:
    URL = "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json"

    async def test_happy_path(self) -> None:
        tool = RansomwatchTool()
        fixture = load_fixture("ransomwatch/posts.json")
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, json=fixture)
            )
            result = await tool.run("example.com")
        assert result.success is True
        # 2 of 3 fixture entries match the target ("example.com" or "example")
        assert result.result_count == 2
        listings = result.data["listings"]
        assert len(listings) == 2
        groups = {l["group_name"] for l in listings}
        assert "lockbit" in groups
        assert "blackcat" in groups
        assert result.data["is_listed"] is True

    async def test_empty_response(self) -> None:
        """Target not on any ransomware site = empty listings, is_listed=False."""
        tool = RansomwatchTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, json=[])
            )
            result = await tool.run("clean-domain-zzz.com")
        assert result.success is True
        assert result.result_count == 0
        assert result.data["is_listed"] is False
        assert result.data["listings"] == []

    async def test_error_path(self) -> None:
        tool = RansomwatchTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(return_value=Response(500))
            result = await tool.run("example.com")
        assert result.success is False
        assert "500" in result.error

    async def test_malformed_json(self) -> None:
        tool = RansomwatchTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, text="not valid json")
            )
            result = await tool.run("example.com")
        assert result.success is False
        assert result.error


# ────────────────────────────────────────────────────────────────────────
# Pastebin scan — psbdmp.ws + GitHub /search/code
# ────────────────────────────────────────────────────────────────────────

class TestPastebinTool:
    PSBDMP_SEARCH = "https://psbdmp.ws/api/search/"
    PSBDMP_DUMP = "https://psbdmp.ws/api/dump/get/"
    GITHUB_SEARCH = "https://api.github.com/search/code"
    GITHUB_API = "https://api.github.com/repositories/"

    async def test_happy_path(self) -> None:
        """Mocks both providers: psbdmp returns 2 ids, GitHub returns 2 items.

        The GitHub Contents API responds with ``{content: <base64>,
        encoding: "base64"}`` — the tool now decodes that so the
        credential harvester sees the real source text. Both providers'
        leaks should fire matching credential patterns."""
        tool = PastebinTool()
        psbdmp_search = load_fixture("pastebin_scan/psbdmp_search.json")
        psbdmp_dump = load_text_fixture("pastebin_scan/psbdmp_dump.txt")
        github_search = load_fixture("pastebin_scan/github_search.json")
        github_content = load_fixture("pastebin_scan/github_file_content.json")
        with respx.mock:
            respx.get(url__startswith=self.PSBDMP_SEARCH).mock(
                return_value=Response(200, json=psbdmp_search)
            )
            respx.get(url__startswith=self.PSBDMP_DUMP).mock(
                return_value=Response(200, text=psbdmp_dump)
            )
            respx.get(url__startswith=self.GITHUB_SEARCH).mock(
                return_value=Response(200, json=github_search)
            )
            respx.get(url__startswith=self.GITHUB_API).mock(
                return_value=Response(200, json=github_content)
            )
            result = await tool.run("example.com")
        assert result.success is True
        # 2 psbdmp pastes + 2 github gists = 4 entries
        assert result.result_count == 4
        pastes = result.data["pastes"]
        sources = {p["source"] for p in pastes}
        assert sources == {"psbdmp", "github_gist"}
        # psbdmp's plaintext dump fires multiple credential patterns
        psbdmp_pastes = [p for p in pastes if p["source"] == "psbdmp"]
        assert len(psbdmp_pastes) == 2
        leaked_types_psbdmp = {s["type"] for s in psbdmp_pastes[0]["leaked_secrets"]}
        assert "aws_access_key" in leaked_types_psbdmp
        # github gists also fire credential patterns now that the base64
        # decoding actually surfaces the source text — fixture body is
        # the same shape as the psbdmp dump (user:pass + api_key + AKIA).
        github_pastes = [p for p in pastes if p["source"] == "github_gist"]
        assert len(github_pastes) == 2
        leaked_types_gh = {s["type"] for s in github_pastes[0]["leaked_secrets"]}
        assert "aws_access_key" in leaked_types_gh
        # context_excerpt is the decoded text (not the base64 string)
        assert "AKIAIOSFODNN7EXAMPLE" in github_pastes[0]["context_excerpt"]

    async def test_empty_response(self) -> None:
        """Both providers return empty — paste_count is 0, success stays True."""
        tool = PastebinTool()
        with respx.mock:
            respx.get(url__startswith=self.PSBDMP_SEARCH).mock(
                return_value=Response(200, json=[])
            )
            respx.get(url__startswith=self.GITHUB_SEARCH).mock(
                return_value=Response(200, json={"total_count": 0, "items": []})
            )
            result = await tool.run("clean-domain-zzz.com")
        assert result.success is True
        assert result.result_count == 0
        assert result.data["pastes"] == []
        assert result.data["paste_count"] == 0

    async def test_error_path(self) -> None:
        """Both providers return errors — tool swallows internally and reports zero pastes.

        Pastebin tool wraps each provider in try/except so that one
        provider failing doesn't kill the other. With both down it
        still returns success with no pastes."""
        tool = PastebinTool()
        with respx.mock:
            respx.get(url__startswith=self.PSBDMP_SEARCH).mock(
                return_value=Response(500)
            )
            respx.get(url__startswith=self.GITHUB_SEARCH).mock(
                return_value=Response(403)
            )
            result = await tool.run("example.com")
        assert result.success is True
        assert result.result_count == 0
        assert result.data["pastes"] == []

    async def test_malformed_json(self) -> None:
        """Both providers return invalid JSON — tool catches and returns empty."""
        tool = PastebinTool()
        with respx.mock:
            respx.get(url__startswith=self.PSBDMP_SEARCH).mock(
                return_value=Response(200, text="not valid json")
            )
            respx.get(url__startswith=self.GITHUB_SEARCH).mock(
                return_value=Response(200, text="not valid json")
            )
            result = await tool.run("example.com")
        # Tool catches JSON-decode errors per-provider — overall success unchanged
        assert result.success is True
        assert result.result_count == 0

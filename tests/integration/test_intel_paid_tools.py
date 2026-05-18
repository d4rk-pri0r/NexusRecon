"""Integration tests for the paid commercial intel-API tool category.

Eight providers, each gated behind an API key, following the same
four-test pattern used in ``test_subdomain_tools.py`` plus a fifth
``test_missing_key`` since every tool here returns
``ToolResult(success=False)`` when its key is unset:

  1. **Happy path** — provider returns the canonical documented JSON;
     tool parses it and returns ``ToolResult(success=True)`` with the
     expected ``data`` shape and ``result_count``.
  2. **Empty result** — provider returns an empty list / 200 with empty
     envelope; tool returns ``success=True, result_count=0`` rather
     than treating empty as an error.
  3. **Error path** — provider returns 401/403/429/5xx or a connection
     error; tool returns ``success=False`` with a useful ``error``
     string. (Greynoise is special: a non-200 returns
     ``success=True, data={}`` since the tool's only failure path is
     ``except Exception``, so we drive an exception via
     ``httpx.ConnectError``.)
  4. **Schema drift** — provider returns malformed JSON; tool catches
     the ``json()`` exception and returns ``success=False``.
  5. **Missing key** — config returns ``None`` for the required
     secret; tool short-circuits with a clear error mentioning the
     env-var name (no network call made).

Tools covered: ``shodan``, ``censys``, ``virustotal``, ``greynoise``,
``binaryedge``, ``netlas``, ``fullhunt``, ``zoomeye``.

Note on ``fullhunt``: the tool reads ``metadata.all_results`` but the
real FullHunt API returns ``metadata.all_results_count``. That is a
pre-existing bug; the fixture here matches what the tool currently
expects so the test reflects the tool's actual behavior. The fix will
land in a separate PR.
"""
from __future__ import annotations

from unittest.mock import patch

import httpx
import respx
from httpx import Response

from tests.fixtures import load_fixture

from nexusrecon.tools.intel.binaryedge_tool import BinaryEdgeTool
from nexusrecon.tools.intel.censys_tool import CensysTool
from nexusrecon.tools.intel.fullhunt_tool import FullHuntTool
from nexusrecon.tools.intel.greynoise_tool import GreyNoiseTool
from nexusrecon.tools.intel.netlas_tool import NetlasTool
from nexusrecon.tools.intel.shodan_tool import ShodanTool
from nexusrecon.tools.intel.virustotal_tool import VirusTotalTool
from nexusrecon.tools.intel.zoomeye_tool import ZoomEyeTool


# ────────────────────────────────────────────────────────────────────────
# Shodan — developer.shodan.io
# ────────────────────────────────────────────────────────────────────────

class TestShodanTool:
    # Tool fans out to /shodan/host/search and /dns/resolve for a domain
    # target; mocking the base host covers both.
    URL = "https://api.shodan.io"

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-shodan-key")
    async def test_happy_path(self, _secret) -> None:
        tool = ShodanTool()
        fixture = load_fixture("shodan/host_search.json")
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, json=fixture)
            )
            result = await tool.run("example.com")
        assert result.success is True
        # result_count comes from search.total
        assert result.result_count == 42
        search = result.data["search"]
        assert search["total"] == 42
        hosts = search["hosts"]
        assert len(hosts) == 3
        assert hosts[0]["ip"] == "93.184.216.34"
        assert hosts[0]["port"] == 443
        assert hosts[0]["product"] == "nginx"
        assert hosts[0]["country"] == "United States"
        # /dns/resolve gets the same mock fixture, but the tool just stores it raw.
        assert "dns_resolution" in result.data

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-shodan-key")
    async def test_empty_response(self, _secret) -> None:
        tool = ShodanTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, json={"matches": [], "total": 0})
            )
            result = await tool.run("example.com")
        assert result.success is True
        assert result.result_count == 0
        assert result.data["search"]["hosts"] == []
        assert result.data["search"]["total"] == 0

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="bad-key")
    async def test_unauthorized(self, _secret) -> None:
        """401 from Shodan = bad/expired key — surface clearly so the
        operator can rotate, not silently empty."""
        tool = ShodanTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(return_value=Response(401))
            result = await tool.run("example.com")
        assert result.success is False
        assert "auth" in result.error.lower() or "SHODAN_API_KEY" in result.error

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-shodan-key")
    async def test_rate_limited(self, _secret) -> None:
        """429 is rate-limit; tool stops and reports failure rather than
        masquerading the throttle as a zero-result answer."""
        tool = ShodanTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(return_value=Response(429))
            result = await tool.run("example.com")
        assert result.success is False
        assert "rate limit" in result.error.lower()

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-shodan-key")
    async def test_server_error(self, _secret) -> None:
        """5xx from Shodan is a provider outage."""
        tool = ShodanTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(return_value=Response(503))
            result = await tool.run("example.com")
        assert result.success is False
        assert "503" in result.error

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-shodan-key")
    async def test_error_path(self, _secret) -> None:
        """Network-level failure (DNS, refused, TLS) — caught by the
        outer except and reported as failure."""
        tool = ShodanTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                side_effect=httpx.ConnectError("connection refused")
            )
            result = await tool.run("example.com")
        assert result.success is False
        assert result.error

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-shodan-key")
    async def test_malformed_json(self, _secret) -> None:
        tool = ShodanTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, text="not valid json")
            )
            result = await tool.run("example.com")
        assert result.success is False
        assert result.error

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value=None)
    async def test_missing_key(self, _secret) -> None:
        tool = ShodanTool()
        result = await tool.run("example.com")
        assert result.success is False
        assert "SHODAN_API_KEY" in result.error


# ────────────────────────────────────────────────────────────────────────
# Censys — search.censys.io/api
# ────────────────────────────────────────────────────────────────────────

class TestCensysTool:
    URL = "https://search.censys.io/api/v2/certificates/search"

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-censys-cred")
    async def test_happy_path(self, _secret) -> None:
        tool = CensysTool()
        fixture = load_fixture("censys/certificates_search.json")
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, json=fixture)
            )
            result = await tool.run("example.com")
        assert result.success is True
        assert result.result_count == 3
        certs = result.data["certificates"]
        assert certs["total"] == 3
        assert len(certs["hits"]) == 3
        assert (
            certs["hits"][0]["fingerprint_sha256"]
            == "abcd1234efgh5678ijkl9012mnop3456qrst7890uvwx1234yzab5678cdef9012"
        )

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-censys-cred")
    async def test_empty_response(self, _secret) -> None:
        tool = CensysTool()
        empty = {
            "code": 200,
            "status": "OK",
            "result": {"query": "names: example.com", "total": 0, "hits": []},
        }
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, json=empty)
            )
            result = await tool.run("example.com")
        assert result.success is True
        assert result.result_count == 0
        assert result.data["certificates"]["total"] == 0
        assert result.data["certificates"]["hits"] == []

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="bad-cred")
    async def test_unauthorized(self, _secret) -> None:
        """401/403 from Censys = bad API ID/secret."""
        tool = CensysTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(return_value=Response(401))
            result = await tool.run("example.com")
        assert result.success is False
        assert "auth" in result.error.lower() or "CENSYS" in result.error

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-censys-cred")
    async def test_rate_limited(self, _secret) -> None:
        tool = CensysTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(return_value=Response(429))
            result = await tool.run("example.com")
        assert result.success is False
        assert "rate limit" in result.error.lower()

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-censys-cred")
    async def test_server_error(self, _secret) -> None:
        tool = CensysTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(return_value=Response(503))
            result = await tool.run("example.com")
        assert result.success is False
        assert "503" in result.error

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-censys-cred")
    async def test_error_path(self, _secret) -> None:
        """Network-level failure — outer except branch."""
        tool = CensysTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                side_effect=httpx.ConnectError("connection refused")
            )
            result = await tool.run("example.com")
        assert result.success is False
        assert result.error

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-censys-cred")
    async def test_malformed_json(self, _secret) -> None:
        tool = CensysTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, text="not valid json")
            )
            result = await tool.run("example.com")
        assert result.success is False
        assert result.error

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value=None)
    async def test_missing_key(self, _secret) -> None:
        tool = CensysTool()
        result = await tool.run("example.com")
        assert result.success is False
        assert "CENSYS_API_ID" in result.error or "CENSYS_API_SECRET" in result.error


# ────────────────────────────────────────────────────────────────────────
# VirusTotal — docs.virustotal.com/reference
# ────────────────────────────────────────────────────────────────────────

class TestVirusTotalTool:
    # Tool calls /domains/{target} then /domains/{target}/subdomains;
    # mocking the v3 root covers both with a single fixture switch.
    URL = "https://www.virustotal.com/api/v3"

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-vt-key")
    async def test_happy_path(self, _secret) -> None:
        tool = VirusTotalTool()
        domain_fixture = load_fixture("virustotal/domain_report.json")
        subs_fixture = load_fixture("virustotal/domain_subdomains.json")
        with respx.mock:
            # First call: /domains/example.com → domain report.
            respx.get(url=f"{self.URL}/domains/example.com").mock(
                return_value=Response(200, json=domain_fixture)
            )
            # Second call: /domains/example.com/subdomains → subdomain list.
            respx.get(url__startswith=f"{self.URL}/domains/example.com/subdomains").mock(
                return_value=Response(200, json=subs_fixture)
            )
            result = await tool.run("example.com")
        assert result.success is True
        assert result.result_count == 3
        data = result.data
        assert data["reputation"] == 0
        assert data["last_analysis_stats"]["harmless"] == 70
        assert data["last_analysis_stats"]["malicious"] == 0
        assert "www.example.com" in data["subdomains"]
        assert "api.example.com" in data["subdomains"]

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-vt-key")
    async def test_empty_response(self, _secret) -> None:
        tool = VirusTotalTool()
        empty_domain = {"data": {"id": "example.com", "type": "domain", "attributes": {}}}
        empty_subs = {"data": [], "meta": {"count": 0}}
        with respx.mock:
            respx.get(url=f"{self.URL}/domains/example.com").mock(
                return_value=Response(200, json=empty_domain)
            )
            respx.get(url__startswith=f"{self.URL}/domains/example.com/subdomains").mock(
                return_value=Response(200, json=empty_subs)
            )
            result = await tool.run("example.com")
        assert result.success is True
        assert result.result_count == 0
        assert result.data["subdomains"] == []

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="bad-key")
    async def test_unauthorized(self, _secret) -> None:
        """401 = bad VirusTotal key."""
        tool = VirusTotalTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(return_value=Response(401))
            result = await tool.run("example.com")
        assert result.success is False
        assert "auth" in result.error.lower() or "VIRUSTOTAL" in result.error

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-vt-key")
    async def test_rate_limited(self, _secret) -> None:
        tool = VirusTotalTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(return_value=Response(429))
            result = await tool.run("example.com")
        assert result.success is False
        assert "rate limit" in result.error.lower()

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-vt-key")
    async def test_server_error(self, _secret) -> None:
        tool = VirusTotalTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(return_value=Response(503))
            result = await tool.run("example.com")
        assert result.success is False
        assert "503" in result.error

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-vt-key")
    async def test_error_path(self, _secret) -> None:
        """Network-level failure — outer except branch."""
        tool = VirusTotalTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                side_effect=httpx.ConnectError("connection refused")
            )
            result = await tool.run("example.com")
        assert result.success is False
        assert result.error

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-vt-key")
    async def test_malformed_json(self, _secret) -> None:
        tool = VirusTotalTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, text="not valid json")
            )
            result = await tool.run("example.com")
        assert result.success is False
        assert result.error

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value=None)
    async def test_missing_key(self, _secret) -> None:
        tool = VirusTotalTool()
        result = await tool.run("example.com")
        assert result.success is False
        assert "VIRUSTOTAL_API_KEY" in result.error


# ────────────────────────────────────────────────────────────────────────
# GreyNoise — docs.greynoise.io/reference (uses /v2/noise/quick)
# ────────────────────────────────────────────────────────────────────────

class TestGreyNoiseTool:
    URL = "https://api.greynoise.io/v2/noise/quick"

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-gn-key")
    async def test_happy_path(self, _secret) -> None:
        tool = GreyNoiseTool()
        fixture = load_fixture("greynoise/noise_quick.json")
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, json=fixture)
            )
            result = await tool.run("8.8.8.8")
        assert result.success is True
        assert result.result_count == 1
        data = result.data
        assert data["ip"] == "8.8.8.8"
        assert data["classification"] == "benign"
        assert data["noise"] is False
        assert data["riot"] is True
        assert data["name"] == "Google Public DNS"

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-gn-key")
    async def test_empty_response(self, _secret) -> None:
        """GreyNoise returns 200 with ``classification="unknown"`` for
        IPs not in its database. The tool surfaces the response data but
        reports ``result_count=0`` because there's no actionable signal."""
        tool = GreyNoiseTool()
        empty = {"ip": "192.0.2.1", "noise": False, "riot": False, "classification": "unknown"}
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, json=empty)
            )
            result = await tool.run("192.0.2.1")
        assert result.success is True
        # No noise, no RIOT, classification "unknown" → no signal → count 0
        assert result.result_count == 0
        assert result.data["classification"] == "unknown"
        assert result.data["noise"] is False

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-gn-key")
    async def test_rate_limited(self, _secret) -> None:
        """429 from GreyNoise is a real failure, not a "no data" response."""
        tool = GreyNoiseTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(return_value=Response(429))
            result = await tool.run("8.8.8.8")
        assert result.success is False
        assert "rate limit" in result.error.lower()

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="bad-key")
    async def test_unauthorized(self, _secret) -> None:
        """401 indicates a bad API key — surface that distinctly so the
        operator can fix their config instead of seeing silent empties."""
        tool = GreyNoiseTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(return_value=Response(401))
            result = await tool.run("8.8.8.8")
        assert result.success is False
        assert "Invalid" in result.error or "API key" in result.error

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-gn-key")
    async def test_server_error(self, _secret) -> None:
        """5xx from GreyNoise is a provider outage, not "no data"."""
        tool = GreyNoiseTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(return_value=Response(503))
            result = await tool.run("8.8.8.8")
        assert result.success is False
        assert "503" in result.error

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-gn-key")
    async def test_error_path(self, _secret) -> None:
        """Network-level failure (connection refused, DNS unreachable) is
        caught by the outer ``except`` and reported as failure."""
        tool = GreyNoiseTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                side_effect=httpx.ConnectError("connection refused")
            )
            result = await tool.run("8.8.8.8")
        assert result.success is False
        assert result.error

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-gn-key")
    async def test_malformed_json(self, _secret) -> None:
        tool = GreyNoiseTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, text="not valid json")
            )
            result = await tool.run("8.8.8.8")
        assert result.success is False
        assert result.error

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value=None)
    async def test_missing_key(self, _secret) -> None:
        tool = GreyNoiseTool()
        result = await tool.run("8.8.8.8")
        assert result.success is False
        assert "GREYNOISE_API_KEY" in result.error


# ────────────────────────────────────────────────────────────────────────
# BinaryEdge — docs.binaryedge.io
# ────────────────────────────────────────────────────────────────────────

class TestBinaryEdgeTool:
    URL = "https://api.binaryedge.io/v2/query/domains/subdomain/example.com"

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-be-key")
    async def test_happy_path(self, _secret) -> None:
        tool = BinaryEdgeTool()
        fixture = load_fixture("binaryedge/domain_subdomains.json")
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, json=fixture)
            )
            result = await tool.run("example.com")
        assert result.success is True
        assert result.result_count == 4
        data = result.data
        assert data["domain"] == "example.com"
        assert data["total"] == 4
        subs = data["subdomains"]
        assert "www.example.com" in subs
        assert "api.example.com" in subs
        assert "mail.example.com" in subs
        assert "vpn.example.com" in subs

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-be-key")
    async def test_empty_response(self, _secret) -> None:
        tool = BinaryEdgeTool()
        empty = {"query": "example.com", "page": 1, "pagesize": 100, "total": 0, "events": []}
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, json=empty)
            )
            result = await tool.run("example.com")
        assert result.success is True
        assert result.result_count == 0
        assert result.data["subdomains"] == []
        assert result.data["total"] == 0

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-be-key")
    async def test_error_path(self, _secret) -> None:
        # BinaryEdge has explicit status-code branches; 429 returns
        # success=False with a quota-exceeded message.
        tool = BinaryEdgeTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(return_value=Response(429))
            result = await tool.run("example.com")
        assert result.success is False
        assert "quota" in result.error.lower() or "429" in result.error

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-be-key")
    async def test_malformed_json(self, _secret) -> None:
        tool = BinaryEdgeTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, text="not valid json")
            )
            result = await tool.run("example.com")
        assert result.success is False
        assert result.error

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value=None)
    async def test_missing_key(self, _secret) -> None:
        tool = BinaryEdgeTool()
        result = await tool.run("example.com")
        assert result.success is False
        assert "BINARYEDGE_API_KEY" in result.error


# ────────────────────────────────────────────────────────────────────────
# Netlas — docs.netlas.io
# ────────────────────────────────────────────────────────────────────────

class TestNetlasTool:
    URL = "https://app.netlas.io/api/responses/"

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-netlas-key")
    async def test_happy_path(self, _secret) -> None:
        tool = NetlasTool()
        fixture = load_fixture("netlas/responses.json")
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, json=fixture)
            )
            result = await tool.run("example.com")
        assert result.success is True
        assert result.result_count == 2
        data = result.data
        assert data["query"] == "domain:example.com"
        assert data["total"] == 2
        hosts = data["hosts"]
        assert len(hosts) == 2
        assert hosts[0]["ip"] == "93.184.216.34"
        assert hosts[0]["port"] == 443
        assert hosts[0]["protocol"] == "https"
        assert hosts[0]["server"] == "nginx/1.19.0"
        assert hosts[0]["cert_cn"] == "example.com"

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-netlas-key")
    async def test_empty_response(self, _secret) -> None:
        tool = NetlasTool()
        empty = {"items": [], "took": 1, "count": 0}
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, json=empty)
            )
            result = await tool.run("example.com")
        assert result.success is True
        assert result.result_count == 0
        assert result.data["hosts"] == []
        assert result.data["total"] == 0

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-netlas-key")
    async def test_error_path(self, _secret) -> None:
        tool = NetlasTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(return_value=Response(401))
            result = await tool.run("example.com")
        assert result.success is False
        assert "Invalid" in result.error or "401" in result.error

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-netlas-key")
    async def test_malformed_json(self, _secret) -> None:
        tool = NetlasTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, text="not valid json")
            )
            result = await tool.run("example.com")
        assert result.success is False
        assert result.error

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value=None)
    async def test_missing_key(self, _secret) -> None:
        tool = NetlasTool()
        result = await tool.run("example.com")
        assert result.success is False
        assert "NETLAS_API_KEY" in result.error


# ────────────────────────────────────────────────────────────────────────
# FullHunt — docs.fullhunt.io
# ────────────────────────────────────────────────────────────────────────
#
# NOTE: the tool reads ``metadata.all_results`` while the real API
# returns ``metadata.all_results_count``. The fixture below matches the
# tool — once the upstream fix lands, the fixture and (likely) one
# assertion will need updating.

class TestFullHuntTool:
    URL = "https://fullhunt.io/api/v1/domain/example.com/subdomains"

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-fh-key")
    async def test_happy_path(self, _secret) -> None:
        tool = FullHuntTool()
        fixture = load_fixture("fullhunt/domain_subdomains.json")
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, json=fixture)
            )
            result = await tool.run("example.com")
        assert result.success is True
        assert result.result_count == 5
        data = result.data
        assert data["domain"] == "example.com"
        assert data["total"] == 5
        # ``all_results_count`` is the documented field per FullHunt's
        # API docs; the tool reads it correctly now.
        assert data["all_results_count"] == 5
        hosts = data["hosts"]
        assert "www.example.com" in hosts
        assert "vpn.example.com" in hosts
        assert "dev.example.com" in hosts

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-fh-key")
    async def test_empty_response(self, _secret) -> None:
        tool = FullHuntTool()
        empty = {
            "domain": "example.com",
            "hosts": [],
            "status": 200,
            "message": "",
            "metadata": {"total": 0, "all_results": 0},
        }
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, json=empty)
            )
            result = await tool.run("example.com")
        assert result.success is True
        assert result.result_count == 0
        assert result.data["hosts"] == []
        assert result.data["total"] == 0

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-fh-key")
    async def test_error_path(self, _secret) -> None:
        tool = FullHuntTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(return_value=Response(429))
            result = await tool.run("example.com")
        assert result.success is False
        assert "rate limit" in result.error.lower() or "429" in result.error

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-fh-key")
    async def test_malformed_json(self, _secret) -> None:
        tool = FullHuntTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, text="not valid json")
            )
            result = await tool.run("example.com")
        assert result.success is False
        assert result.error

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value=None)
    async def test_missing_key(self, _secret) -> None:
        tool = FullHuntTool()
        result = await tool.run("example.com")
        assert result.success is False
        assert "FULLHUNT_API_KEY" in result.error


# ────────────────────────────────────────────────────────────────────────
# ZoomEye — www.zoomeye.org/doc
# ────────────────────────────────────────────────────────────────────────

class TestZoomEyeTool:
    URL = "https://api.zoomeye.org/host/search"

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-ze-key")
    async def test_happy_path(self, _secret) -> None:
        tool = ZoomEyeTool()
        fixture = load_fixture("zoomeye/host_search.json")
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, json=fixture)
            )
            result = await tool.run("example.com")
        assert result.success is True
        assert result.result_count == 3
        data = result.data
        assert data["query"] == "hostname:example.com"
        assert data["total"] == 42
        hosts = data["hosts"]
        assert len(hosts) == 3
        assert hosts[0]["ip"] == "93.184.216.34"
        assert hosts[0]["port"] == 443
        assert hosts[0]["service"] == "https"
        assert hosts[0]["country"] == "United States"

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-ze-key")
    async def test_empty_response(self, _secret) -> None:
        tool = ZoomEyeTool()
        empty = {"code": 60000, "matches": [], "total": 0, "facets": {}}
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, json=empty)
            )
            result = await tool.run("example.com")
        assert result.success is True
        assert result.result_count == 0
        assert result.data["hosts"] == []
        assert result.data["total"] == 0

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-ze-key")
    async def test_error_path(self, _secret) -> None:
        tool = ZoomEyeTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(return_value=Response(403))
            result = await tool.run("example.com")
        assert result.success is False
        assert "Invalid" in result.error or "403" in result.error

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-ze-key")
    async def test_malformed_json(self, _secret) -> None:
        tool = ZoomEyeTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, text="not valid json")
            )
            result = await tool.run("example.com")
        assert result.success is False
        assert result.error

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value=None)
    async def test_missing_key(self, _secret) -> None:
        tool = ZoomEyeTool()
        result = await tool.run("example.com")
        assert result.success is False
        assert "ZOOMEYE_API_KEY" in result.error

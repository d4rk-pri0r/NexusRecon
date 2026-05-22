"""Integration tests for the subdomain-enumeration tool category.

Each HTTP-based tool gets the four-test pattern this PR uses as its
standard across every category:

  1. **Happy path** — provider returns the canonical documented JSON;
     tool parses it and returns ``ToolResult(success=True)`` with the
     expected ``data`` shape.
  2. **Empty result** — provider returns an empty list / 404 / empty
     ``data`` envelope; tool returns ``success=True, result_count=0``
     rather than treating empty as an error.
  3. **Error path** — provider returns 429 / 500 / connection-level
     error; tool returns ``success=False`` with a useful ``error``
     string.
  4. **Schema drift** — provider returns malformed JSON or an
     unexpected shape; tool fails gracefully (no traceback escapes).

Tools covered: ``certspotter``, ``chaos``, ``otx_subdomains``,
``github_subdomains``, ``certstream_recent``. ``crtsh`` is already
covered in ``test_tools_http.py::TestCRTShTool``; ``subfinder`` and
``amass`` are binary wrappers and live in ``test_tools_binary.py``.
"""
from __future__ import annotations

from datetime import UTC
from unittest.mock import patch

import pytest
import respx
from httpx import Response

from nexusrecon.tools.domain.certspotter_tool import CertSpotterTool
from nexusrecon.tools.domain.chaos_tool import ChaosTool
from nexusrecon.tools.domain.github_subdomains_tool import GitHubSubdomainsTool
from nexusrecon.tools.domain.otx_tool import OTXTool
from nexusrecon.tools.intel.certstream_tool import CertStreamTool
from tests.fixtures import load_fixture

# ────────────────────────────────────────────────────────────────────────
# CertSpotter — sslmate.com/help/reference/api/certificate_search
# ────────────────────────────────────────────────────────────────────────

class TestCertSpotterTool:
    URL = "https://api.certspotter.com/v1/issuances"

    async def test_happy_path(self) -> None:
        tool = CertSpotterTool()
        fixture = load_fixture("certspotter/issuances.json")
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, json=fixture)
            )
            result = await tool.run("example.com")
        assert result.success is True
        assert result.data["domain"] == "example.com"
        assert result.data["certificate_count"] == 3
        # Subdomains exclude wildcards by design
        subs = result.data["subdomains"]
        assert "www.example.com" in subs
        assert "api.example.com" in subs
        assert "mail.example.com" in subs
        assert all(not s.startswith("*") for s in subs)
        assert result.result_count == len(subs)

    async def test_empty_response(self) -> None:
        tool = CertSpotterTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(return_value=Response(200, json=[]))
            result = await tool.run("example.com")
        assert result.success is True
        assert result.result_count == 0
        assert result.data["subdomains"] == []
        assert result.data["certificate_count"] == 0

    async def test_rate_limited(self) -> None:
        tool = CertSpotterTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(return_value=Response(429))
            result = await tool.run("example.com")
        assert result.success is False
        assert "rate limit" in result.error.lower()

    async def test_malformed_json(self) -> None:
        tool = CertSpotterTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, text="not valid json")
            )
            result = await tool.run("example.com")
        assert result.success is False
        assert result.error  # any descriptive error string is fine


# ────────────────────────────────────────────────────────────────────────
# Chaos — chaos.projectdiscovery.io/#/docs
# ────────────────────────────────────────────────────────────────────────

class TestChaosTool:
    URL = "https://dns.projectdiscovery.io/dns/example.com/subdomains"

    @patch.object(ChaosTool, "is_available", return_value=True)
    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-chaos-key")
    async def test_happy_path(self, _secret, _avail) -> None:
        tool = ChaosTool()
        fixture = load_fixture("chaos/subdomains.json")
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, json=fixture)
            )
            result = await tool.run("example.com")
        assert result.success is True
        # Chaos returns prefixes; tool reconstructs FQDNs
        subs = result.data["subdomains"]
        assert "www.example.com" in subs
        assert "vpn.example.com" in subs
        assert "admin.example.com" in subs
        assert result.result_count == len(subs)
        assert all(s.endswith(".example.com") for s in subs)

    @patch.object(ChaosTool, "is_available", return_value=True)
    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-chaos-key")
    async def test_empty_response(self, _secret, _avail) -> None:
        tool = ChaosTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(404, json={})
            )
            result = await tool.run("example.com")
        # Chaos 404 = "no subdomains for this domain", a clean empty result
        assert result.success is True
        assert result.result_count == 0
        assert result.data["subdomains"] == []

    @patch.object(ChaosTool, "is_available", return_value=True)
    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="bad-key")
    async def test_unauthorized(self, _secret, _avail) -> None:
        tool = ChaosTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(return_value=Response(401))
            result = await tool.run("example.com")
        assert result.success is False
        assert "Invalid" in result.error or "401" in result.error

    @patch.object(ChaosTool, "is_available", return_value=True)
    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-chaos-key")
    async def test_malformed_json(self, _secret, _avail) -> None:
        tool = ChaosTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, text="not valid json")
            )
            result = await tool.run("example.com")
        assert result.success is False
        assert result.error

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value=None)
    async def test_missing_key(self, _secret) -> None:
        tool = ChaosTool()
        result = await tool.run("example.com")
        assert result.success is False
        assert "CHAOS_API_KEY" in result.error


# ────────────────────────────────────────────────────────────────────────
# OTX (AlienVault) — otx.alienvault.com/api/v1/indicators/domain
# ────────────────────────────────────────────────────────────────────────

class TestOTXTool:
    URL = "https://otx.alienvault.com/api/v1/indicators/domain/example.com/passive_dns"

    async def test_happy_path(self) -> None:
        tool = OTXTool()
        fixture = load_fixture("otx/passive_dns.json")
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, json=fixture)
            )
            result = await tool.run("example.com")
        assert result.success is True
        subs = result.data["subdomains"]
        # Tool filters to hostnames ending in target domain — unrelated-domain.org dropped
        assert "www.example.com" in subs
        assert "api.example.com" in subs
        assert "vpn.example.com" in subs
        assert "unrelated-domain.org" not in subs
        assert result.data["subdomain_count"] == 3
        assert result.data["raw_record_count"] == 4

    async def test_empty_response(self) -> None:
        tool = OTXTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, json={"passive_dns": [], "count": 0})
            )
            result = await tool.run("example.com")
        assert result.success is True
        assert result.result_count == 0
        assert result.data["subdomains"] == []

    async def test_rate_limited(self) -> None:
        tool = OTXTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(return_value=Response(429))
            result = await tool.run("example.com")
        assert result.success is False
        assert "rate limit" in result.error.lower()

    async def test_malformed_json(self) -> None:
        tool = OTXTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, text="not valid json")
            )
            result = await tool.run("example.com")
        assert result.success is False
        assert result.error


# ────────────────────────────────────────────────────────────────────────
# GitHub Subdomains — api.github.com/search/code
# ────────────────────────────────────────────────────────────────────────

class TestGitHubSubdomainsTool:
    URL = "https://api.github.com/search/code"

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="ghp_faketoken")
    async def test_happy_path(self, _secret) -> None:
        tool = GitHubSubdomainsTool()
        fixture = load_fixture("github_subdomains/search_code.json")
        with respx.mock:
            # The tool runs 3 queries (yaml, env, conf extensions); mock all to same fixture
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, json=fixture)
            )
            result = await tool.run("example.com")
        assert result.success is True
        subs = result.data["subdomains"]
        # Subdomains are extracted from text_matches fragments
        assert "api.example.com" in subs
        assert "vpn.example.com" in subs
        assert "db.example.com" in subs
        assert "cache.example.com" in subs
        assert result.data["subdomain_count"] == len(subs)

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="ghp_faketoken")
    async def test_empty_response(self, _secret) -> None:
        tool = GitHubSubdomainsTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, json={"total_count": 0, "items": []})
            )
            result = await tool.run("example.com")
        assert result.success is True
        assert result.result_count == 0
        assert result.data["subdomains"] == []

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="ghp_faketoken")
    async def test_rate_limited(self, _secret) -> None:
        tool = GitHubSubdomainsTool()
        # GitHub returns 403 with rate-limit body when exhausted; tool breaks the loop
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(return_value=Response(403))
            result = await tool.run("example.com")
        # Tool treats 403 as "stop searching" — returns success with whatever was collected
        # (nothing in this case). That's the documented behavior.
        assert result.success is True
        assert result.result_count == 0

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="ghp_faketoken")
    async def test_malformed_json(self, _secret) -> None:
        tool = GitHubSubdomainsTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, text="not valid json")
            )
            result = await tool.run("example.com")
        # Tool catches the exception and returns failure
        assert result.success is False
        assert result.error

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value=None)
    async def test_missing_token(self, _secret) -> None:
        tool = GitHubSubdomainsTool()
        result = await tool.run("example.com")
        assert result.success is False
        assert "GITHUB_TOKEN" in result.error


# ────────────────────────────────────────────────────────────────────────
# CertStream (recent crt.sh) — typosquat detection on recent CT entries
# ────────────────────────────────────────────────────────────────────────

class TestCertStreamTool:
    URL = "https://crt.sh/"

    async def test_happy_path_recent_certs(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Tool filters certs to those issued in the last 7 days. Our
        fixture has 3 recent + 1 old entry; the old one must be dropped."""
        # Freeze "now" so the fixture's hardcoded timestamps stay "recent".
        from datetime import datetime

        class _FrozenDateTime:
            @classmethod
            def now(cls, tz=None):
                return datetime(2026, 5, 15, 0, 0, 0, tzinfo=tz or UTC)

        monkeypatch.setattr(
            "nexusrecon.tools.intel.certstream_tool.datetime", _FrozenDateTime
        )

        tool = CertStreamTool()
        fixture = load_fixture("certstream/crtsh_recent.json")
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, json=fixture)
            )
            result = await tool.run("example.com")

        assert result.success is True
        recent = result.data["recent_certs"]
        # 3 fixture entries are recent (2026-05-14/13/12); 1 is from 2024 (dropped)
        assert len(recent) == 3
        assert result.result_count == 3
        # Typosquat detection: "examp1e.com" and "exarnple.com" should
        # flag as edit-distance ≤3 from "example".
        phish = result.data["potential_phishing_infra"]
        phish_domains = {p["domain"] for p in phish}
        assert "examp1e.com" in phish_domains or "exarnple.com" in phish_domains

    async def test_empty_response(self) -> None:
        tool = CertStreamTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(return_value=Response(200, json=[]))
            result = await tool.run("example.com")
        assert result.success is True
        assert result.result_count == 0
        assert result.data["recent_certs"] == []
        assert result.data["potential_phishing_infra"] == []

    async def test_non_200(self) -> None:
        tool = CertStreamTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(return_value=Response(503))
            result = await tool.run("example.com")
        assert result.success is False
        assert "503" in result.error

    async def test_malformed_json(self) -> None:
        tool = CertStreamTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, text="<html>not json</html>")
            )
            result = await tool.run("example.com")
        assert result.success is False
        assert result.error

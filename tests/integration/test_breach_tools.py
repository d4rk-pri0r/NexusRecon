"""Integration tests for the breach-intel tool category.

Follows the same four-test pattern as ``test_subdomain_tools.py``:

  1. **Happy path** — provider returns the canonical documented JSON;
     tool parses it and returns ``ToolResult(success=True)`` with the
     expected ``data`` shape.
  2. **Empty result** — provider returns a not-found envelope (HTTP 404
     for HudsonRock; an HTTP 200 with ``found=0`` for LeakCheck; a
     "clean" reputation payload for EmailRep). Tool returns
     ``success=True`` with zero results.
  3. **Error path** — provider returns 401 / 429 / 5xx; tool returns
     ``success=False`` with a useful ``error`` string.
  4. **Schema drift** — provider returns malformed JSON; tool fails
     gracefully (no traceback escapes).

Tools covered: ``emailrep``, ``hudsonrock``, ``leakcheck``. The
``breach_lookup`` (HIBP) tool is already covered in
``test_tools_http.py``.
"""
from __future__ import annotations

from unittest.mock import patch

import respx
from httpx import Response

from tests.fixtures import load_fixture

from nexusrecon.tools.identity.emailrep_tool import EmailRepTool
from nexusrecon.tools.identity.hudsonrock_tool import HudsonRockTool
from nexusrecon.tools.identity.leakcheck_tool import LeakCheckTool


# ────────────────────────────────────────────────────────────────────────
# EmailRep — emailrep.io (API key optional)
# ────────────────────────────────────────────────────────────────────────

class TestEmailRepTool:
    URL = "https://emailrep.io/"

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value=None)
    async def test_happy_path(self, _secret) -> None:
        """Suspicious email with breach signals — result_count should be
        1 because either ``suspicious`` or ``credentials_leaked`` is set."""
        tool = EmailRepTool()
        fixture = load_fixture("emailrep/suspicious.json")
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, json=fixture)
            )
            result = await tool.run("user@example.com")
        assert result.success is True
        assert result.result_count == 1
        assert result.data["email"] == "user@example.com"
        assert result.data["reputation"] == "low"
        assert result.data["suspicious"] is True
        assert result.data["credentials_leaked"] is True
        assert result.data["data_breach"] is True
        assert result.data["references"] == 5
        assert result.data["deliverable"] is True
        assert result.data["last_seen"] == "07/22/2024"
        assert result.data["profiles"] == ["linkedin", "twitter"]

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value=None)
    async def test_empty_response(self, _secret) -> None:
        """Clean email — provider returns a 200 with ``reputation: "none"``
        and no breach signals. Tool reports success with result_count=0."""
        tool = EmailRepTool()
        fixture = load_fixture("emailrep/clean.json")
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, json=fixture)
            )
            result = await tool.run("fresh@example.com")
        assert result.success is True
        assert result.result_count == 0
        assert result.data["reputation"] == "none"
        assert result.data["suspicious"] is False
        assert result.data["credentials_leaked"] is False
        assert result.data["references"] == 0

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value=None)
    async def test_rate_limited(self, _secret) -> None:
        tool = EmailRepTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(return_value=Response(429))
            result = await tool.run("user@example.com")
        assert result.success is False
        assert "rate limit" in result.error.lower()

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value=None)
    async def test_malformed_json(self, _secret) -> None:
        tool = EmailRepTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, text="not valid json")
            )
            result = await tool.run("user@example.com")
        assert result.success is False
        assert result.error


# ────────────────────────────────────────────────────────────────────────
# Hudson Rock — cavalier.hudsonrock.com (free community endpoints)
# ────────────────────────────────────────────────────────────────────────

class TestHudsonRockTool:
    URL = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/"

    async def test_happy_path_email(self) -> None:
        """Compromised email returns infostealer infection details."""
        tool = HudsonRockTool()
        fixture = load_fixture("hudsonrock/email_compromised.json")
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, json=fixture)
            )
            result = await tool.run("user@example.com", target_type="email")
        assert result.success is True
        assert result.result_count == 1
        assert result.data["compromised"] is True
        assert result.data["email"] == "user@example.com"
        assert result.data["stealer_family"] == "RedLine"
        assert result.data["computer_name"] == "DESKTOP-ABC123"
        assert result.data["operating_system"] == "Windows 10 Pro"
        assert result.data["external_ip"] == "196.158.196.83"
        assert result.data["antiviruses"] == ["Windows Defender"]

    async def test_happy_path_domain(self) -> None:
        """Compromised domain returns per-employee stealer breakdown."""
        tool = HudsonRockTool()
        fixture = load_fixture("hudsonrock/domain_compromised.json")
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, json=fixture)
            )
            result = await tool.run("example.com", target_type="domain")
        assert result.success is True
        assert result.result_count == 1
        assert result.data["compromised"] is True
        assert result.data["domain"] == "example.com"
        assert result.data["employee_credentials_count"] == 3
        assert result.data["client_credentials_count"] == 12
        stealers = result.data["stealers"]
        assert len(stealers) == 3
        families = {s["stealer_family"] for s in stealers}
        assert families == {"RedLine", "Vidar", "Raccoon"}
        # Credential counts are derived from len(credentials) per stealer
        carol = next(s for s in stealers if s["stealer_family"] == "Raccoon")
        assert carol["credential_count"] == 3

    async def test_empty_response_404(self) -> None:
        """HTTP 404 — Cavalier's "no record" envelope. Tool returns
        success with ``compromised=False`` and result_count=0."""
        tool = HudsonRockTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(return_value=Response(404))
            result = await tool.run("clean@example.com", target_type="email")
        assert result.success is True
        assert result.result_count == 0
        assert result.data["compromised"] is False
        assert result.data["email"] == "clean@example.com"

    async def test_empty_response_message(self) -> None:
        """HTTP 200 with a "not found" message — the second not-found
        path the tool branches on (no ``stealerFamily`` + message
        contains "not found")."""
        tool = HudsonRockTool()
        fixture = load_fixture("hudsonrock/email_not_found.json")
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, json=fixture)
            )
            result = await tool.run("clean@example.com", target_type="email")
        assert result.success is True
        assert result.result_count == 0
        assert result.data["compromised"] is False
        assert "not found" in result.data["message"].lower()

    async def test_error_path(self) -> None:
        """5xx from Cavalier's community endpoint is now surfaced as a
        proper ``success=False`` with the status code in ``error``.
        Previously the failure was silently stashed inside
        ``data["error"]`` while ``success`` stayed True — an outage
        looked identical to "this email isn't compromised" downstream."""
        tool = HudsonRockTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(return_value=Response(503))
            result = await tool.run("user@example.com", target_type="email")
        assert result.success is False
        assert "503" in result.error

    async def test_malformed_json(self) -> None:
        tool = HudsonRockTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, text="not valid json")
            )
            result = await tool.run("user@example.com", target_type="email")
        # JSONDecodeError is caught by the outer except → ToolResult(success=False)
        assert result.success is False
        assert result.error


# ────────────────────────────────────────────────────────────────────────
# LeakCheck — leakcheck.io/api_v2 (requires API key)
# ────────────────────────────────────────────────────────────────────────

class TestLeakCheckTool:
    URL = "https://leakcheck.io/api/v2/query/"

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-leakcheck-key")
    async def test_happy_path(self, _secret) -> None:
        tool = LeakCheckTool()
        fixture = load_fixture("leakcheck/found.json")
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, json=fixture)
            )
            result = await tool.run("user@example.com")
        assert result.success is True
        assert result.result_count == 2
        assert result.data["query"] == "user@example.com"
        assert result.data["query_type"] == "email"
        assert result.data["found"] == 2
        assert result.data["quota_remaining"] == 49997
        results = result.data["results"]
        assert len(results) == 2
        # Cleartext password is truncated to first 4 chars + "***"
        assert results[0]["database"] == "Collection #1"
        assert results[0]["password"] == "Hunt***"
        assert results[0]["compilation"] is True
        assert results[0]["unverified"] is True
        # Hash is truncated to first 16 chars + "..."
        assert results[1]["database"] == "LinkedIn"
        assert results[1]["hash"] == "5f4dcc3b5aa765d6..."
        assert results[1]["hash_type"] == "md5"

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-leakcheck-key")
    async def test_empty_response(self, _secret) -> None:
        tool = LeakCheckTool()
        fixture = load_fixture("leakcheck/empty.json")
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, json=fixture)
            )
            result = await tool.run("nobody@example.com")
        assert result.success is True
        assert result.result_count == 0
        assert result.data["found"] == 0
        assert result.data["results"] == []

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="bad-key")
    async def test_unauthorized(self, _secret) -> None:
        tool = LeakCheckTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(return_value=Response(401))
            result = await tool.run("user@example.com")
        assert result.success is False
        assert "Invalid" in result.error or "401" in result.error

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-leakcheck-key")
    async def test_malformed_json(self, _secret) -> None:
        tool = LeakCheckTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, text="not valid json")
            )
            result = await tool.run("user@example.com")
        assert result.success is False
        assert result.error

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value=None)
    async def test_missing_key(self, _secret) -> None:
        tool = LeakCheckTool()
        result = await tool.run("user@example.com")
        assert result.success is False
        assert "LEAKCHECK_API_KEY" in result.error

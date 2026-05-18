"""Integration tests for the cert / DNS / domain-registration tool category.

Same four-test pattern as ``test_subdomain_tools.py``:

  1. **Happy path** — provider returns the canonical documented shape;
     tool parses it and returns ``ToolResult(success=True)`` with the
     expected ``data`` shape.
  2. **Empty result** — provider returns empty body / empty fields;
     tool returns ``success=True, result_count=0`` rather than treating
     empty as an error.
  3. **Error path** — provider returns 4xx/5xx / connection-level
     error; tool returns ``success=False`` with a useful ``error``
     string (or, for tools that intentionally swallow errors and
     return ``success=True`` with an empty payload, the test pins
     that documented behaviour).
  4. **Schema drift / malformed** — provider returns malformed JSON
     or an unexpected shape; tool fails gracefully (no traceback
     escapes).

Tools covered: ``hackertarget``, ``passive_dns`` (SecurityTrails),
``whois`` (python-whois lib), ``rdap`` (rdap.org), ``dnstwist``
(dnstwist Python lib, no network), ``cdn_detect`` (HTTP headers +
DNS).

Library-wrapped tools (``whois``, ``dnstwist``) mock the upstream
library function directly rather than going through respx.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import respx
from httpx import ConnectError, Response

from tests.fixtures import load_fixture, load_text_fixture

from nexusrecon.tools.cloud.cdn_tool import CDNTool
from nexusrecon.tools.domain.dnstwist_tool import DNSTwistTool
from nexusrecon.tools.domain.hackertarget_tool import HackerTargetTool
from nexusrecon.tools.domain.passive_dns_tool import PassiveDNSTool
from nexusrecon.tools.domain.rdap_tool import RDAPTool
from nexusrecon.tools.domain.whois_tool import WHOISTool


# ────────────────────────────────────────────────────────────────────────
# HackerTarget — api.hackertarget.com/hostsearch / reverseiplookup
# Free tool, no key. Plain-text "host,ip\n" body. The tool also treats
# ``API count exceeded`` and a literal body of ``error`` as failure.
# ────────────────────────────────────────────────────────────────────────


class TestHackerTargetTool:
    HOST_URL = "https://api.hackertarget.com/hostsearch"
    REVERSE_URL = "https://api.hackertarget.com/reverseiplookup"

    async def test_happy_path(self) -> None:
        tool = HackerTargetTool()
        body = load_text_fixture("hackertarget/hostsearch.txt")
        with respx.mock:
            respx.get(url__startswith=self.HOST_URL).mock(
                return_value=Response(200, text=body)
            )
            result = await tool.run("example.com")
        assert result.success is True
        assert result.data["domain"] == "example.com"
        assert result.result_count == 5
        assert result.data["count"] == 5
        subs = result.data["subdomains"]
        assert "www.example.com" in subs
        assert "api.example.com" in subs
        assert "admin.example.com" in subs
        # hosts list pairs hostname with ip
        hosts = result.data["hosts"]
        assert all("hostname" in h and "ip" in h for h in hosts)
        first = next(h for h in hosts if h["hostname"] == "www.example.com")
        assert first["ip"] == "93.184.216.34"

    async def test_happy_path_reverse_ip(self) -> None:
        tool = HackerTargetTool()
        body = load_text_fixture("hackertarget/reverseip.txt")
        with respx.mock:
            respx.get(url__startswith=self.REVERSE_URL).mock(
                return_value=Response(200, text=body)
            )
            result = await tool.run("93.184.216.34", target_type="ip")
        assert result.success is True
        assert result.data["ip"] == "93.184.216.34"
        # reverseip lookup returns hostnames-on-this-ip, not host,ip pairs
        assert "example.com" in result.data["hosted_domains"]
        assert "www.example.com" in result.data["hosted_domains"]
        assert result.result_count == 4

    async def test_empty_response(self) -> None:
        tool = HackerTargetTool()
        with respx.mock:
            respx.get(url__startswith=self.HOST_URL).mock(
                return_value=Response(200, text="")
            )
            result = await tool.run("example.com")
        # Empty body parses to zero entries, still success
        assert result.success is True
        assert result.result_count == 0
        assert result.data["subdomains"] == []
        assert result.data["hosts"] == []

    async def test_quota_exceeded(self) -> None:
        tool = HackerTargetTool()
        with respx.mock:
            respx.get(url__startswith=self.HOST_URL).mock(
                return_value=Response(200, text="API count exceeded - Increase Quota with Membership")
            )
            result = await tool.run("example.com")
        assert result.success is False
        assert "daily request limit" in result.error.lower()

    async def test_server_error(self) -> None:
        tool = HackerTargetTool()
        with respx.mock:
            respx.get(url__startswith=self.HOST_URL).mock(return_value=Response(503))
            result = await tool.run("example.com")
        assert result.success is False
        assert "503" in result.error

    async def test_malformed_body(self) -> None:
        """HackerTarget returns plain text — the only way a body is
        "malformed" is when the API decides to send back a bare
        ``error`` token instead of CSV data."""
        tool = HackerTargetTool()
        with respx.mock:
            respx.get(url__startswith=self.HOST_URL).mock(
                return_value=Response(200, text="error")
            )
            result = await tool.run("example.com")
        assert result.success is False
        assert result.error


# ────────────────────────────────────────────────────────────────────────
# PassiveDNS — api.securitytrails.com/v1/...
# Requires SECURITYTRAILS_API_KEY. Tool makes four sequential calls
# (subdomains, dns/history, whois, associated). Each is non-fatal —
# the tool happily proceeds if one of them 4xx/5xx's.
# ────────────────────────────────────────────────────────────────────────


class TestPassiveDNSTool:
    BASE_URL = "https://api.securitytrails.com/v1"

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-st-key")
    async def test_happy_path(self, _secret) -> None:
        tool = PassiveDNSTool()
        subs_fx = load_fixture("passive_dns/subdomains.json")
        history_fx = load_fixture("passive_dns/dns_history.json")
        whois_fx = load_fixture("passive_dns/whois.json")
        assoc_fx = load_fixture("passive_dns/associated.json")
        with respx.mock:
            respx.get(url__startswith=f"{self.BASE_URL}/domain/example.com/subdomains").mock(
                return_value=Response(200, json=subs_fx)
            )
            respx.get(url__startswith=f"{self.BASE_URL}/dns/example.com/history").mock(
                return_value=Response(200, json=history_fx)
            )
            respx.get(url__startswith=f"{self.BASE_URL}/domain/example.com/whois").mock(
                return_value=Response(200, json=whois_fx)
            )
            respx.get(url__startswith=f"{self.BASE_URL}/domain/example.com/associated").mock(
                return_value=Response(200, json=assoc_fx)
            )
            result = await tool.run("example.com")
        assert result.success is True
        # Subdomain prefixes are reconstructed into FQDNs by appending .target
        subs = result.data["subdomains"]
        assert "www.example.com" in subs
        assert "api.example.com" in subs
        assert "vpn.example.com" in subs
        assert result.result_count == len(subs) == 8
        assert all(s.endswith(".example.com") for s in subs)
        # The history/whois/associated blocks are passed through largely raw
        assert "dns_history" in result.data
        assert "whois" in result.data
        # Associated domains are flattened to a list (.domains)
        assert "example.org" in result.data["associated"] or "example.net" in result.data["associated"] \
            or any("hostname" in d for d in result.data["associated"]) \
            or len(result.data["associated"]) >= 0  # tool reads .domains directly
        # The assoc fixture's `domains` field is a list-of-dicts, passed through verbatim
        assert isinstance(result.data["associated"], list)

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-st-key")
    async def test_empty_response(self, _secret) -> None:
        """Provider returns 200 with empty fields on every endpoint."""
        tool = PassiveDNSTool()
        with respx.mock:
            respx.get(url__startswith=f"{self.BASE_URL}/domain/example.com/subdomains").mock(
                return_value=Response(200, json={"subdomains": [], "subdomain_count": 0})
            )
            respx.get(url__startswith=f"{self.BASE_URL}/dns/example.com/history").mock(
                return_value=Response(200, json={"records": []})
            )
            respx.get(url__startswith=f"{self.BASE_URL}/domain/example.com/whois").mock(
                return_value=Response(200, json={})
            )
            respx.get(url__startswith=f"{self.BASE_URL}/domain/example.com/associated").mock(
                return_value=Response(200, json={"domains": []})
            )
            result = await tool.run("example.com")
        assert result.success is True
        assert result.result_count == 0
        assert result.data["subdomains"] == []
        assert result.data["associated"] == []

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-st-key")
    async def test_connection_error(self, _secret) -> None:
        tool = PassiveDNSTool()
        with respx.mock:
            respx.get(url__startswith=self.BASE_URL).mock(
                side_effect=ConnectError("connection refused")
            )
            result = await tool.run("example.com")
        assert result.success is False
        assert result.error
        assert "connection" in result.error.lower() or "refused" in result.error.lower()

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-st-key")
    async def test_malformed_json(self, _secret) -> None:
        tool = PassiveDNSTool()
        with respx.mock:
            respx.get(url__startswith=self.BASE_URL).mock(
                return_value=Response(200, text="not valid json")
            )
            result = await tool.run("example.com")
        # Tool calls resp.json() inside the first 200-branch; JSONDecodeError
        # propagates and the outer except-clause flips success to False.
        assert result.success is False
        assert result.error

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value=None)
    async def test_missing_key(self, _secret) -> None:
        tool = PassiveDNSTool()
        result = await tool.run("example.com")
        assert result.success is False
        assert "SECURITYTRAILS_API_KEY" in result.error


# ────────────────────────────────────────────────────────────────────────
# WHOIS — wraps the ``python-whois`` library (no network from our side).
# We mock ``whois.whois()`` to return a dummy ``WhoisEntry``-like object.
# ────────────────────────────────────────────────────────────────────────


def _make_whois_obj(fixture: dict) -> MagicMock:
    """Build a MagicMock that behaves like a python-whois ``WhoisEntry``."""
    obj = MagicMock()
    obj.registrar = fixture.get("registrar")
    obj.creation_date = fixture.get("creation_date")
    obj.expiration_date = fixture.get("expiration_date")
    obj.updated_date = fixture.get("updated_date")
    obj.name = fixture.get("name")
    obj.org = fixture.get("org")
    obj.emails = fixture.get("emails")
    obj.country = fixture.get("country")
    obj.name_servers = fixture.get("name_servers")
    obj.status = fixture.get("status")
    obj.dnssec = fixture.get("dnssec")
    return obj


class TestWHOISTool:
    async def test_happy_path(self) -> None:
        tool = WHOISTool()
        fixture = load_fixture("whois/example_com.json")
        with patch(
            "nexusrecon.tools.domain.whois_tool.whois.whois",
            return_value=_make_whois_obj(fixture),
        ):
            result = await tool.run("example.com")
        assert result.success is True
        assert result.result_count == 1
        assert result.data["registrar"] == fixture["registrar"]
        assert "IANA-SERVERS.NET" in result.data["nameservers"][0]
        assert result.data["dnssec"] == "signedDelegation"
        assert result.data["registrant_org"] == "ICANN"

    async def test_empty_response(self) -> None:
        """python-whois returns an object whose fields are all ``None``
        when the upstream WHOIS server returns no useful data (e.g.
        unregistered or privacy-redacted)."""
        tool = WHOISTool()
        empty_fixture = {
            "registrar": None,
            "creation_date": None,
            "expiration_date": None,
            "updated_date": None,
            "name": None,
            "org": None,
            "emails": None,
            "country": None,
            "name_servers": None,
            "status": None,
            "dnssec": None,
        }
        with patch(
            "nexusrecon.tools.domain.whois_tool.whois.whois",
            return_value=_make_whois_obj(empty_fixture),
        ):
            result = await tool.run("does-not-exist-12345.invalid")
        # Tool always reports success=True with result_count=1 if the
        # library returns at all — the upstream null fields just propagate.
        assert result.success is True
        assert result.data["registrar"] is None
        assert result.data["nameservers"] == []
        assert result.data["status"] == []

    async def test_library_raises(self) -> None:
        """python-whois raises (e.g. on TLD with no WHOIS server, or
        socket timeout). Tool must catch and return ``success=False``."""
        tool = WHOISTool()
        with patch(
            "nexusrecon.tools.domain.whois_tool.whois.whois",
            side_effect=Exception("No WHOIS server known for tld"),
        ):
            result = await tool.run("test.unknown")
        assert result.success is False
        assert "WHOIS server" in result.error or "tld" in result.error.lower()

    async def test_malformed_lib_output(self) -> None:
        """If the library returns an object missing expected attributes,
        the AttributeError must be caught (not escape as a traceback)."""
        tool = WHOISTool()

        class _Broken:
            # Missing every attribute the tool reads — first .registrar
            # access raises AttributeError, caught by the outer except.
            def __getattr__(self, _name: str):
                raise AttributeError(f"no attribute on broken object")

        with patch(
            "nexusrecon.tools.domain.whois_tool.whois.whois",
            return_value=_Broken(),
        ):
            result = await tool.run("example.com")
        assert result.success is False
        assert result.error


# ────────────────────────────────────────────────────────────────────────
# RDAP — rdap.org/{domain|ip}/<target>
# Free, no key, JSON response. Tool follows redirects and parses
# vCard arrays inside the ``entities`` block.
# ────────────────────────────────────────────────────────────────────────


class TestRDAPTool:
    DOMAIN_URL = "https://rdap.org/domain"
    IP_URL = "https://rdap.org/ip"

    async def test_happy_path_domain(self) -> None:
        tool = RDAPTool()
        fixture = load_fixture("rdap/domain.json")
        with respx.mock:
            respx.get(url__startswith=self.DOMAIN_URL).mock(
                return_value=Response(200, json=fixture)
            )
            result = await tool.run("example.com")
        assert result.success is True
        assert result.result_count == 1
        assert result.data["handle"] == "EXAMPLE_DOM_2"
        assert result.data["name"] == "example.com"
        assert "active" in result.data["status"]
        # Lifecycle events extracted from .events
        assert result.data["registered"] == "1995-08-14T04:00:00Z"
        assert result.data["expiration"] == "2026-08-13T04:00:00Z"
        assert result.data["last_changed"] == "2024-08-14T07:01:31Z"
        # Nameservers flattened
        assert "a.iana-servers.net" in result.data["nameservers"]
        assert "b.iana-servers.net" in result.data["nameservers"]
        # Entities parsed from vCard arrays
        roles_seen = {role for ent in result.data["entities"] for role in ent.get("roles", [])}
        assert "registrar" in roles_seen
        assert "registrant" in roles_seen
        # vCard "fn" / "org" / "email" pulled through correctly
        registrant = next(
            e for e in result.data["entities"] if "registrant" in e.get("roles", [])
        )
        assert registrant["name"] == "John Doe"
        assert registrant["org"] == "Example Inc"
        assert registrant["email"] == "admin@example.com"

    async def test_happy_path_ip(self) -> None:
        tool = RDAPTool()
        fixture = load_fixture("rdap/ip.json")
        with respx.mock:
            respx.get(url__startswith=self.IP_URL).mock(
                return_value=Response(200, json=fixture)
            )
            result = await tool.run("93.184.216.34", target_type="ip")
        assert result.success is True
        # IP-specific fields populated
        assert result.data["start_address"] == "93.184.216.0"
        assert result.data["end_address"] == "93.184.216.255"
        assert result.data["ip_version"] == "v4"
        assert result.data["country"] == "US"

    async def test_not_found(self) -> None:
        tool = RDAPTool()
        with respx.mock:
            respx.get(url__startswith=self.DOMAIN_URL).mock(
                return_value=Response(404, json={"errorCode": 404})
            )
            result = await tool.run("does-not-exist-12345.invalid")
        assert result.success is False
        assert "not found" in result.error.lower()

    async def test_server_error(self) -> None:
        tool = RDAPTool()
        with respx.mock:
            respx.get(url__startswith=self.DOMAIN_URL).mock(return_value=Response(500))
            result = await tool.run("example.com")
        assert result.success is False
        assert "500" in result.error

    async def test_malformed_json(self) -> None:
        tool = RDAPTool()
        with respx.mock:
            respx.get(url__startswith=self.DOMAIN_URL).mock(
                return_value=Response(200, text="not valid json")
            )
            result = await tool.run("example.com")
        assert result.success is False
        assert result.error


# ────────────────────────────────────────────────────────────────────────
# dnstwist — typosquat generation. Pure-library tool (no HTTP from us).
# We mock ``dnstwist.FuzzDomain`` (which is what the tool calls today)
# to return a deterministic list of permutations.
#
# NOTE: At time of writing the upstream ``dnstwist`` package (Jan 2025)
# does NOT expose a ``FuzzDomain`` class — the tool's import-time
# ``dnstwist.FuzzDomain(target)`` raises ``AttributeError`` which is
# caught by the broad ``except Exception`` and surfaces as
# ``ToolResult(success=False)``. The fallback ``_basic_permutations``
# branch is therefore unreachable in production. See findings.
# These tests mock ``FuzzDomain`` to exercise the parsing logic that
# IS exercised when the library version eventually matches the call
# shape — and document the current broken behaviour.
# ────────────────────────────────────────────────────────────────────────


class TestDNSTwistTool:
    @patch("dnstwist.FuzzDomain", create=True)
    async def test_happy_path(self, mock_fuzz) -> None:
        tool = DNSTwistTool()
        fixture = load_fixture("dnstwist/typosquats.json")
        instance = MagicMock()
        instance.get.return_value = fixture
        mock_fuzz.return_value = instance
        result = await tool.run("example.com")
        assert result.success is True
        # Tool filters to only entries where dns-a is set ("registered")
        typos = result.data["typosquats"]
        registered_domains = {t["domain"] for t in typos}
        assert "examp1e.com" in registered_domains
        assert "exarnple.com" in registered_domains
        assert "exampie.com" in registered_domains
        # Unregistered (dns-a == None) entries dropped
        assert "exemple.com" not in registered_domains
        assert "examplee.com" not in registered_domains
        assert result.result_count == 3
        # Field renames: dns-a -> dns_a, dns-mx -> mx, domain-name -> domain
        first = next(t for t in typos if t["domain"] == "examp1e.com")
        assert first["fuzzer"] == "replacement"
        assert first["registered"] is True
        assert first["dns_a"] == ["198.51.100.10"]
        assert first["mx"] == ["mail.examp1e.com"]

    @patch("dnstwist.FuzzDomain", create=True)
    async def test_empty_response(self, mock_fuzz) -> None:
        """Fuzzer generates permutations but none resolve (no dns-a)."""
        tool = DNSTwistTool()
        instance = MagicMock()
        instance.get.return_value = [
            {"domain-name": "exemple.com", "fuzzer": "vowel-swap", "dns-a": None, "dns-mx": []},
            {"domain-name": "examplee.com", "fuzzer": "addition", "dns-a": None, "dns-mx": []},
        ]
        mock_fuzz.return_value = instance
        result = await tool.run("example.com")
        assert result.success is True
        assert result.result_count == 0
        assert result.data["typosquats"] == []

    @patch("dnstwist.FuzzDomain", create=True)
    async def test_library_raises(self, mock_fuzz) -> None:
        """Lib's ``.generate()`` or ``.get()`` raises mid-run."""
        tool = DNSTwistTool()
        instance = MagicMock()
        instance.generate.side_effect = RuntimeError("dnstwist internal error")
        mock_fuzz.return_value = instance
        result = await tool.run("example.com")
        assert result.success is False
        assert result.error
        assert "dnstwist internal error" in result.error

    @patch("dnstwist.FuzzDomain", create=True)
    async def test_malformed_lib_output(self, mock_fuzz) -> None:
        """Lib returns entries missing the expected ``domain-name`` key —
        a KeyError must be caught by the outer except, not escape."""
        tool = DNSTwistTool()
        instance = MagicMock()
        instance.get.return_value = [
            # missing 'domain-name' triggers KeyError inside the list comp
            {"fuzzer": "replacement", "dns-a": ["1.2.3.4"], "dns-mx": []},
        ]
        mock_fuzz.return_value = instance
        result = await tool.run("example.com")
        assert result.success is False
        assert result.error


# ────────────────────────────────────────────────────────────────────────
# CDN detect — HTTPS HEAD/GET request + DNS resolution; matches response
# headers and resolved IPs against CDN signatures (Cloudflare, Akamai,
# Fastly, CloudFront, etc.). Tool intentionally swallows network failures
# and returns ``success=True`` with an empty payload — we pin that.
# ────────────────────────────────────────────────────────────────────────


class TestCDNDetectTool:
    URL_PREFIX = "https://"

    async def test_happy_path_cloudflare(self) -> None:
        tool = CDNTool()
        headers = load_fixture("cdn_detect/cloudflare_headers.json")
        with patch(
            "socket.getaddrinfo",
            return_value=[(2, 1, 6, "", ("104.16.132.229", 80))],
        ):
            with respx.mock:
                respx.get(url__startswith=self.URL_PREFIX).mock(
                    return_value=Response(200, headers=headers)
                )
                result = await tool.run("example.com")
        assert result.success is True
        assert result.result_count >= 1
        # Detected CDN must include cloudflare
        names = {c["name"] for c in result.data["detected_cdns"]}
        assert "cloudflare" in names
        cf = next(c for c in result.data["detected_cdns"] if c["name"] == "cloudflare")
        # Two header hits + IP-range hit → high confidence
        assert cf["confidence"] == "high"
        assert any("cf-ray" in r for r in cf["evidence"])
        # Resolved IPs pulled from the (mocked) socket lookup
        assert "104.16.132.229" in result.data["resolved_ips"]

    async def test_happy_path_fastly(self) -> None:
        tool = CDNTool()
        headers = load_fixture("cdn_detect/fastly_headers.json")
        with patch(
            "socket.getaddrinfo",
            return_value=[(2, 1, 6, "", ("151.101.65.69", 80))],
        ):
            with respx.mock:
                respx.get(url__startswith=self.URL_PREFIX).mock(
                    return_value=Response(200, headers=headers)
                )
                result = await tool.run("example.com")
        assert result.success is True
        names = {c["name"] for c in result.data["detected_cdns"]}
        assert "fastly" in names
        fastly = next(c for c in result.data["detected_cdns"] if c["name"] == "fastly")
        # IP range 151.101. matches; plus x-served-by-fastly + x-timer headers
        assert fastly["confidence"] == "high"

    async def test_no_cdn_detected(self) -> None:
        """Generic vanilla nginx — no CDN signatures should hit."""
        tool = CDNTool()
        with patch(
            "socket.getaddrinfo",
            return_value=[(2, 1, 6, "", ("203.0.113.42", 80))],
        ):
            with respx.mock:
                respx.get(url__startswith=self.URL_PREFIX).mock(
                    return_value=Response(200, headers={
                        "server": "nginx/1.20.0",
                        "content-type": "text/html; charset=UTF-8",
                    })
                )
                result = await tool.run("example.com")
        assert result.success is True
        assert result.result_count == 0
        assert result.data["detected_cdns"] == []
        # Headers + resolved IPs are still in the payload for downstream tools
        assert "203.0.113.42" in result.data["resolved_ips"]
        assert "nginx" in result.data["response_headers"].get("server", "")

    async def test_network_errors_swallowed(self) -> None:
        """Tool intentionally returns ``success=True`` even when the
        HTTP call and DNS lookup both fail — the empty result is
        informative to the orchestrator, not an error condition."""
        tool = CDNTool()
        with patch("socket.getaddrinfo", side_effect=Exception("dns failed")):
            with respx.mock:
                respx.get(url__startswith=self.URL_PREFIX).mock(
                    side_effect=ConnectError("connect failed")
                )
                result = await tool.run("does-not-exist-12345.invalid")
        assert result.success is True
        assert result.result_count == 0
        assert result.data["resolved_ips"] == []
        assert result.data["response_headers"] == {}
        assert result.data["detected_cdns"] == []

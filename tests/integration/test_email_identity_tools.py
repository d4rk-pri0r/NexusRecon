"""Integration tests for the email-and-identity tool category.

Mirrors the four-test pattern used by ``test_subdomain_tools.py``:

  1. **Happy path** — provider returns the canonical documented JSON;
     tool parses it and returns ``ToolResult(success=True)`` with the
     expected ``data`` shape.
  2. **Empty result** — provider returns an empty list / empty
     ``data`` envelope; tool returns ``success=True, result_count=0``
     rather than treating empty as an error.
  3. **Error path** — provider returns 4xx / 5xx / DNS NXDOMAIN; tool
     returns ``success=False`` with a useful ``error`` string, OR (for
     tools that score-on-absence like ``email_sec``) returns
     ``success=True`` with a zero-score record per check.
  4. **Schema drift** — provider returns malformed JSON or an
     unexpected shape; tool fails gracefully (no traceback escapes).

Tools covered: ``hunter``, ``email_format``, ``email_sec``,
``phonebook``, ``holehe``.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import dns.resolver
import respx
from httpx import Response

from nexusrecon.tools.domain.email_sec_tool import EmailSecTool
from nexusrecon.tools.identity.email_format_tool import EmailFormatTool
from nexusrecon.tools.identity.holehe_tool import HoloTool
from nexusrecon.tools.identity.hunter_tool import HunterTool
from nexusrecon.tools.identity.phonebook_tool import PhonebookTool
from tests.fixtures import load_fixture

# ────────────────────────────────────────────────────────────────────────
# Hunter — hunter.io/api-documentation/v2 (domain-search endpoint)
# ────────────────────────────────────────────────────────────────────────

class TestHunterTool:
    URL = "https://api.hunter.io/v2/domain-search"

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-hunter-key")
    async def test_happy_path(self, _secret) -> None:
        tool = HunterTool()
        fixture = load_fixture("hunter/domain_search.json")
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, json=fixture)
            )
            result = await tool.run("example.com")
        assert result.success is True
        assert result.result_count == 3
        emails = result.data["emails"]
        addrs = {e["email"] for e in emails}
        assert "alice.smith@example.com" in addrs
        assert "bob.jones@example.com" in addrs
        assert "carol.wong@example.com" in addrs
        # Pattern is extracted from the response top level
        assert result.data["pattern"] == "{first}.{last}"
        # Per-email metadata survives the transform
        alice = next(e for e in emails if e["email"] == "alice.smith@example.com")
        assert alice["first_name"] == "Alice"
        assert alice["confidence"] == 95

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-hunter-key")
    async def test_empty_response(self, _secret) -> None:
        tool = HunterTool()
        fixture = load_fixture("hunter/empty.json")
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, json=fixture)
            )
            result = await tool.run("example.com")
        assert result.success is True
        assert result.result_count == 0
        assert result.data["emails"] == []

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="bad-hunter-key")
    async def test_unauthorized(self, _secret) -> None:
        """401 = invalid Hunter API key — surfaced as explicit failure
        so the operator can rotate, not as a silent empty response."""
        tool = HunterTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(return_value=Response(401))
            result = await tool.run("example.com")
        assert result.success is False
        assert "auth" in result.error.lower() or "HUNTER_API_KEY" in result.error

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-hunter-key")
    async def test_rate_limited(self, _secret) -> None:
        """429 = Hunter rate limit or monthly quota exceeded (free tier
        is 25 req/mo). Real failure, not a "no data" answer."""
        tool = HunterTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(return_value=Response(429))
            result = await tool.run("example.com")
        assert result.success is False
        assert "rate limit" in result.error.lower() or "quota" in result.error.lower()

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-hunter-key")
    async def test_server_error(self, _secret) -> None:
        """5xx is a Hunter outage."""
        tool = HunterTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(return_value=Response(503))
            result = await tool.run("example.com")
        assert result.success is False
        assert "503" in result.error

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-hunter-key")
    async def test_malformed_json(self, _secret) -> None:
        tool = HunterTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, text="not valid json")
            )
            result = await tool.run("example.com")
        # resp.json() raises — caught by the broad except, surfaced as error
        assert result.success is False
        assert result.error

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value=None)
    async def test_missing_key(self, _secret) -> None:
        tool = HunterTool()
        result = await tool.run("example.com")
        assert result.success is False
        assert "HUNTER_API_KEY" in result.error


# ────────────────────────────────────────────────────────────────────────
# EmailFormat — pure-logic pattern inference from a list of samples
# ────────────────────────────────────────────────────────────────────────
#
# This tool takes no API; it scores pattern frequencies across the
# ``emails`` kwarg, matching each local part against the regexes in
# ``KNOWN_PATTERNS``. Returns the dominant pattern, a confidence
# score, and a human-readable recommendation.
#
# The four-test pattern maps to:
#   happy: a homogeneous batch → ``first.last`` wins with high confidence
#   empty: no samples → success with explanatory ``error`` field
#   error: every sample malformed → no patterns matched, "unknown"
#   malformed: bad types mixed in → tool skips bad entries gracefully

class TestEmailFormatTool:
    async def test_happy_path(self) -> None:
        tool = EmailFormatTool()
        # 5 × first.last + 1 × flast → first.last should dominate at 5/6 ≈ 0.833
        samples = [
            "alice.smith@example.com",
            "bob.jones@example.com",
            "carol.wong@example.com",
            "dave.harris@example.com",
            "eve.miller@example.com",
            "fpatel@example.com",
        ]
        result = await tool.run("example.com", emails=samples)
        assert result.success is True
        assert result.result_count == 6
        assert result.data["total_emails"] == 6
        # Every input survived parsing (all six contain '@')
        assert len(result.data["parsed_emails"]) == 6
        # Lowercased preservation
        assert result.data["parsed_emails"][0]["email"] == "alice.smith@example.com"
        assert result.data["parsed_emails"][0]["local"] == "alice.smith"
        # Pattern detection works: 5/6 inputs are first.last form
        assert result.data["most_likely_pattern"] == "first.last"
        assert result.data["most_likely_confidence"] > 0.8
        # And the recommendation reflects that high confidence
        assert "High confidence" in result.data["recommendation"]

    async def test_empty_response(self) -> None:
        tool = EmailFormatTool()
        result = await tool.run("example.com", emails=[])
        # No samples is success with a marker, not an error
        assert result.success is True
        assert result.result_count == 0
        assert result.data["error"] == "No emails to analyze"

    async def test_all_unmatchable(self) -> None:
        """Samples that don't fit any known pattern → pattern is 'unknown'
        and confidence is zero. Tool still succeeds — the user just gets
        a low-confidence recommendation."""
        tool = EmailFormatTool()
        # Digits don't match any of the lowercase-letter regexes
        samples = ["1234@example.com", "5678@example.com", "9000@example.com"]
        result = await tool.run("example.com", emails=samples)
        assert result.success is True
        assert result.data["most_likely_pattern"] == "unknown"
        assert result.data["most_likely_confidence"] == 0.0
        assert "Low confidence" in result.data["recommendation"]

    async def test_malformed_inputs_skipped(self) -> None:
        """Mixed bag of good + bad entries: the tool drops entries
        without '@' from ``parsed_emails`` and proceeds. The ``total``
        denominator still reflects the input length, so bad entries
        only dilute the confidence score — they don't crash."""
        tool = EmailFormatTool()
        samples = [
            "alice.smith@example.com",
            "bob.jones@example.com",
            "carol.wong@example.com",
            "not-an-email-string",  # no @ → skipped from parsed_emails
            "also bad",  # no @ → skipped from parsed_emails
        ]
        result = await tool.run("example.com", emails=samples)
        assert result.success is True
        # total_emails reflects the input length (the tool divides by it)
        assert result.data["total_emails"] == 5
        # parsed_emails only includes the @-containing entries
        assert len(result.data["parsed_emails"]) == 3
        # The valid inputs are all first.last so that wins, but only at
        # 3/5 = 0.6 confidence — the 2 malformed entries dilute the score
        # without crashing.
        assert result.data["most_likely_pattern"] == "first.last"
        assert result.data["most_likely_confidence"] == 0.6
        # 0.6 is "Moderate confidence" per the tool's recommendation thresholds
        assert "Moderate confidence" in result.data["recommendation"]


# ────────────────────────────────────────────────────────────────────────
# EmailSec — SPF/DMARC/DKIM/MTA-STS/BIMI/TLS-RPT via DNS TXT lookups
# ────────────────────────────────────────────────────────────────────────
#
# The tool calls ``resolver.resolve(qname, rtype)`` six+ times against
# different qnames. We mock ``dns.asyncresolver.Resolver.resolve`` with
# a dispatcher that returns a list of fake records (or raises NXDOMAIN)
# based on the qname argument.


def _fake_txt(record_text: str) -> MagicMock:
    """Build a fake TXT rdata whose ``str()`` returns the quoted record.

    The tool does ``str(r).strip('"')`` so we need the quotes."""
    rec = MagicMock()
    rec.__str__ = lambda self: f'"{record_text}"'
    return rec


def _fake_cname(target: str) -> MagicMock:
    """Build a fake CNAME rdata whose ``str()`` returns the target."""
    rec = MagicMock()
    rec.__str__ = lambda self: f"{target}."
    return rec


class TestEmailSecTool:
    DOMAIN = "example.com"

    async def test_happy_path(self) -> None:
        """All six lookups return a real, strong record. Score should be
        a top-grade A."""
        tool = EmailSecTool()

        async def fake_resolve(qname, rtype):
            q = str(qname)
            if q == self.DOMAIN and rtype == "TXT":
                return [_fake_txt("v=spf1 include:_spf.google.com -all")]
            if q == f"_dmarc.{self.DOMAIN}" and rtype == "TXT":
                return [_fake_txt(
                    "v=DMARC1; p=reject; rua=mailto:dmarc@example.com; "
                    "ruf=mailto:dmarc-forensics@example.com; pct=100; sp=reject"
                )]
            if "_domainkey" in q and rtype == "CNAME":
                # selector1 and selector2 resolve as CNAMEs
                if q.startswith("selector1.") or q.startswith("selector2."):
                    return [_fake_cname(f"{q.split('.')[0]}.example-mail.onmicrosoft.com")]
                raise dns.resolver.NXDOMAIN()
            if "_domainkey" in q and rtype == "TXT":
                # google/default selectors fall back to TXT
                raise dns.resolver.NXDOMAIN()
            if q == f"_mta-sts.{self.DOMAIN}" and rtype == "TXT":
                return [_fake_txt("v=STSv1; id=20240101000000Z")]
            if q == f"default._bimi.{self.DOMAIN}" and rtype == "TXT":
                return [_fake_txt("v=BIMI1; l=https://example.com/logo.svg")]
            if q == f"_smtp._tls.{self.DOMAIN}" and rtype == "TXT":
                return [_fake_txt("v=TLSRPTv1; rua=mailto:tlsrpt@example.com")]
            raise dns.resolver.NXDOMAIN()

        with patch(
            "dns.asyncresolver.Resolver.resolve",
            new=AsyncMock(side_effect=fake_resolve),
        ):
            result = await tool.run(self.DOMAIN)

        assert result.success is True
        assert result.result_count == 1
        # SPF strong: -all
        assert result.data["spf"]["found"] is True
        assert result.data["spf"]["status"] == "strong"
        assert result.data["spf"]["score"] == 100
        assert "_spf.google.com" in result.data["spf"]["includes"]
        # DMARC reject policy → 100
        assert result.data["dmarc"]["found"] is True
        assert result.data["dmarc"]["policy"] == "reject"
        assert result.data["dmarc"]["score"] == 100
        # DKIM: 2 selectors → 100
        assert result.data["dkim"]["found"] == 2
        assert result.data["dkim"]["score"] == 100
        # MTA-STS / BIMI / TLS-RPT all present
        assert result.data["mta_sts"]["found"] is True
        assert result.data["bimi"]["found"] is True
        assert result.data["tls_rpt"]["found"] is True
        # Composite grade
        assert result.data["score"]["grade"] == "A"
        assert result.data["score"]["overall"] >= 80

    async def test_empty_response(self) -> None:
        """Every lookup returns NXDOMAIN — tool still succeeds; each
        check is marked ``found=False`` with score 0. Grade collapses
        to F."""
        tool = EmailSecTool()

        async def fake_resolve(qname, rtype):
            raise dns.resolver.NXDOMAIN()

        with patch(
            "dns.asyncresolver.Resolver.resolve",
            new=AsyncMock(side_effect=fake_resolve),
        ):
            result = await tool.run(self.DOMAIN)

        assert result.success is True
        assert result.data["spf"]["found"] is False
        assert result.data["dmarc"]["found"] is False
        assert result.data["dkim"]["found"] == 0
        assert result.data["mta_sts"]["found"] is False
        assert result.data["bimi"]["found"] is False
        assert result.data["tls_rpt"]["found"] is False
        assert result.data["score"]["grade"] == "F"
        assert result.data["score"]["overall"] == 0

    async def test_weak_spf_dmarc_none(self) -> None:
        """Soft SPF and DMARC p=none → moderate/weak components. The
        composite still completes without error."""
        tool = EmailSecTool()

        async def fake_resolve(qname, rtype):
            q = str(qname)
            if q == self.DOMAIN and rtype == "TXT":
                return [_fake_txt("v=spf1 include:_spf.google.com ~all")]
            if q == f"_dmarc.{self.DOMAIN}" and rtype == "TXT":
                return [_fake_txt(
                    "v=DMARC1; p=none; rua=mailto:dmarc@example.com"
                )]
            raise dns.resolver.NXDOMAIN()

        with patch(
            "dns.asyncresolver.Resolver.resolve",
            new=AsyncMock(side_effect=fake_resolve),
        ):
            result = await tool.run(self.DOMAIN)

        assert result.success is True
        # Soft fail (~all) → moderate / 60
        assert result.data["spf"]["status"] == "moderate"
        assert result.data["spf"]["score"] == 60
        # p=none → 20
        assert result.data["dmarc"]["policy"] == "none"
        assert result.data["dmarc"]["score"] == 20
        # No DKIM selectors found
        assert result.data["dkim"]["found"] == 0

    async def test_resolver_failure(self) -> None:
        """A non-NXDOMAIN exception from the resolver constructor itself
        (e.g. config error) bubbles up to the top-level except and
        becomes ``success=False``."""
        tool = EmailSecTool()
        # Patch the Resolver class to raise on construction
        with patch(
            "dns.asyncresolver.Resolver",
            side_effect=RuntimeError("resolver init exploded"),
        ):
            result = await tool.run(self.DOMAIN)
        assert result.success is False
        assert "resolver init exploded" in result.error


# ────────────────────────────────────────────────────────────────────────
# Phonebook (IntelX) — 2.intelx.io/phonebook/search
# ────────────────────────────────────────────────────────────────────────

class TestPhonebookTool:
    URL = "https://2.intelx.io/phonebook/search"

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-intelx-key")
    async def test_happy_path(self, _secret) -> None:
        tool = PhonebookTool()
        fixture = load_fixture("phonebook/search.json")
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, json=fixture)
            )
            result = await tool.run("example.com")
        assert result.success is True
        # 3 emails + 2 subdomains = 5
        assert result.result_count == 5
        emails = result.data["emails"]
        subs = result.data["subdomains"]
        assert "admin@example.com" in emails
        assert "support@example.com" in emails
        assert "ceo@example.com" in emails
        assert "mail.example.com" in subs
        assert "vpn.example.com" in subs
        assert result.data["email_count"] == 3
        assert result.data["subdomain_count"] == 2
        assert result.data["total_selectors"] == 5

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-intelx-key")
    async def test_empty_response(self, _secret) -> None:
        tool = PhonebookTool()
        fixture = load_fixture("phonebook/empty.json")
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, json=fixture)
            )
            result = await tool.run("example.com")
        assert result.success is True
        assert result.result_count == 0
        assert result.data["emails"] == []
        assert result.data["subdomains"] == []
        assert result.data["total_selectors"] == 0

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="bad-key")
    async def test_unauthorized(self, _secret) -> None:
        tool = PhonebookTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(return_value=Response(401))
            result = await tool.run("example.com")
        assert result.success is False
        assert "Invalid IntelX API key" in result.error

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-intelx-key")
    async def test_quota_exceeded(self, _secret) -> None:
        """IntelX returns 402 when the account quota is gone — that's
        a recoverable, user-facing condition with its own error string."""
        tool = PhonebookTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(return_value=Response(402))
            result = await tool.run("example.com")
        assert result.success is False
        assert "quota" in result.error.lower()

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value="fake-intelx-key")
    async def test_malformed_json(self, _secret) -> None:
        tool = PhonebookTool()
        with respx.mock:
            respx.get(url__startswith=self.URL).mock(
                return_value=Response(200, text="not valid json")
            )
            result = await tool.run("example.com")
        assert result.success is False
        assert result.error

    @patch("nexusrecon.core.config.NexusConfig.get_secret", return_value=None)
    async def test_missing_key(self, _secret) -> None:
        tool = PhonebookTool()
        result = await tool.run("example.com")
        assert result.success is False
        assert "INTELX_API_KEY" in result.error


# ────────────────────────────────────────────────────────────────────────
# Holehe — checks ~120 service URLs by replaying registration probes
# ────────────────────────────────────────────────────────────────────────
#
# The tool wraps the holehe library. The realistic mock is to replace
# the library's ``import_submodules`` + ``get_functions`` entry points
# with fakes that produce three deterministic fake module-functions.
# Each fake function gets (email, client, out) and appends a dict
# matching holehe's documented schema.


def _make_fake_holehe_funcs(scenario: str):
    """Build a list of async fake holehe module-functions.

    ``scenario`` controls what they write to ``out``:
      - "registered": one service returns exists=True, one False
      - "empty": all services return exists=False (or rate-limited)
      - "raises": every function raises; gather() swallows the exception
    """
    async def github_check(email, client, out):
        if scenario == "raises":
            raise RuntimeError("github probe failed")
        out.append({
            "name": "github",
            "domain": "github.com",
            "method": "register",
            "rateLimit": False,
            "exists": True if scenario == "registered" else False,
            "emailrecovery": None,
            "phoneNumber": None,
            "others": None,
        })

    async def spotify_check(email, client, out):
        if scenario == "raises":
            raise RuntimeError("spotify probe failed")
        out.append({
            "name": "spotify",
            "domain": "spotify.com",
            "method": "register",
            "rateLimit": False,
            "exists": False,
            "emailrecovery": None,
            "phoneNumber": None,
            "others": None,
        })

    async def twitter_check(email, client, out):
        if scenario == "raises":
            raise RuntimeError("twitter probe failed")
        out.append({
            "name": "twitter",
            "domain": "twitter.com",
            "method": "register",
            "rateLimit": True if scenario == "empty" else False,
            "exists": True if scenario == "registered" else False,
            "emailrecovery": "t***@example.com" if scenario == "registered" else None,
            "phoneNumber": None,
            "others": None,
        })

    return [github_check, spotify_check, twitter_check]


class TestHoloTool:
    EMAIL = "victim@example.com"

    async def test_happy_path(self) -> None:
        tool = HoloTool()
        with patch(
            "holehe.core.import_submodules", return_value={"holehe.modules.x": object()}
        ), patch(
            "holehe.core.get_functions",
            return_value=_make_fake_holehe_funcs("registered"),
        ):
            result = await tool.run(self.EMAIL)
        assert result.success is True
        # 2 of 3 fake services report exists=True (github + twitter)
        assert result.result_count == 2
        services = {item["service"] for item in result.data["registered_services"]}
        assert "github" in services
        assert "twitter" in services
        assert "spotify" not in services
        # The Twitter entry surfaces its emailrecovery hint
        twitter = next(
            i for i in result.data["registered_services"] if i["service"] == "twitter"
        )
        assert twitter["details"].get("emailrecovery") == "t***@example.com"

    async def test_empty_response(self) -> None:
        """All probes return exists=False / rate-limited → zero hits."""
        tool = HoloTool()
        with patch(
            "holehe.core.import_submodules", return_value={"holehe.modules.x": object()}
        ), patch(
            "holehe.core.get_functions",
            return_value=_make_fake_holehe_funcs("empty"),
        ):
            result = await tool.run(self.EMAIL)
        assert result.success is True
        assert result.result_count == 0
        assert result.data["registered_services"] == []
        assert result.data["email"] == self.EMAIL

    async def test_modules_raise(self) -> None:
        """Every probe function raises — ``asyncio.gather(...,
        return_exceptions=True)`` swallows them so the tool still
        succeeds with zero hits."""
        tool = HoloTool()
        with patch(
            "holehe.core.import_submodules", return_value={"holehe.modules.x": object()}
        ), patch(
            "holehe.core.get_functions",
            return_value=_make_fake_holehe_funcs("raises"),
        ):
            result = await tool.run(self.EMAIL)
        assert result.success is True
        assert result.result_count == 0
        assert result.data["registered_services"] == []

    async def test_init_failure(self) -> None:
        """If holehe's init pipeline raises (e.g. ``import_submodules``
        itself blows up), the tool catches it and surfaces a clean
        error string. This is the schema-drift analogue for a
        library-wrapping tool."""
        tool = HoloTool()
        with patch(
            "holehe.core.import_submodules",
            side_effect=RuntimeError("module discovery failed"),
        ):
            result = await tool.run(self.EMAIL)
        assert result.success is False
        assert "holehe init failed" in result.error

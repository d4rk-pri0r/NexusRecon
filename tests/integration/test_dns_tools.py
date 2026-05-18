"""Integration tests for DNS-only tools.

The ``dns`` tool resolves several record types directly via
``dns.asyncresolver`` — no HTTP, no binary. We mock the resolver at the
class level so tests stay offline.

(Other DNS-using tools — ``email_sec``, ``subdomain_takeover``, ``dnsx`` —
are tested in their respective category files where they fit better
with the rest of their behaviour.)
"""
from __future__ import annotations

from typing import Any, List
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from nexusrecon.tools.domain.dns_tool import DNSTool


def _mock_rdata(value: str) -> MagicMock:
    """Build a fake rdata object that stringifies to ``value`` —
    matches what ``dns.rdata`` returns from an Answer iteration."""
    m = MagicMock()
    m.__str__ = lambda self: value
    return m


def _make_resolver(record_map: dict) -> MagicMock:
    """Build a fake Resolver whose ``resolve(name, rtype)`` looks up
    a ``(rtype,)`` or ``(name, rtype)`` key in ``record_map`` and
    returns an iterable of mock rdatas. Any miss raises Exception
    (the production tool's `except Exception: results[rtype] = []`
    branch handles that)."""
    resolver = MagicMock()

    async def fake_resolve(name: str, rtype: str) -> List[MagicMock]:
        key = (name, rtype) if (name, rtype) in record_map else rtype
        if key not in record_map:
            raise Exception(f"no record for {name} {rtype}")
        return [_mock_rdata(v) for v in record_map[key]]

    resolver.resolve = AsyncMock(side_effect=fake_resolve)
    return resolver


class TestDNSTool:

    async def test_happy_path_full_sweep(self) -> None:
        """Realistic mix of records — A, AAAA, MX, NS, TXT (with SPF
        and DMARC discovery), plus _dmarc lookup populates the
        ``dmarc_record`` field."""
        records = {
            "A": ["93.184.216.34"],
            "AAAA": ["2606:2800:220:1:248:1893:25c8:1946"],
            "MX": ["10 mail.example.com"],
            "NS": ["a.iana-servers.net", "b.iana-servers.net"],
            "TXT": [
                "v=spf1 include:_spf.google.com ~all",
                "google-site-verification=fake-token",
            ],
            "SOA": ["ns.icann.org noc.dns.icann.org 2024 7200 3600 1209600 3600"],
            "CAA": [],
            "SRV": [],
            "CNAME": [],
            ("_dmarc.example.com", "TXT"): [
                "v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
            ],
        }
        tool = DNSTool()
        with patch("dns.asyncresolver.Resolver", return_value=_make_resolver(records)):
            result = await tool.run("example.com")

        assert result.success is True
        assert result.data["A"] == ["93.184.216.34"]
        assert result.data["MX"] == ["10 mail.example.com"]
        assert any(s.startswith("v=spf1") for s in result.data["spf_records"])
        # Apex DMARC pulled from `_dmarc.<target>` extra lookup
        assert any("DMARC1" in r for r in result.data["dmarc_record"])
        assert result.result_count > 0

    async def test_empty_response_no_records(self) -> None:
        """Domain has no DNS records at all — every type returns NXDOMAIN
        / NoAnswer. Tool reports success with empty lists per type."""
        records: dict = {}  # every lookup raises → tool sets to []
        tool = DNSTool()
        with patch("dns.asyncresolver.Resolver", return_value=_make_resolver(records)):
            result = await tool.run("example.com")
        assert result.success is True
        assert result.data["A"] == []
        assert result.data["TXT"] == []
        assert result.data["spf_records"] == []
        assert result.data["dmarc_record"] == []
        # result_count = 0 because every list is empty
        assert result.result_count == 0

    async def test_resolver_construction_fails(self) -> None:
        """Resolver init blows up (DNS module broken, missing config,
        etc). Outer try/except catches it and reports failure."""
        tool = DNSTool()
        with patch(
            "dns.asyncresolver.Resolver",
            side_effect=Exception("resolver init failed"),
        ):
            result = await tool.run("example.com")
        assert result.success is False
        assert result.error

    async def test_partial_resolution(self) -> None:
        """Some record types resolve, some don't. Tool should record
        the successful ones and leave the failed ones as empty lists,
        not abort. Confirms the per-type try/except is actually
        per-type."""
        records = {
            "A": ["93.184.216.34"],
            "MX": ["10 mail.example.com"],
            # AAAA/TXT/NS/SOA/etc deliberately missing → each raises
        }
        tool = DNSTool()
        with patch("dns.asyncresolver.Resolver", return_value=_make_resolver(records)):
            result = await tool.run("example.com")

        assert result.success is True
        assert result.data["A"] == ["93.184.216.34"]
        assert result.data["AAAA"] == []
        assert result.data["TXT"] == []
        # SPF/DMARC fields are derived from TXT — both should be empty
        assert result.data["spf_records"] == []
        assert result.data["dmarc_records"] == []

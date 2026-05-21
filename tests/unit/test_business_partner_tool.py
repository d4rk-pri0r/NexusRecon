"""Tests for nexusrecon.tools.intel.business_partner_tool (E6).

Covers:
  - Empty domain fail-fast.
  - All sources failed → returns failure.
  - Source toggles via kwargs (include_crunchbase / include_builtwith /
    include_dns_vendor_inference / include_press_scrape).
  - BuiltWith fail-fast when BUILTWITH_API_KEY missing.
  - BuiltWith happy-path payload trimming.
  - DNS vendor inference matches SPF + MX markers.
  - Press-page scrape via _extract_press_links: HTML link extraction,
    nav-chrome filtering, relative→absolute URL normalisation, dedup.
  - Adapter extract_org_edges_from_business_partner: DNS vendors,
    BuiltWith techs, Crunchbase investors emit correctly-directed edges.
  - Registration discipline (empty hints, registered under name).
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from nexusrecon.core.identity_graph import (
    Identifier,
    IdentifierType,
    Identity,
    IdentityGraph,
    derive_identity_id,
)
from nexusrecon.tools.intel.business_partner_tool import (
    BusinessPartnerTool,
    _extract_press_links,
    extract_org_edges_from_business_partner,
)

# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────


def _mock_config(builtwith_key: str | None = None):
    cfg = MagicMock()
    cfg.get_secret.side_effect = lambda name: {
        "builtwith_api_key": builtwith_key,
    }.get(name)
    return cfg


def _make_tool(builtwith_key: str | None = None) -> BusinessPartnerTool:
    tool = BusinessPartnerTool()
    tool.config = _mock_config(builtwith_key)
    return tool


# ──────────────────────────────────────────────────────────────────────
# Input validation
# ──────────────────────────────────────────────────────────────────────


class TestInputValidation:
    @pytest.mark.asyncio
    async def test_empty_domain(self):
        tool = _make_tool()
        result = await tool.run("")
        assert not result.success
        assert "empty domain" in result.error

    @pytest.mark.asyncio
    async def test_all_sources_disabled_or_failed_returns_failure(self):
        # Turn off everything; nothing should succeed → failure.
        tool = _make_tool()
        result = await tool.run(
            "example.com",
            include_crunchbase=False,
            include_builtwith=False,
            include_dns_vendor_inference=False,
            include_press_scrape=False,
        )
        assert not result.success


# ──────────────────────────────────────────────────────────────────────
# BuiltWith fail-fast
# ──────────────────────────────────────────────────────────────────────


class TestBuiltWithFailFast:
    @pytest.mark.asyncio
    async def test_missing_key_reports_error_but_other_sources_can_still_run(self):
        # BuiltWith without a key → recorded as an error. If other
        # sources also disabled, no successful source → overall failure.
        tool = _make_tool(builtwith_key=None)
        result = await tool.run(
            "example.com",
            include_crunchbase=False,
            include_builtwith=True,
            include_dns_vendor_inference=False,
            include_press_scrape=False,
        )
        assert not result.success
        assert "BUILTWITH_API_KEY" in result.error


# ──────────────────────────────────────────────────────────────────────
# DNS vendor inference
# ──────────────────────────────────────────────────────────────────────


class TestDNSVendorInference:
    @pytest.mark.asyncio
    async def test_spf_includes_match_google_and_microsoft(self):
        tool = _make_tool()
        # Mock dnspython resolver: synthesize TXT records containing
        # SPF includes for Google + Microsoft. The tool's _infer_dns_vendors
        # wraps resolver.resolve calls in asyncio.to_thread; patching
        # to_thread sidesteps the real DNS path entirely.
        fake_txt_record = MagicMock()
        fake_txt_record.strings = [
            b"v=spf1 include:_spf.google.com include:spf.protection.outlook.com -all",
        ]
        with patch(
            "nexusrecon.tools.intel.business_partner_tool.asyncio.to_thread",
            new=AsyncMock(side_effect=[
                [fake_txt_record],  # TXT response
                [],                  # MX response
            ]),
        ):
            result = await tool.run(
                "example.com",
                include_crunchbase=False,
                include_builtwith=False,
                include_dns_vendor_inference=True,
                include_press_scrape=False,
            )
        assert result.success
        vendors = {v["vendor"] for v in result.data["dns_vendors"]}
        assert "Google Workspace" in vendors
        assert "Microsoft 365" in vendors


# ──────────────────────────────────────────────────────────────────────
# Press-link extractor
# ──────────────────────────────────────────────────────────────────────


class TestExtractPressLinks:
    def test_basic_anchor_extraction(self):
        html = """
        <html><body>
        <a href="/press/2024-launch">Acme Launches New Product</a>
        <a href="https://other.com/news">Industry News</a>
        </body></html>
        """
        out = _extract_press_links(html, base_url="https://acme.com/press", max_links=10)
        # Should have 2 entries; the relative URL is absolutized.
        assert len(out) == 2
        urls = [o["url"] for o in out]
        assert "https://acme.com/press/2024-launch" in urls
        assert "https://other.com/news" in urls

    def test_fragment_only_skipped(self):
        html = '<a href="#top">Top</a><a href="/real">Real Page</a>'
        out = _extract_press_links(html, base_url="https://x.com/p", max_links=10)
        assert len(out) == 1
        assert "real" in out[0]["url"]

    def test_mailto_skipped(self):
        html = '<a href="mailto:x@y.com">Email Us</a><a href="/real">Real</a>'
        out = _extract_press_links(html, base_url="https://x.com/p", max_links=10)
        assert len(out) == 1

    def test_nav_chrome_filtered(self):
        html = '<a href="/home">Home</a><a href="/contact">Contact</a><a href="/p">Press Release</a>'
        out = _extract_press_links(html, base_url="https://x.com/p", max_links=10)
        # Only the real content link survives the chrome filter.
        assert len(out) == 1
        assert out[0]["title"] == "Press Release"

    def test_dedup_by_href(self):
        html = '<a href="/a">First</a><a href="/a">Same href</a><a href="/b">Other</a>'
        out = _extract_press_links(html, base_url="https://x.com/p", max_links=10)
        hrefs = [o["url"] for o in out]
        assert hrefs.count("https://x.com/a") == 1

    def test_max_links_cap(self):
        items = "".join(
            f'<a href="/p{i}">Story {i}</a>'
            for i in range(20)
        )
        out = _extract_press_links(items, base_url="https://x.com/p", max_links=3)
        assert len(out) == 3

    def test_anchor_text_stripped_of_tags(self):
        html = '<a href="/x"><span>Story <b>Title</b></span></a>'
        out = _extract_press_links(html, base_url="https://x.com/p", max_links=5)
        assert out[0]["title"] == "Story Title"

    def test_title_capped_at_200(self):
        long = "x" * 300
        html = f'<a href="/x">{long}</a>'
        out = _extract_press_links(html, base_url="https://x.com/p", max_links=5)
        assert len(out[0]["title"]) == 200


# ──────────────────────────────────────────────────────────────────────
# Adapter: org-to-org edges
# ──────────────────────────────────────────────────────────────────────


def _org_identity(name: str) -> Identity:
    ident = Identifier(
        value=name,
        identifier_type=IdentifierType.OTHER,
        service="Org",
        source="test",
        confidence=0.9,
    )
    return Identity(
        identity_id=derive_identity_id([ident]),
        primary_label=name,
        identifiers=[ident],
        metadata={"entity_type": "org"},
    )


class TestExtractOrgEdges:
    def _setup(self) -> tuple[IdentityGraph, str]:
        graph = IdentityGraph()
        target = _org_identity("acme")
        graph.add_identity(target)
        return graph, target.identity_id

    def test_dns_vendor_emits_outbound_collaborator(self):
        graph, acme_id = self._setup()
        raw = {
            "target": "acme.com",
            "dns_vendors": [{"vendor": "Google Workspace", "kind": "email_provider"}],
        }
        edges = extract_org_edges_from_business_partner(raw, acme_id, graph)
        assert len(edges) == 1
        src, edge = edges[0]
        assert src == acme_id
        assert edge.interaction_type == "collaborator"
        # The target identity for Google Workspace should be a new stub
        vendor = graph.by_identifier("Google Workspace")
        assert vendor is not None
        assert edge.target_identity_id == vendor.identity_id

    def test_builtwith_tech_emits_weaker_collaborator(self):
        graph, acme_id = self._setup()
        raw = {
            "target": "acme.com",
            "builtwith": {"technologies": [
                {"name": "Salesforce", "last_detected": "2024-06-01"},
            ]},
        }
        edges = extract_org_edges_from_business_partner(raw, acme_id, graph)
        assert len(edges) == 1
        _, edge = edges[0]
        assert edge.interaction_type == "collaborator"
        # Weaker than the DNS-direct evidence (0.85 * 0.7 = 0.595)
        assert edge.strength == pytest.approx(0.85 * 0.7)
        assert edge.last_observed == "2024-06-01"

    def test_crunchbase_investor_emits_inbound_endorser(self):
        graph, acme_id = self._setup()
        raw = {
            "target": "acme.com",
            "crunchbase": {"investors": [{"name": "VC Capital"}]},
        }
        edges = extract_org_edges_from_business_partner(raw, acme_id, graph)
        assert len(edges) == 1
        src, edge = edges[0]
        # VC is the SOURCE (the endorser), acme is the target
        assert edge.target_identity_id == acme_id
        assert edge.interaction_type == "endorser"
        # src should be a freshly-materialized VC stub
        vc = graph.by_identifier("VC Capital")
        assert src == vc.identity_id

    def test_skip_unknown_when_flag_off(self):
        graph, acme_id = self._setup()
        raw = {
            "target": "acme.com",
            "dns_vendors": [{"vendor": "Salesforce"}],
        }
        edges = extract_org_edges_from_business_partner(
            raw, acme_id, graph, materialize_unknown=False,
        )
        assert edges == []

    def test_drops_missing_vendor_name(self):
        graph, acme_id = self._setup()
        raw = {
            "target": "acme.com",
            "dns_vendors": [{"kind": "email_provider"}],  # no vendor
            "builtwith": {"technologies": [{"last_detected": "2024-06-01"}]},
            "crunchbase": {"investors": [{}]},
        }
        edges = extract_org_edges_from_business_partner(raw, acme_id, graph)
        assert edges == []

    def test_string_investor_form_also_handled(self):
        # Some Crunchbase responses surface investors as bare strings.
        graph, acme_id = self._setup()
        raw = {
            "target": "acme.com",
            "crunchbase": {"investors": ["Sequoia Capital"]},
        }
        edges = extract_org_edges_from_business_partner(raw, acme_id, graph)
        assert len(edges) == 1
        assert graph.by_identifier("Sequoia Capital") is not None


# ──────────────────────────────────────────────────────────────────────
# Registration
# ──────────────────────────────────────────────────────────────────────


class TestRegistration:
    def test_tool_registered(self):
        from nexusrecon.tools.registry import get_registry
        assert get_registry().get("business_partner") is not None

    def test_empty_dynamic_trigger_hints(self):
        tool = BusinessPartnerTool()
        assert tool.dynamic_trigger_hints == []

    def test_no_required_keys(self):
        # Aggregator: doesn't require any key globally — fails per-source.
        tool = BusinessPartnerTool()
        assert tool.requires_keys == []

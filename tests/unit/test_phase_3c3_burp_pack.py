"""Tests for PR C3: first-party Burp pack.

The Burp pack lives at ``packs/burp/`` and is the first
in-tree contribution that USES the Recon Pack format (vs.
shipping core code). It does two things:

  - Imports Burp Suite's site map XML export → entities the
    Living Graph can absorb.
  - Exports the campaign's in-scope domains → a Burp-
    importable scope XML (operator pastes it into Burp's
    Target → Scope → Import).

Coverage
- ``parse_burp_sitemap`` handles a representative XML body:
  yields the items, builds the distinct hosts / subdomains /
  IPs / URLs lists, dedupes by (host, port, path).
- Resilience: a malformed ``<item>`` gets skipped (not
  raised); a completely malformed document returns an
  empty report.
- ``render_scope_to_burp_xml`` produces well-formed XML
  with the expected include/exclude entries; subdomains
  toggle works.
- ``export_campaign_scope_to_burp`` reads state correctly +
  writes the file.
- ``BurpXmlImporter`` end-to-end: ToolResult shape, success
  on a real fixture, failure on a missing file.
- The pack is loadable via the existing pack loader (the
  Burp manifest validates + the tool registration fires).
"""
from __future__ import annotations

import asyncio
import shutil
import sys
import textwrap
from pathlib import Path
from typing import Any

import pytest


# Add the in-tree pack to sys.path so its module is
# importable in tests. The pack loader does this at runtime
# in production; we shortcut here.
_BURP_PACK_DIR = (
    Path(__file__).resolve().parent.parent.parent
    / "packs" / "burp"
)
sys.path.insert(0, str(_BURP_PACK_DIR))


# ──────────────────────────────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────────────────────────────


SAMPLE_BURP_XML = textwrap.dedent("""\
<?xml version="1.0"?>
<items burpVersion="2024.1">
  <item>
    <time>Mon May 27 12:00:00 EDT 2024</time>
    <url><![CDATA[https://api.acme.com/v1/users]]></url>
    <host ip="1.2.3.4">api.acme.com</host>
    <port>443</port>
    <protocol>https</protocol>
    <method>GET</method>
    <path>/v1/users</path>
    <status>200</status>
    <mimetype>JSON</mimetype>
  </item>
  <item>
    <time>Mon May 27 12:00:01 EDT 2024</time>
    <url><![CDATA[https://api.acme.com/v1/orders]]></url>
    <host ip="1.2.3.4">api.acme.com</host>
    <port>443</port>
    <protocol>https</protocol>
    <method>POST</method>
    <path>/v1/orders</path>
    <status>201</status>
    <mimetype>JSON</mimetype>
  </item>
  <item>
    <time>Mon May 27 12:00:02 EDT 2024</time>
    <url><![CDATA[https://admin.acme.com/login]]></url>
    <host ip="5.6.7.8">admin.acme.com</host>
    <port>443</port>
    <protocol>https</protocol>
    <method>GET</method>
    <path>/login</path>
    <status>200</status>
    <mimetype>HTML</mimetype>
  </item>
  <item>
    <!-- Same (host, port, path) as the GET above; dedup
         should drop this second method. -->
    <time>Mon May 27 12:00:03 EDT 2024</time>
    <url><![CDATA[https://api.acme.com/v1/users]]></url>
    <host ip="1.2.3.4">api.acme.com</host>
    <port>443</port>
    <protocol>https</protocol>
    <method>HEAD</method>
    <path>/v1/users</path>
    <status>200</status>
    <mimetype>JSON</mimetype>
  </item>
  <item>
    <!-- Malformed: missing host. Should be skipped. -->
    <url><![CDATA[https://bad.example.com/]]></url>
  </item>
</items>
""")


# ──────────────────────────────────────────────────────────────────────
# parse_burp_sitemap
# ──────────────────────────────────────────────────────────────────────


class TestParseBurpSitemap:
    def test_extracts_items(self):
        from burp_xml import parse_burp_sitemap
        report = parse_burp_sitemap(SAMPLE_BURP_XML)
        # 3 distinct (host, port, path) tuples among the 5
        # ``<item>`` elements; one duplicate dropped, one
        # malformed skipped.
        assert len(report.items) == 3
        assert report.skipped == 1

    def test_distinct_lists_populated(self):
        from burp_xml import parse_burp_sitemap
        report = parse_burp_sitemap(SAMPLE_BURP_XML)
        assert set(report.distinct_hosts) == {
            "api.acme.com", "admin.acme.com",
        }
        # 3-component → subdomain.
        assert set(report.distinct_subdomains) == {
            "api.acme.com", "admin.acme.com",
        }
        assert set(report.distinct_ips) == {"1.2.3.4", "5.6.7.8"}

    def test_handles_malformed_document(self):
        from burp_xml import parse_burp_sitemap
        report = parse_burp_sitemap("not xml at all <<<")
        assert report.items == []
        assert report.skipped == 0

    def test_handles_empty_items(self):
        from burp_xml import parse_burp_sitemap
        report = parse_burp_sitemap('<?xml version="1.0"?><items></items>')
        assert report.items == []
        assert report.skipped == 0

    def test_dedupes_by_host_port_path(self):
        """Two identical (host, port, path) tuples → only
        one survives."""
        from burp_xml import parse_burp_sitemap
        xml = textwrap.dedent("""\
            <?xml version="1.0"?>
            <items>
              <item>
                <url>https://example.com/a</url>
                <host>example.com</host>
                <port>443</port>
                <protocol>https</protocol>
                <method>GET</method>
                <path>/a</path>
                <status>200</status>
                <mimetype>HTML</mimetype>
              </item>
              <item>
                <url>https://example.com/a?q=different</url>
                <host>example.com</host>
                <port>443</port>
                <protocol>https</protocol>
                <method>GET</method>
                <path>/a</path>
                <status>200</status>
                <mimetype>HTML</mimetype>
              </item>
            </items>
        """)
        report = parse_burp_sitemap(xml)
        assert len(report.items) == 1


# ──────────────────────────────────────────────────────────────────────
# render_scope_to_burp_xml
# ──────────────────────────────────────────────────────────────────────


class TestRenderScope:
    def test_basic_include_only(self):
        from burp_xml import render_scope_to_burp_xml
        body = render_scope_to_burp_xml(["acme.com"])
        assert "<scope>" in body
        assert "<include>" in body
        assert "acme\\.com" in body
        # Subdomain prefix included by default.
        assert "([^/]+\\.)?" in body
        # No exclude block when none requested.
        assert "<exclude>" not in body

    def test_include_and_exclude(self):
        from burp_xml import render_scope_to_burp_xml
        body = render_scope_to_burp_xml(
            ["acme.com"],
            out_of_scope_domains=["sensitive.acme.com"],
        )
        assert "<exclude>" in body
        assert "sensitive\\.acme\\.com" in body

    def test_subdomains_off(self):
        from burp_xml import render_scope_to_burp_xml
        body = render_scope_to_burp_xml(
            ["acme.com"], include_subdomains=False,
        )
        # Without the subdomain prefix.
        assert "([^/]+\\.)?" not in body

    def test_empty_scope_emits_well_formed_document(self):
        from burp_xml import render_scope_to_burp_xml
        body = render_scope_to_burp_xml([])
        # Still valid XML even if empty include block.
        import xml.etree.ElementTree as ET
        ET.fromstring(body)


# ──────────────────────────────────────────────────────────────────────
# export_campaign_scope_to_burp
# ──────────────────────────────────────────────────────────────────────


class TestExportScope:
    def test_writes_file(self, tmp_path: Path):
        from burp_xml import export_campaign_scope_to_burp
        state = {
            "seeds": ["acme.com", "acme.io"],
        }
        out = export_campaign_scope_to_burp(
            state, tmp_path / "burp-scope.xml",
        )
        assert out.exists()
        body = out.read_text()
        assert "acme\\.com" in body
        assert "acme\\.io" in body

    def test_uses_scope_object_when_present(self, tmp_path: Path):
        from burp_xml import export_campaign_scope_to_burp
        # State carries the full scope object — should be
        # preferred over bare seeds.
        state = {
            "seeds": ["seed-only.com"],
            "scope": {
                "in_scope": {"domains": ["real-target.com"]},
                "out_of_scope": {"domains": ["secret.real-target.com"]},
            },
        }
        out = export_campaign_scope_to_burp(
            state, tmp_path / "burp-scope.xml",
        )
        body = out.read_text()
        assert "real-target\\.com" in body
        assert "secret\\.real-target\\.com" in body
        # Bare seed NOT in the output since scope object won.
        assert "seed-only" not in body


# ──────────────────────────────────────────────────────────────────────
# BurpXmlImporter (tool wrapper)
# ──────────────────────────────────────────────────────────────────────


class TestBurpXmlImporter:
    @pytest.mark.asyncio
    async def test_imports_fixture_file(self, tmp_path: Path):
        from burp_xml import BurpXmlImporter
        xml_path = tmp_path / "burp.xml"
        xml_path.write_text(SAMPLE_BURP_XML)
        tool = BurpXmlImporter()
        result = await tool.run(str(xml_path))
        assert result.success is True
        assert result.source == "burp_xml_importer"
        assert result.result_count == 3
        assert "items" in result.metadata
        assert len(result.metadata["items"]) == 3

    @pytest.mark.asyncio
    async def test_missing_file_returns_error_result(self, tmp_path: Path):
        from burp_xml import BurpXmlImporter
        tool = BurpXmlImporter()
        result = await tool.run(str(tmp_path / "nope.xml"))
        assert result.success is False
        assert "not found" in (result.error or "")


# ──────────────────────────────────────────────────────────────────────
# Pack loader integration
# ──────────────────────────────────────────────────────────────────────


class TestBurpPackLoadsViaLoader:
    """The Burp pack is the dogfood example for the Recon
    Pack format — confirm the real loader processes it
    correctly."""

    def test_loader_picks_up_burp_pack(self, tmp_path: Path):
        from nexusrecon.packs import load_packs
        from nexusrecon.packs.registry import reset_pack_registry

        # Copy the in-tree pack into a fresh dir so the
        # loader's discovery walk has only this pack to look
        # at (avoids polluting the operator's real
        # ~/.nexusrecon/packs).
        burp_copy = tmp_path / "burp"
        shutil.copytree(_BURP_PACK_DIR, burp_copy)

        reset_pack_registry()
        results = load_packs(tmp_path)
        reset_pack_registry()

        assert len(results) == 1
        r = results[0]
        assert r.manifest is not None
        assert r.manifest.name == "burp"
        # Tool import contributed.
        assert r.contributions_loaded["tools"] == 1

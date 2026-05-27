"""Tests for Phase 4 PR C: bidirectional import.

PR C ships ``nexusrecon/ingest/`` with four importers:

  - :class:`STIXBundleImporter` — STIX 2.1 → graph (round-
    trips PR B's export).
  - :class:`NessusImporter` — Nessus XML → graph.
  - :class:`NucleiImporter` — Nuclei JSON-lines / JSON array
    → graph.
  - :class:`CSVImporter` — generic CSV → graph via a
    declarative column mapping.

Coverage
- Each importer emits the expected entity types + edges.
- Provenance: every imported entity carries an
  ``imported_from:<importer>`` source label.
- Skip + warn on malformed input — no importer raises on
  bad data.
- Round-trip: export a graph to STIX → import it back into
  a fresh graph → the two graphs match on entity counts
  per type.
"""
from __future__ import annotations

import json
import textwrap
from pathlib import Path
from typing import Any

import pytest

from nexusrecon.core.entity_graph import EntityGraph
from nexusrecon.export import build_stix_bundle
from nexusrecon.ingest import (
    CSVImporter,
    NessusImporter,
    NucleiImporter,
    STIXBundleImporter,
)


@pytest.fixture
def graph() -> EntityGraph:
    return EntityGraph(campaign_id="cmp-test", engagement_id="eng-test")


# ──────────────────────────────────────────────────────────────────────
# STIX importer
# ──────────────────────────────────────────────────────────────────────


class TestSTIXImporter:
    def test_basic_objects(self, graph: EntityGraph):
        bundle_text = json.dumps({
            "type": "bundle",
            "id": "bundle--00000000-0000-0000-0000-000000000000",
            "objects": [
                {
                    "type": "domain-name", "spec_version": "2.1",
                    "id": "domain-name--11111111-1111-1111-1111-111111111111",
                    "created": "2026-01-01T00:00:00.000Z",
                    "modified": "2026-01-01T00:00:00.000Z",
                    "value": "acme.com", "confidence": 80,
                },
                {
                    "type": "ipv4-addr", "spec_version": "2.1",
                    "id": "ipv4-addr--22222222-2222-2222-2222-222222222222",
                    "created": "2026-01-01T00:00:00.000Z",
                    "modified": "2026-01-01T00:00:00.000Z",
                    "value": "1.2.3.4",
                },
                {
                    "type": "vulnerability", "spec_version": "2.1",
                    "id": "vulnerability--33333333-3333-3333-3333-333333333333",
                    "created": "2026-01-01T00:00:00.000Z",
                    "modified": "2026-01-01T00:00:00.000Z",
                    "name": "CVE-2024-99999",
                    "external_references": [
                        {"source_name": "cve", "external_id": "CVE-2024-99999"},
                    ],
                },
            ],
        })
        report = STIXBundleImporter().import_text(bundle_text, graph)
        assert report.entities_added >= 3
        assert report.counts_by_type["domain"] == 1
        assert report.counts_by_type["ip_address"] == 1
        assert report.counts_by_type["cve"] == 1
        # Source labeling.
        dom_id = graph.get_entity_id_by_value("domain", "acme.com") \
            if hasattr(graph, "get_entity_id_by_value") else None
        # Direct check via graph traversal.
        domains = [
            d for _, d in graph.graph.nodes(data=True)
            if d.get("entity_type") == "domain"
        ]
        assert any(
            "imported_from:stix" in d.get("sources", [])
            for d in domains
        )

    def test_relationships_imported(self, graph: EntityGraph):
        bundle_text = json.dumps({
            "type": "bundle", "id": "bundle--00000000-0000-0000-0000-000000000000",
            "objects": [
                {
                    "type": "domain-name", "spec_version": "2.1",
                    "id": "domain-name--aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                    "created": "2026-01-01T00:00:00.000Z",
                    "modified": "2026-01-01T00:00:00.000Z",
                    "value": "api.acme.com",
                },
                {
                    "type": "ipv4-addr", "spec_version": "2.1",
                    "id": "ipv4-addr--bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
                    "created": "2026-01-01T00:00:00.000Z",
                    "modified": "2026-01-01T00:00:00.000Z",
                    "value": "1.1.1.1",
                },
                {
                    "type": "relationship", "spec_version": "2.1",
                    "id": "relationship--cccccccc-cccc-cccc-cccc-cccccccccccc",
                    "created": "2026-01-01T00:00:00.000Z",
                    "modified": "2026-01-01T00:00:00.000Z",
                    "relationship_type": "resolves-to",
                    "source_ref": "domain-name--aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                    "target_ref": "ipv4-addr--bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
                    "confidence": 90,
                },
            ],
        })
        report = STIXBundleImporter().import_text(bundle_text, graph)
        assert report.relationships_added == 1
        # The edge is real on the graph.
        assert graph.graph.number_of_edges() == 1

    def test_round_trip_with_export(self, graph: EntityGraph):
        """Build a graph → export to STIX → import into a
        fresh graph → entity counts match."""
        graph.add_domain("acme.com", source="scope")
        graph.add_subdomain("api.acme.com", "acme.com", "subfinder")
        graph.add_ip("1.2.3.4", source="naabu")
        graph.add_email("test@acme.com", source="hunter")

        bundle = build_stix_bundle(graph).bundle
        # Re-import into a fresh graph.
        fresh = EntityGraph(
            campaign_id="cmp-test2", engagement_id="eng-test2",
        )
        report = STIXBundleImporter().import_text(
            json.dumps(bundle), fresh,
        )
        # All 4 entities came through.
        assert report.entities_added >= 4
        # Counts by type match.
        assert report.counts_by_type.get("domain", 0) == 1
        assert report.counts_by_type.get("subdomain", 0) == 1
        assert report.counts_by_type.get("ip_address", 0) == 1
        assert report.counts_by_type.get("email", 0) == 1

    def test_skips_synthetic_nexusrecon_identity(self, graph: EntityGraph):
        """The export emits a synthetic Identity SDO that
        represents NexusRecon itself; the importer should
        SKIP it (not turn it into an Organization entity)."""
        graph.add_domain("acme.com", source="scope")
        bundle = build_stix_bundle(graph).bundle
        # Confirm an identity SDO with identity_class=system
        # is in the bundle.
        assert any(
            o["type"] == "identity"
            and o.get("identity_class") == "system"
            for o in bundle["objects"]
        )
        fresh = EntityGraph(campaign_id="c", engagement_id="e")
        STIXBundleImporter().import_text(json.dumps(bundle), fresh)
        # No Organization / Person entity emitted for the
        # synthetic identity.
        non_target_identities = [
            d for _, d in fresh.graph.nodes(data=True)
            if d.get("entity_type") in ("organization", "person")
        ]
        # The graph above didn't include any person/org
        # entities, so post-import shouldn't either.
        assert non_target_identities == []

    def test_malformed_input_warns(self, graph: EntityGraph):
        report = STIXBundleImporter().import_text("not JSON at all", graph)
        assert report.warnings
        assert report.entities_added == 0

    def test_missing_bundle_envelope(self, graph: EntityGraph):
        report = STIXBundleImporter().import_text(
            '{"type": "indicator"}', graph,
        )
        assert any("bundle envelope" in w for w in report.warnings)
        assert report.entities_added == 0


# ──────────────────────────────────────────────────────────────────────
# Nessus importer
# ──────────────────────────────────────────────────────────────────────


SAMPLE_NESSUS = textwrap.dedent("""\
<?xml version="1.0" ?>
<NessusClientData_v2>
  <Report name="Sample Report">
    <ReportHost name="api.acme.com">
      <HostProperties>
        <tag name="host-ip">1.2.3.4</tag>
        <tag name="host-fqdn">api.acme.com</tag>
      </HostProperties>
      <ReportItem pluginID="12345" port="443" severity="3"
                  protocol="tcp" pluginName="Foo">
        <cve>CVE-2024-12345</cve>
        <cve>CVE-2024-67890</cve>
      </ReportItem>
      <ReportItem pluginID="12346" port="443" severity="2"
                  protocol="tcp" pluginName="Bar">
        <cve>CVE-2024-12345</cve>
      </ReportItem>
    </ReportHost>
    <ReportHost name="10.0.0.5">
      <HostProperties>
        <tag name="host-ip">10.0.0.5</tag>
      </HostProperties>
      <ReportItem pluginID="22222" port="22" severity="1"
                  protocol="tcp" pluginName="OpenSSH"/>
    </ReportHost>
  </Report>
</NessusClientData_v2>
""")


class TestNessusImporter:
    def test_extracts_hosts_and_cves(self, graph: EntityGraph):
        report = NessusImporter().import_text(SAMPLE_NESSUS, graph)
        # subdomain (api.acme.com) + ip_address (1.2.3.4 and 10.0.0.5)
        # + 2 CVEs (deduped).
        assert report.counts_by_type.get("subdomain", 0) == 1
        assert report.counts_by_type.get("ip_address", 0) >= 1
        assert report.counts_by_type.get("cve", 0) == 2
        # has_cve edges from host → CVE.
        edge_types = {
            d.get("rel_type")
            for _, _, d in graph.graph.edges(data=True)
        }
        assert "has_cve" in edge_types

    def test_dedups_cves_per_host(self, graph: EntityGraph):
        """Same CVE in multiple ReportItems → still emits one
        CVE entity per host (the dedup is per host_elem)."""
        report = NessusImporter().import_text(SAMPLE_NESSUS, graph)
        # CVE-2024-12345 appears in two report items but
        # should land as one CVE entity (the graph's
        # add_entity merges by (type, value), and the
        # importer further dedupes per-host).
        cves = [
            d for _, d in graph.graph.nodes(data=True)
            if d.get("entity_type") == "cve"
        ]
        cve_values = {c["value"] for c in cves}
        assert cve_values == {"CVE-2024-12345", "CVE-2024-67890"}

    def test_malformed_xml(self, graph: EntityGraph):
        report = NessusImporter().import_text("not XML", graph)
        assert report.warnings
        assert report.entities_added == 0

    def test_resolves_to_edge_when_both_fqdn_and_ip(self, graph: EntityGraph):
        """When the host has both host-fqdn and host-ip the
        importer emits both entities + a RESOLVES_TO edge."""
        NessusImporter().import_text(SAMPLE_NESSUS, graph)
        edge_types = [
            d.get("rel_type")
            for _, _, d in graph.graph.edges(data=True)
        ]
        assert "resolves_to" in edge_types


# ──────────────────────────────────────────────────────────────────────
# Nuclei importer
# ──────────────────────────────────────────────────────────────────────


def _nuclei_finding(
    *, url: str = "https://api.acme.com/admin",
    host: str = "https://api.acme.com",
    severity: str = "high",
    cves: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "template-id": "exposed-panel",
        "type": "http",
        "host": host,
        "matched-at": url,
        "info": {
            "name": "Exposed admin panel",
            "severity": severity,
            "classification": (
                {"cve-id": cves or []}
                if cves is not None else {}
            ),
        },
    }


class TestNucleiImporter:
    def test_jsonl_input(self, graph: EntityGraph):
        body = "\n".join(
            json.dumps(_nuclei_finding(
                url=f"https://api.acme.com/a{i}",
                cves=["CVE-2024-11111"],
            ))
            for i in range(3)
        )
        report = NucleiImporter().import_text(body, graph)
        # 3 URLs, 1 host (deduped), 1 CVE.
        assert report.counts_by_type.get("url", 0) == 3
        assert report.counts_by_type.get("subdomain", 0) >= 1

    def test_json_array_input(self, graph: EntityGraph):
        body = json.dumps([
            _nuclei_finding(cves=["CVE-2024-99999"]),
            _nuclei_finding(url="https://api.acme.com/x"),
        ])
        report = NucleiImporter().import_text(body, graph)
        assert report.counts_by_type.get("url", 0) == 2
        assert report.counts_by_type.get("cve", 0) == 1

    def test_skips_malformed_lines(self, graph: EntityGraph):
        body = "\n".join([
            json.dumps(_nuclei_finding()),
            "this is not JSON",
            json.dumps(_nuclei_finding(url="https://api.acme.com/y")),
        ])
        report = NucleiImporter().import_text(body, graph)
        assert report.entities_added > 0
        assert report.skipped == 1
        assert any("invalid JSON" in w for w in report.warnings)

    def test_severity_drives_confidence(self, graph: EntityGraph):
        body = json.dumps(_nuclei_finding(severity="critical"))
        NucleiImporter().import_text(body, graph)
        urls = [
            d for _, d in graph.graph.nodes(data=True)
            if d.get("entity_type") == "url"
        ]
        assert urls[0]["confidence"] == pytest.approx(0.95)

    def test_creates_url_to_cve_edge(self, graph: EntityGraph):
        body = json.dumps(_nuclei_finding(cves=["CVE-2024-11111"]))
        NucleiImporter().import_text(body, graph)
        edge_types = [
            d.get("rel_type")
            for _, _, d in graph.graph.edges(data=True)
        ]
        assert "has_cve" in edge_types


# ──────────────────────────────────────────────────────────────────────
# CSV importer
# ──────────────────────────────────────────────────────────────────────


class TestCSVImporter:
    def test_domain_column_mapping(self, graph: EntityGraph, tmp_path: Path):
        path = tmp_path / "assets.csv"
        path.write_text(
            "Hostname,Owner\nacme.com,Infra\napi.acme.com,Infra\n",
        )
        report = CSVImporter().import_file(
            path, graph,
            mapping={
                "entity_type": "domain",
                "value_column": "Hostname",
            },
        )
        # Returns parsed counts.
        assert report.entities_added == 2
        assert report.counts_by_type.get("domain", 0) == 1
        assert report.counts_by_type.get("subdomain", 0) == 1

    def test_unsupported_entity_type_warns(
        self, graph: EntityGraph, tmp_path: Path,
    ):
        path = tmp_path / "data.csv"
        path.write_text("X\n1\n")
        report = CSVImporter().import_file(
            path, graph,
            mapping={
                "entity_type": "unicorn",
                "value_column": "X",
            },
        )
        assert any("unsupported" in w for w in report.warnings)
        assert report.entities_added == 0

    def test_missing_value_column_warns(
        self, graph: EntityGraph, tmp_path: Path,
    ):
        path = tmp_path / "data.csv"
        path.write_text("A,B\n1,2\n")
        report = CSVImporter().import_file(
            path, graph,
            mapping={
                "entity_type": "domain",
                "value_column": "Missing",
            },
        )
        assert any("not in CSV" in w for w in report.warnings)

    def test_confidence_column(
        self, graph: EntityGraph, tmp_path: Path,
    ):
        path = tmp_path / "scored.csv"
        path.write_text(
            "Hostname,Score\nacme.com,0.95\napi.acme.com,0.7\n",
        )
        CSVImporter().import_file(
            path, graph,
            mapping={
                "entity_type": "domain",
                "value_column": "Hostname",
                "confidence_column": "Score",
            },
        )
        domains = [
            d for _, d in graph.graph.nodes(data=True)
            if d.get("value") == "acme.com"
        ]
        assert domains[0]["confidence"] == pytest.approx(0.95)

    def test_skips_blank_value(
        self, graph: EntityGraph, tmp_path: Path,
    ):
        # An empty cell in the value column (as opposed to an
        # empty LINE, which csv.DictReader silently skips) is
        # what the importer's `if not value: skipped += 1`
        # branch actually catches.
        path = tmp_path / "patchy.csv"
        path.write_text(
            "Hostname,Owner\nacme.com,a\n,b\napi.acme.com,c\n",
        )
        report = CSVImporter().import_file(
            path, graph,
            mapping={
                "entity_type": "domain",
                "value_column": "Hostname",
            },
        )
        assert report.entities_added == 2
        assert report.skipped == 1

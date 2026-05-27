"""Nessus XML report importer.

Nessus exports a ``.nessus`` XML file structured as::

  <NessusClientData_v2>
    <Report>
      <ReportHost name="acme.com">
        <HostProperties>
          <tag name="host-ip">1.2.3.4</tag>
          <tag name="host-fqdn">api.acme.com</tag>
        </HostProperties>
        <ReportItem pluginID="..." severity="3" pluginName="..."
                    pluginFamily="..." port="443" protocol="tcp"
                    svc_name="https">
          <cve>CVE-2024-12345</cve>
          ...
        </ReportItem>
      </ReportHost>
    </Report>
  </NessusClientData_v2>

We emit:

- ``DomainEntity`` / ``SubdomainEntity`` for each
  ``ReportHost name`` + the ``host-fqdn`` tag.
- ``IPAddressEntity`` for the ``host-ip`` tag.
- ``CVEEntity`` for every ``<cve>`` element inside a
  ``ReportItem`` (deduplicated).
- Relationships: ``has_cve`` edges from the host to each CVE.

Resilient
- Bad XML → empty report + a warning.
- Hosts without IP / fqdn → still emit the host name itself
  if it looks domain-shaped.
- Items without CVEs → still surface the host.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

import structlog

from nexusrecon.ingest.types import ImportReport
from nexusrecon.models.entities import (
    CVEEntity,
    DomainEntity,
    EntityRelationship,
    IPAddressEntity,
    RelationshipType,
    SubdomainEntity,
)

log = structlog.get_logger(__name__)


_DOMAIN_PATTERN = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)"
    r"+[a-z]{2,24}$",
    re.IGNORECASE,
)
_IP_PATTERN = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


class NessusImporter:
    """Nessus .nessus XML → EntityGraph."""

    name: str = "nessus"

    def __init__(self, *, source_label: str | None = None):
        self.source_label = (
            source_label or f"imported_from:{self.name}"
        )

    def import_file(self, path: Path | str, graph: Any) -> ImportReport:
        p = Path(path).expanduser()
        report = ImportReport(importer=self.name, source_path=str(p))
        if not p.exists():
            report.warnings.append(f"file not found: {p}")
            return report
        try:
            xml_text = p.read_text(encoding="utf-8")
        except Exception as exc:
            report.warnings.append(f"read failed: {exc}")
            return report
        return self.import_text(xml_text, graph, source_path=str(p))

    def import_text(
        self,
        xml_text: str,
        graph: Any,
        *,
        source_path: str = "",
    ) -> ImportReport:
        report = ImportReport(importer=self.name, source_path=source_path)
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError as exc:
            report.warnings.append(f"invalid XML: {exc}")
            return report

        # ``.//ReportHost`` works whether the namespace is
        # default or prefixed.
        for host_elem in root.findall(".//ReportHost"):
            try:
                self._import_host(host_elem, graph, report)
            except Exception as exc:
                report.warnings.append(
                    f"host {host_elem.get('name', '?')!r}: {exc}"
                )
                report.skipped += 1
        return report

    def _import_host(
        self,
        host_elem: ET.Element,
        graph: Any,
        report: ImportReport,
    ) -> None:
        host_name = host_elem.get("name", "").strip()
        host_props = self._collect_host_props(host_elem)

        # Pick the best entity for the "host": fqdn first,
        # then name, then IP.
        fqdn = host_props.get("host-fqdn") or ""
        ip = host_props.get("host-ip") or ""
        host_entity_id: str | None = None

        target_value = (
            fqdn
            if _DOMAIN_PATTERN.match(fqdn)
            else (
                host_name
                if _DOMAIN_PATTERN.match(host_name)
                else ip
                if _IP_PATTERN.match(ip)
                else host_name
            )
        )
        if not target_value:
            report.skipped += 1
            return

        # Domain / subdomain / IP.
        if _IP_PATTERN.match(target_value):
            ip_entity = IPAddressEntity(
                value=target_value,
                sources=[self.source_label],
                confidence=0.85,
            )
            host_entity_id = graph.add_entity(ip_entity)
            report.entities_added += 1
            report.counts_by_type["ip_address"] = (
                report.counts_by_type.get("ip_address", 0) + 1
            )
        elif _DOMAIN_PATTERN.match(target_value):
            if target_value.count(".") >= 2:
                parent = ".".join(target_value.split(".")[-2:])
                d = SubdomainEntity(
                    value=target_value,
                    parent_domain=parent,
                    sources=[self.source_label],
                    confidence=0.85,
                )
                e_type = "subdomain"
            else:
                d = DomainEntity(
                    value=target_value,
                    sources=[self.source_label],
                    confidence=0.85,
                )
                e_type = "domain"
            host_entity_id = graph.add_entity(d)
            report.entities_added += 1
            report.counts_by_type[e_type] = (
                report.counts_by_type.get(e_type, 0) + 1
            )

        # Also emit a separate IP entity if we have both fqdn
        # + ip — and link them via RESOLVES_TO.
        if (
            host_entity_id
            and ip
            and _IP_PATTERN.match(ip)
            and target_value != ip
        ):
            ip_entity = IPAddressEntity(
                value=ip,
                sources=[self.source_label],
                confidence=0.85,
            )
            ip_id = graph.add_entity(ip_entity)
            report.entities_added += 1
            report.counts_by_type["ip_address"] = (
                report.counts_by_type.get("ip_address", 0) + 1
            )
            graph.add_relationship(EntityRelationship(
                source_id=host_entity_id,
                target_id=ip_id,
                rel_type=RelationshipType.RESOLVES_TO,
                confidence=0.85,
                source_tool=self.source_label,
            ))
            report.relationships_added += 1

        # Per-item CVEs.
        if host_entity_id is None:
            return
        seen_cves: set[str] = set()
        for report_item in host_elem.findall("ReportItem"):
            for cve_elem in report_item.findall("cve"):
                cve_id = (cve_elem.text or "").strip()
                if not cve_id or cve_id in seen_cves:
                    continue
                seen_cves.add(cve_id)
                cve_entity = CVEEntity(
                    value=cve_id, cve_id=cve_id,
                    sources=[self.source_label],
                    confidence=0.85,
                )
                cve_node_id = graph.add_entity(cve_entity)
                report.entities_added += 1
                report.counts_by_type["cve"] = (
                    report.counts_by_type.get("cve", 0) + 1
                )
                graph.add_relationship(EntityRelationship(
                    source_id=host_entity_id,
                    target_id=cve_node_id,
                    rel_type=RelationshipType.HAS_CVE,
                    confidence=0.85,
                    source_tool=self.source_label,
                ))
                report.relationships_added += 1

    @staticmethod
    def _collect_host_props(host_elem: ET.Element) -> dict[str, str]:
        """Flatten the ``HostProperties/tag[name=...]`` block
        into a dict."""
        out: dict[str, str] = {}
        props = host_elem.find("HostProperties")
        if props is None:
            return out
        for tag in props.findall("tag"):
            n = tag.get("name", "")
            if n:
                out[n] = (tag.text or "").strip()
        return out

"""Nuclei JSON-lines output importer.

Nuclei's ``-json-export`` / ``-json`` output is a JSON-lines
stream where each line is one finding::

  {"template-id": "...", "matcher-name": "...",
   "type": "http", "host": "https://api.acme.com",
   "matched-at": "https://api.acme.com/admin",
   "info": {"name": "...", "severity": "medium",
            "classification": {"cve-id": ["CVE-2024-12345"]}},
   ...}

We emit:

- A URL entity for ``matched-at``.
- A subdomain / domain entity for the host part.
- A CVE entity for each ``info.classification.cve-id`` value.
- Relationships: ``has_cve`` from URL to CVE.

Resilient
- Each line parses independently; a malformed line goes to
  ``skipped`` and the rest of the file continues.
- Missing fields → best-effort with what's there.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import structlog

from nexusrecon.ingest.types import ImportReport
from nexusrecon.models.entities import (
    CVEEntity,
    DomainEntity,
    EntityRelationship,
    RelationshipType,
    SubdomainEntity,
    URLEntity,
)

log = structlog.get_logger(__name__)


_DOMAIN_PATTERN = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)"
    r"+[a-z]{2,24}$",
    re.IGNORECASE,
)


def _severity_to_confidence(severity: str) -> float:
    """Map Nuclei severity strings to a graph confidence.
    Critical/high findings come with stronger confidence
    that the underlying entity matters; info-level matches
    less so."""
    return {
        "critical": 0.95,
        "high": 0.9,
        "medium": 0.85,
        "low": 0.75,
        "info": 0.6,
    }.get(severity.lower(), 0.75)


class NucleiImporter:
    """Nuclei JSON-lines → EntityGraph."""

    name: str = "nuclei"

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
            body = p.read_text(encoding="utf-8")
        except Exception as exc:
            report.warnings.append(f"read failed: {exc}")
            return report
        return self.import_text(body, graph, source_path=str(p))

    def import_text(
        self,
        body: str,
        graph: Any,
        *,
        source_path: str = "",
    ) -> ImportReport:
        report = ImportReport(importer=self.name, source_path=source_path)

        # Two modes:
        # 1) jsonl (one finding per line). Nuclei default.
        # 2) JSON array (the ``-json-export`` flag emits this).
        # Try array first; fall back to per-line.
        body = body.strip()
        if body.startswith("["):
            try:
                items = json.loads(body)
            except json.JSONDecodeError as exc:
                report.warnings.append(f"invalid JSON array: {exc}")
                return report
            if not isinstance(items, list):
                report.warnings.append("top-level value is not a list")
                return report
            for item in items:
                self._import_finding(item, graph, report)
            return report

        # JSON-lines mode.
        for lineno, line in enumerate(body.splitlines(), 1):
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                report.warnings.append(
                    f"line {lineno}: invalid JSON ({exc})"
                )
                report.skipped += 1
                continue
            self._import_finding(item, graph, report)
        return report

    def _import_finding(
        self,
        item: Any,
        graph: Any,
        report: ImportReport,
    ) -> None:
        if not isinstance(item, dict):
            report.skipped += 1
            return

        # Extract fields with multiple fallback keys —
        # Nuclei's field names have shifted across versions.
        matched_at = (
            item.get("matched-at")
            or item.get("matched_at")
            or item.get("host", "")
        )
        host_raw = item.get("host", "")
        info = item.get("info") or {}
        severity = str(info.get("severity", "info"))
        confidence = _severity_to_confidence(severity)

        # URL entity for the matched location.
        url_id: str | None = None
        if matched_at:
            try:
                url_entity = URLEntity(
                    value=matched_at,
                    sources=[self.source_label],
                    confidence=confidence,
                )
                url_id = graph.add_entity(url_entity)
                report.entities_added += 1
                report.counts_by_type["url"] = (
                    report.counts_by_type.get("url", 0) + 1
                )
            except Exception as exc:
                report.warnings.append(f"URL parse: {exc}")

        # Host entity (domain or subdomain).
        host_value = _extract_hostname(host_raw or matched_at)
        host_id: str | None = None
        if host_value and _DOMAIN_PATTERN.match(host_value):
            if host_value.count(".") >= 2:
                h = SubdomainEntity(
                    value=host_value,
                    parent_domain=".".join(host_value.split(".")[-2:]),
                    sources=[self.source_label],
                    confidence=confidence,
                )
                e_type = "subdomain"
            else:
                h = DomainEntity(
                    value=host_value,
                    sources=[self.source_label],
                    confidence=confidence,
                )
                e_type = "domain"
            host_id = graph.add_entity(h)
            report.entities_added += 1
            report.counts_by_type[e_type] = (
                report.counts_by_type.get(e_type, 0) + 1
            )

        # CVEs from info.classification.cve-id.
        cve_ids: list[str] = []
        classification = info.get("classification") or {}
        if isinstance(classification, dict):
            raw_cves = classification.get("cve-id") or classification.get("cve_id")
            if isinstance(raw_cves, list):
                cve_ids = [str(c) for c in raw_cves if c]
            elif isinstance(raw_cves, str):
                cve_ids = [raw_cves]
        for cve_id in cve_ids:
            cve_entity = CVEEntity(
                value=cve_id, cve_id=cve_id,
                sources=[self.source_label],
                confidence=confidence,
            )
            cve_node_id = graph.add_entity(cve_entity)
            report.entities_added += 1
            report.counts_by_type["cve"] = (
                report.counts_by_type.get("cve", 0) + 1
            )
            # Link from URL (preferred) or host to the CVE.
            edge_source = url_id or host_id
            if edge_source is not None:
                graph.add_relationship(EntityRelationship(
                    source_id=edge_source,
                    target_id=cve_node_id,
                    rel_type=RelationshipType.HAS_CVE,
                    confidence=confidence,
                    source_tool=self.source_label,
                ))
                report.relationships_added += 1


def _extract_hostname(value: str) -> str:
    """Extract the host part from a URL-or-hostname string."""
    if not value:
        return ""
    if "://" in value:
        parsed = urlparse(value)
        return parsed.hostname or ""
    # Plain host[:port].
    return value.split(":", 1)[0]

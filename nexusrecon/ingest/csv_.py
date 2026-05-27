"""Generic CSV importer.

Takes a CSV file + a declarative column mapping. Each row
contributes one entity (and optionally a relationship). The
mapping is small enough that operators can express it inline:

    mapping = {
        "entity_type": "domain",
        "value_column": "Hostname",
        # optional: confidence column / fixed value
        "confidence_column": "Confidence",
    }

    importer = CSVImporter()
    importer.import_file("inventory.csv", graph, mapping=mapping)

Supported ``entity_type`` values match the NexusRecon
:class:`EntityType` enum's lowercase string values
(``domain``, ``subdomain``, ``ip_address``, ``email``,
``url``, ``technology``, ``cve``). Other types require a
plugin-contributed importer (Pack format, Phase 3).
"""
from __future__ import annotations

import csv
import re
from pathlib import Path
from typing import Any

import structlog

from nexusrecon.ingest.types import ImportReport
from nexusrecon.models.entities import (
    CVEEntity,
    DomainEntity,
    EmailEntity,
    IPAddressEntity,
    SubdomainEntity,
    TechnologyEntity,
    URLEntity,
)

log = structlog.get_logger(__name__)


_DOMAIN_PATTERN = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)"
    r"+[a-z]{2,24}$",
    re.IGNORECASE,
)


class CSVImporter:
    """Generic CSV → EntityGraph with a declarative column
    mapping."""

    name: str = "csv"

    def __init__(self, *, source_label: str | None = None):
        self.source_label = (
            source_label or f"imported_from:{self.name}"
        )

    def import_file(
        self,
        path: Path | str,
        graph: Any,
        *,
        mapping: dict[str, Any],
    ) -> ImportReport:
        """Import each row per the ``mapping``. The mapping is
        required — there's no sensible default for which
        column carries the entity value."""
        p = Path(path).expanduser()
        report = ImportReport(importer=self.name, source_path=str(p))
        if not p.exists():
            report.warnings.append(f"file not found: {p}")
            return report

        entity_type = mapping.get("entity_type", "").lower()
        value_column = mapping.get("value_column")
        if not entity_type or not value_column:
            report.warnings.append(
                "mapping requires 'entity_type' and 'value_column'",
            )
            return report

        builder = _BUILDERS.get(entity_type)
        if builder is None:
            report.warnings.append(
                f"unsupported entity_type {entity_type!r}; "
                f"supported: {sorted(_BUILDERS)}"
            )
            return report

        confidence_column = mapping.get("confidence_column")
        confidence_default = float(mapping.get("confidence_default", 0.7))

        try:
            with open(p, "r", encoding="utf-8", newline="") as f:
                reader = csv.DictReader(f)
                if value_column not in (reader.fieldnames or []):
                    report.warnings.append(
                        f"value_column {value_column!r} not in CSV "
                        f"columns {reader.fieldnames}"
                    )
                    return report
                for rownum, row in enumerate(reader, 1):
                    self._import_row(
                        row, rownum, builder,
                        value_column=value_column,
                        confidence_column=confidence_column,
                        confidence_default=confidence_default,
                        graph=graph,
                        report=report,
                        entity_type=entity_type,
                    )
        except Exception as exc:
            report.warnings.append(f"CSV read failed: {exc}")

        return report

    def _import_row(
        self,
        row: dict[str, str],
        rownum: int,
        builder: Any,
        *,
        value_column: str,
        confidence_column: str | None,
        confidence_default: float,
        graph: Any,
        report: ImportReport,
        entity_type: str,
    ) -> None:
        value = (row.get(value_column) or "").strip()
        if not value:
            report.skipped += 1
            return
        confidence = confidence_default
        if confidence_column:
            try:
                confidence = float(row.get(confidence_column, "") or confidence_default)
                # Accept either 0-1 or 0-100 input.
                if confidence > 1.0:
                    confidence = confidence / 100.0
            except ValueError:
                report.warnings.append(
                    f"row {rownum}: confidence column not numeric"
                )
                confidence = confidence_default
        try:
            entity = builder(
                value=value,
                source=self.source_label,
                confidence=confidence,
            )
        except Exception as exc:
            report.warnings.append(
                f"row {rownum}: entity build failed ({exc})"
            )
            report.skipped += 1
            return
        graph.add_entity(entity)
        report.entities_added += 1
        # Use the ACTUAL entity type the builder produced —
        # ``domain`` mapping with a 3-part value yields a
        # SubdomainEntity, and we want that to show up in
        # the count breakdown so operators see the real
        # shape.
        actual_type = entity.entity_type.value
        report.counts_by_type[actual_type] = (
            report.counts_by_type.get(actual_type, 0) + 1
        )


# ──────────────────────────────────────────────────────────────────────
# Per-type builders
# ──────────────────────────────────────────────────────────────────────


def _build_domain(*, value: str, source: str, confidence: float) -> Any:
    if value.count(".") >= 2:
        return SubdomainEntity(
            value=value,
            parent_domain=".".join(value.split(".")[-2:]),
            sources=[source], confidence=confidence,
        )
    return DomainEntity(
        value=value, sources=[source], confidence=confidence,
    )


def _build_subdomain(*, value: str, source: str, confidence: float) -> Any:
    return SubdomainEntity(
        value=value,
        parent_domain=".".join(value.split(".")[-2:])
        if "." in value else "",
        sources=[source], confidence=confidence,
    )


def _build_ip(*, value: str, source: str, confidence: float) -> Any:
    return IPAddressEntity(
        value=value, sources=[source], confidence=confidence,
    )


def _build_email(*, value: str, source: str, confidence: float) -> Any:
    parts = value.lower().split("@")
    return EmailEntity(
        value=value.lower(),
        local_part=parts[0] if len(parts) == 2 else value,
        domain=parts[1] if len(parts) == 2 else "",
        sources=[source], confidence=confidence,
    )


def _build_url(*, value: str, source: str, confidence: float) -> Any:
    return URLEntity(
        value=value, sources=[source], confidence=confidence,
    )


def _build_technology(*, value: str, source: str, confidence: float) -> Any:
    return TechnologyEntity(
        value=value, product=value,
        sources=[source], confidence=confidence,
    )


def _build_cve(*, value: str, source: str, confidence: float) -> Any:
    return CVEEntity(
        value=value, cve_id=value,
        sources=[source], confidence=confidence,
    )


_BUILDERS: dict[str, Any] = {
    "domain": _build_domain,
    "subdomain": _build_subdomain,
    "ip_address": _build_ip,
    "ip": _build_ip,
    "email": _build_email,
    "url": _build_url,
    "technology": _build_technology,
    "cve": _build_cve,
}

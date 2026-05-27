"""STIX 2.1 Bundle importer.

Reverse direction of PR B's :mod:`nexusrecon.export.stix`.
Reads a STIX bundle and emits NexusRecon entities +
relationships into a live :class:`EntityGraph`.

Mapping is the inverse of the export:

  - ``domain-name`` SCO → ``DomainEntity`` (or
    ``SubdomainEntity`` when value has ≥ 3 components)
  - ``ipv4-addr`` / ``ipv6-addr`` → ``IPAddressEntity``
  - ``email-addr`` → ``EmailEntity``
  - ``url`` → ``URLEntity``
  - ``identity`` → ``PersonEntity`` /
    ``OrganizationEntity`` based on ``identity_class``
  - ``software`` → ``TechnologyEntity``
  - ``vulnerability`` → ``CVEEntity`` (when external_references
    include a CVE id)
  - ``infrastructure`` → ``CloudAssetEntity`` (when the bundle
    came from NexusRecon — detected via ``x_nexusrecon_*``
    properties) or ``RepositoryEntity`` (best-effort) or
    ignored
  - ``note`` → ``HypothesisEntity`` / ``LeadEntity`` /
    ``OpenQuestionEntity`` based on the ``abstract`` field
    NexusRecon emitted, or ignored otherwise
  - ``relationship`` SRO → graph edge with the rel_type
    mapped back through the inverse vocabulary

Resilient
- Skip + warn on malformed objects.
- Tolerant of unknown types (record + count under
  ``skipped``).
- Bundle envelope must declare ``type: bundle``; otherwise
  the importer refuses.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import structlog

from nexusrecon.ingest.types import ImportReport
from nexusrecon.models.entities import (
    CloudAssetEntity,
    CVEEntity,
    DomainEntity,
    EmailEntity,
    EntityRelationship,
    HypothesisEntity,
    IPAddressEntity,
    LeadEntity,
    OpenQuestionEntity,
    OrganizationEntity,
    PersonEntity,
    RelationshipType,
    SubdomainEntity,
    TechnologyEntity,
    URLEntity,
)

log = structlog.get_logger(__name__)


#: Inverse of the export mapping for relationship types.
_REL_TYPE_REVERSE: dict[str, str] = {
    "resolves-to": "resolves_to",
    "owns": "owns",
    "belongs-to": "belongs_to",
    "part-of": "part_of",
    "has": "has_cve",
    "hosted-on": "hosted_on",
    "communicates-with": "linked_to",  # closest match
}


def _to_nexusrecon_rel(stix_type: str) -> RelationshipType | None:
    nr_value = _REL_TYPE_REVERSE.get(stix_type, stix_type.replace("-", "_"))
    try:
        return RelationshipType(nr_value)
    except ValueError:
        return None


class STIXBundleImporter:
    """STIX 2.1 → EntityGraph."""

    name: str = "stix"

    def __init__(self, *, source_label: str | None = None):
        self.source_label = (
            source_label or f"imported_from:{self.name}"
        )

    def import_file(self, path: Path | str, graph: Any) -> ImportReport:
        """Parse the bundle at ``path`` and merge into
        ``graph``. Returns an :class:`ImportReport`."""
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
        """Same as :meth:`import_file` but takes the JSON text
        directly (useful for tests + remote-fetched bundles)."""
        report = ImportReport(importer=self.name, source_path=source_path)
        try:
            data = json.loads(body)
        except json.JSONDecodeError as exc:
            report.warnings.append(f"invalid JSON: {exc}")
            return report
        if not isinstance(data, dict) or data.get("type") != "bundle":
            report.warnings.append(
                "bundle envelope missing — expected top-level "
                "object with type=bundle",
            )
            return report

        # Pass 1: entities (every object except relationships).
        stix_id_to_entity_id: dict[str, str] = {}
        for obj in data.get("objects") or []:
            if not isinstance(obj, dict):
                report.skipped += 1
                continue
            stix_type = obj.get("type")
            if stix_type == "relationship":
                continue  # pass 2
            try:
                entity_id = self._import_object(obj, graph, report)
            except Exception as exc:
                report.warnings.append(
                    f"object {obj.get('id')!r}: {exc}"
                )
                report.skipped += 1
                continue
            if entity_id is None:
                report.skipped += 1
                continue
            stix_id_to_entity_id[obj["id"]] = entity_id

        # Pass 2: relationships.
        for obj in data.get("objects") or []:
            if not isinstance(obj, dict) or obj.get("type") != "relationship":
                continue
            try:
                ok = self._import_relationship(
                    obj, graph, stix_id_to_entity_id, report,
                )
                if ok:
                    report.relationships_added += 1
                else:
                    report.skipped += 1
            except Exception as exc:
                report.warnings.append(
                    f"relationship {obj.get('id')!r}: {exc}"
                )
                report.skipped += 1

        return report

    # ── Object → Entity ──────────────────────────────────────

    def _import_object(
        self,
        obj: dict[str, Any],
        graph: Any,
        report: ImportReport,
    ) -> str | None:
        stix_type = obj.get("type")
        value = obj.get("value") or obj.get("name") or ""
        if not value:
            return None

        entity = self._build_entity(stix_type, value, obj)
        if entity is None:
            return None

        # Track whether this is a fresh add or a merge for the
        # report.
        before = graph.graph.number_of_nodes()
        entity_id = graph.add_entity(entity)
        after = graph.graph.number_of_nodes()
        if after > before:
            report.entities_added += 1
        else:
            report.entities_merged += 1
        e_type = entity.entity_type.value
        report.counts_by_type[e_type] = (
            report.counts_by_type.get(e_type, 0) + 1
        )
        return entity_id

    def _build_entity(
        self,
        stix_type: str,
        value: str,
        obj: dict[str, Any],
    ) -> Any | None:
        sources = [self.source_label]
        confidence = self._confidence_from(obj)

        if stix_type == "domain-name":
            # ≥ 3 components → subdomain.
            if value.count(".") >= 2:
                parent = ".".join(value.split(".")[-2:])
                return SubdomainEntity(
                    value=value,
                    parent_domain=parent,
                    sources=sources,
                    confidence=confidence,
                )
            return DomainEntity(
                value=value, sources=sources, confidence=confidence,
            )

        if stix_type in ("ipv4-addr", "ipv6-addr"):
            return IPAddressEntity(
                value=value, sources=sources, confidence=confidence,
            )

        if stix_type == "email-addr":
            parts = value.lower().split("@")
            local = parts[0] if len(parts) == 2 else value
            domain = parts[1] if len(parts) == 2 else ""
            return EmailEntity(
                value=value.lower(),
                local_part=local, domain=domain,
                sources=sources, confidence=confidence,
            )

        if stix_type == "url":
            return URLEntity(
                value=value, sources=sources, confidence=confidence,
            )

        if stix_type == "identity":
            identity_class = obj.get("identity_class", "")
            if identity_class == "organization":
                return OrganizationEntity(
                    value=value, sources=sources, confidence=confidence,
                )
            if identity_class == "individual":
                return PersonEntity(
                    value=value, sources=sources, confidence=confidence,
                )
            # Skip the synthetic NexusRecon identity SDO + any
            # other identity_class we don't model.
            return None

        if stix_type == "software":
            return TechnologyEntity(
                value=value, product=value,
                sources=sources, confidence=confidence,
            )

        if stix_type == "vulnerability":
            cve_id = self._cve_from_refs(obj.get("external_references"))
            if cve_id:
                return CVEEntity(
                    value=cve_id, cve_id=cve_id,
                    sources=sources, confidence=confidence,
                )
            return None

        if stix_type == "infrastructure":
            provider = obj.get("x_nexusrecon_provider", "")
            service = obj.get("x_nexusrecon_service_type", "")
            if provider:
                return CloudAssetEntity(
                    value=value, provider=provider,
                    service_type=service or "",
                    sources=sources, confidence=confidence,
                )
            return None

        if stix_type == "note":
            abstract = obj.get("abstract", "")
            content = obj.get("content", value)
            if abstract == "Analyst hypothesis":
                return HypothesisEntity(
                    value=content, statement=content,
                    sources=sources, confidence=confidence,
                )
            if abstract == "Confirmed lead":
                return LeadEntity(
                    value=content, statement=content,
                    sources=sources, confidence=confidence,
                )
            if abstract == "Open question":
                return OpenQuestionEntity(
                    value=content, question=content,
                    sources=sources, confidence=confidence,
                )
            return None

        return None

    def _import_relationship(
        self,
        obj: dict[str, Any],
        graph: Any,
        stix_id_to_entity_id: dict[str, str],
        report: ImportReport,
    ) -> bool:
        source_ref = obj.get("source_ref", "")
        target_ref = obj.get("target_ref", "")
        rel_type_str = obj.get("relationship_type", "")
        source_id = stix_id_to_entity_id.get(source_ref)
        target_id = stix_id_to_entity_id.get(target_ref)
        if source_id is None or target_id is None:
            return False
        nr_rel = _to_nexusrecon_rel(rel_type_str)
        if nr_rel is None:
            report.warnings.append(
                f"unknown relationship_type {rel_type_str!r}",
            )
            return False
        rel = EntityRelationship(
            source_id=source_id,
            target_id=target_id,
            rel_type=nr_rel,
            confidence=self._confidence_from(obj),
            source_tool=self.source_label,
        )
        graph.add_relationship(rel)
        return True

    @staticmethod
    def _confidence_from(obj: dict[str, Any]) -> float:
        """STIX confidence is 0-100; we want 0-1."""
        raw = obj.get("confidence")
        if raw is None:
            return 0.8  # neutral mid-high for imported data
        try:
            value = float(raw) / 100.0
        except (TypeError, ValueError):
            return 0.8
        return max(0.0, min(1.0, value))

    @staticmethod
    def _cve_from_refs(refs: Any) -> str | None:
        if not isinstance(refs, list):
            return None
        for r in refs:
            if (
                isinstance(r, dict)
                and r.get("source_name") == "cve"
                and r.get("external_id")
            ):
                return str(r["external_id"])
        return None

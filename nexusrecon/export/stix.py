"""STIX 2.1 Bundle serialiser.

Builds a STIX 2.1 Bundle dict from an :class:`EntityGraph`.
The output is a plain JSON-serialisable structure — the
serialised form lands in ``stix2-bundle.json`` (or whatever
the operator picks).

Why stdlib-only
- The official ``stix2`` library is heavy + the schema is
  stable enough that hand-rolling the JSON is reliable.
- A future PR can layer ``stix2`` on for strict validation
  if community adoption justifies the dep.
- For now: structural tests (UUID shape, required fields,
  bundle invariants) catch the cases that matter.

Spec references
- STIX 2.1 spec: https://docs.oasis-open.org/cti/stix/v2.1/
- Bundle: section 3.1
- SDOs / SCOs / SROs: sections 4-7

Identifier convention
- Every object gets a STIX ID: ``<type>--<uuidv4>``.
- We use UUIDv5 in the NexusRecon namespace so re-exporting
  the same campaign produces the same IDs (stable diffs).
- Bundle IDs use UUIDv4 (per-export).
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog

log = structlog.get_logger(__name__)


SPEC_VERSION: str = "2.1"

#: UUIDv5 namespace for NexusRecon-emitted STIX IDs. Lets two
#: exports of the same campaign produce the same IDs (handy
#: for downstream diff / dedup).
NEXUSRECON_NS = uuid.UUID("d2c4f6e8-1a3b-5c7d-9e0f-aabbccddeeff")

_IPV4_PATTERN = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


@dataclass
class STIXBundle:
    """Holds the bundle + a count breakdown for the CLI."""
    bundle: dict[str, Any]
    counts: dict[str, int] = field(default_factory=dict)

    def to_json(self, *, indent: int | None = 2) -> str:
        return json.dumps(self.bundle, indent=indent, default=str)


# ──────────────────────────────────────────────────────────────────────
# ID generation
# ──────────────────────────────────────────────────────────────────────


def _stix_id(stix_type: str, seed: str) -> str:
    """Produce a deterministic STIX ID. Uses UUIDv5 with the
    NexusRecon namespace + the seed string so the same input
    always produces the same ID across exports."""
    digest = uuid.uuid5(NEXUSRECON_NS, f"{stix_type}::{seed}")
    return f"{stix_type}--{digest}"


def _bundle_id() -> str:
    """Per-export UUIDv4."""
    return f"bundle--{uuid.uuid4()}"


# ──────────────────────────────────────────────────────────────────────
# Mappers
# ──────────────────────────────────────────────────────────────────────


def _now() -> str:
    """STIX timestamps are ISO 8601 with millisecond precision."""
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z",
    )


def _base_object(
    stix_type: str,
    seed: str,
    *,
    created_by_ref: str | None = None,
) -> dict[str, Any]:
    """Common fields every SDO/SCO carries."""
    obj: dict[str, Any] = {
        "type": stix_type,
        "spec_version": SPEC_VERSION,
        "id": _stix_id(stix_type, seed),
        "created": _now(),
        "modified": _now(),
    }
    if created_by_ref:
        obj["created_by_ref"] = created_by_ref
    return obj


def _map_domain(entity: dict[str, Any]) -> dict[str, Any]:
    obj = _base_object("domain-name", entity["value"])
    obj["value"] = entity["value"]
    return obj


def _map_ip(entity: dict[str, Any]) -> dict[str, Any]:
    value = entity["value"]
    stix_type = "ipv4-addr" if _IPV4_PATTERN.match(value) else "ipv6-addr"
    obj = _base_object(stix_type, value)
    obj["value"] = value
    return obj


def _map_email(entity: dict[str, Any]) -> dict[str, Any]:
    obj = _base_object("email-addr", entity["value"])
    obj["value"] = entity["value"]
    return obj


def _map_url(entity: dict[str, Any]) -> dict[str, Any]:
    obj = _base_object("url", entity["value"])
    obj["value"] = entity["value"]
    return obj


def _map_identity(entity: dict[str, Any]) -> dict[str, Any]:
    obj = _base_object("identity", entity["value"])
    obj["name"] = entity["value"]
    obj["identity_class"] = (
        "organization"
        if entity.get("entity_type") == "organization"
        else "individual"
    )
    return obj


def _map_technology(entity: dict[str, Any]) -> dict[str, Any]:
    obj = _base_object("software", entity["value"])
    obj["name"] = entity["value"]
    return obj


def _map_cve(entity: dict[str, Any]) -> dict[str, Any]:
    obj = _base_object("vulnerability", entity["value"])
    obj["name"] = entity["value"]
    # CVE id surfaced as an external reference per STIX
    # convention.
    obj["external_references"] = [{
        "source_name": "cve",
        "external_id": entity["value"],
    }]
    return obj


def _map_infrastructure(entity: dict[str, Any]) -> dict[str, Any]:
    obj = _base_object("infrastructure", entity["value"])
    obj["name"] = entity["value"]
    if entity.get("entity_type") == "cloud_asset":
        obj["infrastructure_types"] = ["hosting-malware"]
        # Stash provider / service_type in a custom property
        # (the ``x_`` prefix is the STIX convention).
        if entity.get("provider"):
            obj["x_nexusrecon_provider"] = entity["provider"]
        if entity.get("service_type"):
            obj["x_nexusrecon_service_type"] = entity["service_type"]
    return obj


def _map_note(
    entity: dict[str, Any],
    *,
    abstract: str,
    content_field: str,
) -> dict[str, Any]:
    obj = _base_object("note", entity["value"])
    obj["abstract"] = abstract
    obj["content"] = str(entity.get(content_field) or entity["value"])
    return obj


def _map_secret(entity: dict[str, Any]) -> dict[str, Any]:
    # CRITICAL: never serialise the secret VALUE. The audit
    # chain reasons about secrets at the metadata level only.
    obj = _base_object("note", entity["value"])
    obj["abstract"] = "Secret artifact (value redacted)"
    obj["content"] = (
        f"Secret of type {entity.get('secret_type', 'unknown')!r} "
        f"observed at {entity['value']!r}. Value not exported."
    )
    obj["x_nexusrecon_secret_type"] = entity.get("secret_type", "")
    return obj


#: NexusRecon entity_type → mapper. Functions ALL take the
#: node-data dict and return a STIX object dict.
_ENTITY_MAPPERS: dict[str, Any] = {
    "domain": _map_domain,
    "subdomain": _map_domain,
    "ip_address": _map_ip,
    "email": _map_email,
    "url": _map_url,
    "person": _map_identity,
    "organization": _map_identity,
    "username": _map_identity,
    "technology": _map_technology,
    "cve": _map_cve,
    "cloud_asset": _map_infrastructure,
    "repository": _map_infrastructure,
    "secret": _map_secret,
    "hypothesis": lambda e: _map_note(
        e, abstract="Analyst hypothesis",
        content_field="statement",
    ),
    "lead": lambda e: _map_note(
        e, abstract="Confirmed lead",
        content_field="statement",
    ),
    "open_question": lambda e: _map_note(
        e, abstract="Open question",
        content_field="question",
    ),
}


def _map_entity(entity: dict[str, Any]) -> dict[str, Any] | None:
    """Run the right mapper for one entity. Returns ``None``
    when the entity type has no STIX mapping (those entities
    are skipped + counted under ``unmapped``)."""
    entity_type = str(entity.get("entity_type") or "")
    mapper = _ENTITY_MAPPERS.get(entity_type)
    if mapper is None:
        return None
    obj = mapper(entity)
    # Attach NexusRecon provenance as custom properties.
    if entity.get("confidence") is not None:
        obj["confidence"] = int(float(entity["confidence"]) * 100)
    if entity.get("sources"):
        obj["x_nexusrecon_sources"] = list(entity["sources"])
    if entity.get("entity_id"):
        obj["x_nexusrecon_entity_id"] = entity["entity_id"]
    return obj


# ──────────────────────────────────────────────────────────────────────
# Relationship mapping
# ──────────────────────────────────────────────────────────────────────


#: NexusRecon rel_type → STIX relationship_type. STIX has a
#: small canonical set; everything else gets carried through
#: as-is (STIX 2.1 ALLOWS arbitrary relationship_type
#: strings).
_REL_TYPE_MAP: dict[str, str] = {
    "resolves_to": "resolves-to",
    "owns": "owns",
    "belongs_to": "belongs-to",
    "part_of": "part-of",
    "has_cve": "has",
    "has_cert": "has",
    "hosted_on": "hosted-on",
    "communicates_with": "communicates-with",
}


def _stix_rel_type(nexusrecon_rel: str) -> str:
    return _REL_TYPE_MAP.get(nexusrecon_rel, nexusrecon_rel)


# ──────────────────────────────────────────────────────────────────────
# Bundle builder
# ──────────────────────────────────────────────────────────────────────


def build_stix_bundle(
    graph: Any,
    *,
    scope_hash: str = "",
    campaign_id: str = "",
    created_by_name: str = "NexusRecon",
) -> STIXBundle:
    """Build a STIX 2.1 Bundle from an :class:`EntityGraph`.

    ``scope_hash`` and ``campaign_id`` get embedded as custom
    properties on the Identity SDO that represents NexusRecon
    itself — so downstream consumers can correlate exports
    from the same campaign over time.
    """
    objects: list[dict[str, Any]] = []
    counts: dict[str, int] = {}
    entity_id_to_stix_id: dict[str, str] = {}

    # Synthetic identity for NexusRecon — every emitted SDO
    # claims ``created_by_ref`` pointing at it.
    nr_identity = _base_object("identity", f"nexusrecon::{campaign_id}")
    nr_identity["name"] = created_by_name
    nr_identity["identity_class"] = "system"
    if scope_hash:
        nr_identity["x_nexusrecon_scope_hash"] = scope_hash
    if campaign_id:
        nr_identity["x_nexusrecon_campaign_id"] = campaign_id
    objects.append(nr_identity)

    # Entities → SDOs/SCOs.
    for entity_id, data in graph.graph.nodes(data=True):
        node = dict(data)
        node["entity_id"] = entity_id
        mapped = _map_entity(node)
        if mapped is None:
            counts["unmapped"] = counts.get("unmapped", 0) + 1
            log.debug(
                "STIX export: unmapped entity type",
                entity_type=node.get("entity_type"),
            )
            continue
        # Claim NexusRecon as the creator.
        mapped["created_by_ref"] = nr_identity["id"]
        objects.append(mapped)
        entity_id_to_stix_id[entity_id] = mapped["id"]
        counts[mapped["type"]] = counts.get(mapped["type"], 0) + 1

    # Relationships → SROs.
    for source, target, edge_data in graph.graph.edges(data=True):
        source_stix = entity_id_to_stix_id.get(source)
        target_stix = entity_id_to_stix_id.get(target)
        if source_stix is None or target_stix is None:
            # Edge connects to an unmapped entity → skip.
            counts["unmapped_relationship"] = (
                counts.get("unmapped_relationship", 0) + 1
            )
            continue
        rel_type = _stix_rel_type(str(edge_data.get("rel_type", "linked-to")))
        rel_seed = f"{source_stix}->{target_stix}::{rel_type}"
        rel = _base_object("relationship", rel_seed)
        rel["relationship_type"] = rel_type
        rel["source_ref"] = source_stix
        rel["target_ref"] = target_stix
        rel["created_by_ref"] = nr_identity["id"]
        if edge_data.get("confidence") is not None:
            rel["confidence"] = int(float(edge_data["confidence"]) * 100)
        if edge_data.get("source_tool"):
            rel["x_nexusrecon_source_tool"] = edge_data["source_tool"]
        objects.append(rel)
        counts["relationship"] = counts.get("relationship", 0) + 1

    bundle = {
        "type": "bundle",
        "id": _bundle_id(),
        "objects": objects,
    }
    counts["total_objects"] = len(objects)
    return STIXBundle(bundle=bundle, counts=counts)


def write_stix_bundle(
    graph: Any,
    path: Path | str,
    *,
    scope_hash: str = "",
    campaign_id: str = "",
    indent: int | None = 2,
) -> Path:
    """Build + serialise + write. Returns the resolved
    output path so the CLI can print "N objects → <path>"."""
    bundle = build_stix_bundle(
        graph, scope_hash=scope_hash, campaign_id=campaign_id,
    )
    out = Path(path).expanduser()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(bundle.to_json(indent=indent), encoding="utf-8")
    return out

"""Pack registry — tracks loaded packs + runtime extensions.

Two distinct things live here:

  1. :class:`PackRegistry` — a singleton holding the list of
     successfully-loaded packs (plus their statuses for the
     ``packs list`` CLI). The CLI + the campaign launch path
     read from this to render pack status.

  2. The runtime extension registries for custom entity /
     relationship type strings. Built-in
     :class:`~nexusrecon.models.entities.EntityType` and
     :class:`RelationshipType` are :class:`StrEnum`s — frozen
     after definition, can't be extended. Pack-contributed
     types live alongside as plain strings, validated against
     these runtime registries.

API
- :func:`register_entity_type(name, value)` /
  :func:`register_relationship_type(name, value)` — called by
  the loader; idempotent within a name (re-registering the
  same name with the same value is a no-op).
- :func:`is_known_entity_type(value)` /
  :func:`is_known_relationship_type(value)` — used by
  consumers (graph add helpers, validators) to check a string
  against built-in + custom types in one call.
- :func:`reset_pack_registry()` — for tests + clean
  campaign re-launches; clears the singleton + the runtime
  extension registries.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

from nexusrecon.models.entities import EntityType, RelationshipType

log = structlog.get_logger(__name__)


# ──────────────────────────────────────────────────────────────────────
# Runtime extension registries
# ──────────────────────────────────────────────────────────────────────


_BUILT_IN_ENTITY_VALUES: frozenset[str] = frozenset(
    e.value for e in EntityType
)
_BUILT_IN_REL_VALUES: frozenset[str] = frozenset(
    r.value for r in RelationshipType
)

#: ``UPPER_SNAKE name -> lower_snake value``. Populated by
#: the pack loader. Pack-contributed entity types are checked
#: against this dict (plus the built-in StrEnum) when a tool
#: tries to mint an entity.
_CUSTOM_ENTITY_TYPES: dict[str, str] = {}
_CUSTOM_REL_TYPES: dict[str, str] = {}


def register_entity_type(name: str, value: str) -> None:
    """Register a custom entity type. Idempotent: registering
    the same ``(name, value)`` again is a no-op. Conflict
    (same name with a different value, or value already used
    by a built-in / different custom type) raises
    ``ValueError`` so packs can't quietly shadow each other.
    """
    existing = _CUSTOM_ENTITY_TYPES.get(name)
    if existing == value:
        return
    if existing is not None:
        raise ValueError(
            f"entity_type {name!r} already registered with "
            f"value {existing!r}; refusing to overwrite with {value!r}"
        )
    if value in _BUILT_IN_ENTITY_VALUES:
        raise ValueError(
            f"entity_type value {value!r} shadows a built-in",
        )
    # Reverse-collision: another custom type already uses this
    # value.
    for n, v in _CUSTOM_ENTITY_TYPES.items():
        if v == value:
            raise ValueError(
                f"entity_type value {value!r} already used by {n!r}",
            )
    _CUSTOM_ENTITY_TYPES[name] = value
    log.debug("Registered custom entity_type", name=name, value=value)


def register_relationship_type(name: str, value: str) -> None:
    """Register a custom relationship type. Same idempotency
    + collision rules as :func:`register_entity_type`."""
    existing = _CUSTOM_REL_TYPES.get(name)
    if existing == value:
        return
    if existing is not None:
        raise ValueError(
            f"relationship_type {name!r} already registered with "
            f"value {existing!r}"
        )
    if value in _BUILT_IN_REL_VALUES:
        raise ValueError(
            f"relationship_type value {value!r} shadows a built-in",
        )
    for n, v in _CUSTOM_REL_TYPES.items():
        if v == value:
            raise ValueError(
                f"relationship_type value {value!r} already used by {n!r}",
            )
    _CUSTOM_REL_TYPES[name] = value
    log.debug("Registered custom relationship_type", name=name, value=value)


def is_known_entity_type(value: str) -> bool:
    """True when ``value`` is either a built-in
    :class:`EntityType` value or a registered custom one."""
    return value in _BUILT_IN_ENTITY_VALUES or value in _CUSTOM_ENTITY_TYPES.values()


def is_known_relationship_type(value: str) -> bool:
    """True when ``value`` is either a built-in
    :class:`RelationshipType` value or a registered custom
    one."""
    return value in _BUILT_IN_REL_VALUES or value in _CUSTOM_REL_TYPES.values()


def custom_entity_types() -> dict[str, str]:
    """Read-only snapshot — copy so callers can't mutate the
    registry."""
    return dict(_CUSTOM_ENTITY_TYPES)


def custom_relationship_types() -> dict[str, str]:
    return dict(_CUSTOM_REL_TYPES)


def _reset_extensions() -> None:
    """Clear the runtime extension registries. Tests +
    :func:`reset_pack_registry`."""
    _CUSTOM_ENTITY_TYPES.clear()
    _CUSTOM_REL_TYPES.clear()


# ──────────────────────────────────────────────────────────────────────
# PackRegistry singleton
# ──────────────────────────────────────────────────────────────────────


@dataclass
class PackRegistryEntry:
    """One pack's tracked state. The loader writes one of
    these per discovered pack — even failed packs land here so
    ``packs list`` can show what's installed-but-broken."""

    name: str
    version: str
    path: str
    status: str  # "loaded" | "skipped" | "failed"
    contributions_summary: dict[str, int] = field(default_factory=dict)
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "path": self.path,
            "status": self.status,
            "contributions_summary": dict(self.contributions_summary),
            "error": self.error,
        }


class PackRegistry:
    """Process-wide store of pack states.

    Singleton accessed via :func:`get_pack_registry`. The
    campaign launch path queries it to summarise which packs
    are active; the audit-log writer pulls the same data into
    a hash-chained ``pack_loaded`` entry per pack.
    """

    def __init__(self) -> None:
        self._entries: dict[str, PackRegistryEntry] = {}

    def add(self, entry: PackRegistryEntry) -> None:
        """Add or replace an entry. Replace semantics matter
        for the rare case of a pack being reloaded — we want
        the latest status, not a stack."""
        self._entries[entry.name] = entry

    def get(self, name: str) -> PackRegistryEntry | None:
        return self._entries.get(name)

    def all(self) -> list[PackRegistryEntry]:
        return list(self._entries.values())

    def clear(self) -> None:
        self._entries.clear()

    def summary(self) -> dict[str, Any]:
        """Compact summary surfaced in the CLI + audit log."""
        loaded = [e for e in self._entries.values() if e.status == "loaded"]
        return {
            "total": len(self._entries),
            "loaded": len(loaded),
            "failed": sum(
                1 for e in self._entries.values()
                if e.status == "failed"
            ),
            "skipped": sum(
                1 for e in self._entries.values()
                if e.status == "skipped"
            ),
            "names": sorted(e.name for e in loaded),
        }


_REGISTRY_SINGLETON: PackRegistry | None = None


def get_pack_registry() -> PackRegistry:
    """Get (or lazily construct) the process-wide registry."""
    global _REGISTRY_SINGLETON
    if _REGISTRY_SINGLETON is None:
        _REGISTRY_SINGLETON = PackRegistry()
    return _REGISTRY_SINGLETON


def reset_pack_registry() -> None:
    """Tear down both the registry singleton and the runtime
    extension registries. Used by tests + clean campaign
    re-launches so leftover state from a previous run doesn't
    pollute the next one."""
    global _REGISTRY_SINGLETON
    if _REGISTRY_SINGLETON is not None:
        _REGISTRY_SINGLETON.clear()
    _reset_extensions()

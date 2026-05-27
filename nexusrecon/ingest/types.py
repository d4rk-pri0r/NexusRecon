"""Shared types for the import pipeline."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ImportReport:
    """Outcome of one importer run.

    Counts are keyed by entity_type so the operator-facing
    output can show "added 42 domain entities, 17 IP
    entities" at a glance."""

    importer: str
    """Identifier for the importer that produced this
    report. Same string used as the entity source prefix
    (``imported_from:<importer>``)."""
    source_path: str
    entities_added: int = 0
    entities_merged: int = 0
    relationships_added: int = 0
    counts_by_type: dict[str, int] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    skipped: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "importer": self.importer,
            "source_path": self.source_path,
            "entities_added": self.entities_added,
            "entities_merged": self.entities_merged,
            "relationships_added": self.relationships_added,
            "counts_by_type": dict(self.counts_by_type),
            "warnings": list(self.warnings),
            "skipped": self.skipped,
        }


@dataclass
class ImportResult:
    """One record's worth of state during an import.

    Importers append :class:`ImportResult` values internally
    + roll them up into the final :class:`ImportReport`.
    Public surface — kept simple so future importers can
    reuse the type."""

    entity_id: str
    """The id of the entity the importer landed on (may be
    a fresh add or a merge into an existing entry)."""
    entity_type: str
    was_new: bool
    """True when this was a brand-new node; False when the
    importer merged into an existing entry (the entity_id
    points at the merge target)."""

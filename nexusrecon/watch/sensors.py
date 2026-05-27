"""Watch sensors — define WHAT to monitor.

Three sensor flavors ship in PR A:

  - :class:`EntitySensor` — watches a single entity by id.
    Fires when that entity's confidence, source list, or
    edge degree changes.
  - :class:`ScopeSensor` — watches every entity matching a
    scope filter (entity_type, parent domain, etc.). Fires
    when entities are added/removed from the matched set or
    when any member's fingerprint changes.
  - :class:`TimedSensor` — fires on a polling schedule
    regardless of graph state. Used to re-run a recon
    footprint periodically (the "scheduled" half of the
    "both polling + diff-driven" architecture choice).

Sensor fingerprints
- Each sensor produces a :class:`SensorFingerprint` per tick.
- Diff-driven sensors compare the current fingerprint
  against the previous one and decide whether to fire.
- Timed sensors compare against the previous fire timestamp
  instead.

What sensors DON'T do
- Sensors don't take actions themselves. They produce
  ``Trigger`` results the runner forwards to the action
  policy.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any


# ──────────────────────────────────────────────────────────────────────
# Fingerprint
# ──────────────────────────────────────────────────────────────────────


@dataclass
class SensorFingerprint:
    """Snapshot of what a sensor's watched set looked like at
    one tick. The runner persists this so the next tick can
    compare."""

    sensor_id: str
    """Stable identifier for the sensor within its watch."""
    entity_ids: list[str] = field(default_factory=list)
    """The entities the sensor matched at this tick. Sorted
    for determinism."""
    digest: str = ""
    """SHA-256 of the canonical state of those entities.
    Changes when ANY watched entity's confidence, sources,
    tags, or edge count changes."""
    captured_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "sensor_id": self.sensor_id,
            "entity_ids": list(self.entity_ids),
            "digest": self.digest,
            "captured_at": self.captured_at,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> SensorFingerprint:
        return cls(
            sensor_id=str(raw.get("sensor_id", "")),
            entity_ids=list(raw.get("entity_ids") or []),
            digest=str(raw.get("digest", "")),
            captured_at=str(raw.get("captured_at", "")),
        )


# ──────────────────────────────────────────────────────────────────────
# Trigger
# ──────────────────────────────────────────────────────────────────────


@dataclass
class Trigger:
    """One sensor's tick output. ``fired`` is the operator-
    visible signal; ``fingerprint`` is what gets persisted
    so the NEXT tick can diff against today's state."""

    sensor_id: str
    sensor_kind: str
    fired: bool
    reason: str
    """Human-readable explanation surfaced in the alert
    history."""
    fingerprint: SensorFingerprint
    changed_entity_ids: list[str] = field(default_factory=list)
    """Entities whose state changed since the previous
    fingerprint. Empty for timed-only triggers."""

    def to_dict(self) -> dict[str, Any]:
        return {
            "sensor_id": self.sensor_id,
            "sensor_kind": self.sensor_kind,
            "fired": self.fired,
            "reason": self.reason,
            "fingerprint": self.fingerprint.to_dict(),
            "changed_entity_ids": list(self.changed_entity_ids),
        }


# ──────────────────────────────────────────────────────────────────────
# Sensor base
# ──────────────────────────────────────────────────────────────────────


@dataclass
class Sensor:
    """Base class. Concrete sensors override :meth:`evaluate`."""

    sensor_id: str

    def evaluate(
        self,
        graph: Any,
        previous: SensorFingerprint | None,
        now: datetime,
    ) -> Trigger:
        raise NotImplementedError

    def to_dict(self) -> dict[str, Any]:
        raise NotImplementedError

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> Sensor:
        kind = raw.get("kind") or raw.get("sensor_kind")
        if kind == "entity":
            return EntitySensor(
                sensor_id=str(raw["sensor_id"]),
                entity_id=str(raw["entity_id"]),
            )
        if kind == "scope":
            return ScopeSensor(
                sensor_id=str(raw["sensor_id"]),
                entity_type=raw.get("entity_type") or None,
                parent_domain=raw.get("parent_domain") or None,
                value_contains=raw.get("value_contains") or None,
            )
        if kind == "timed":
            return TimedSensor(
                sensor_id=str(raw["sensor_id"]),
                interval_seconds=int(raw["interval_seconds"]),
                description=str(raw.get("description", "")),
            )
        raise ValueError(f"unknown sensor kind: {kind!r}")


# ──────────────────────────────────────────────────────────────────────
# EntitySensor
# ──────────────────────────────────────────────────────────────────────


@dataclass
class EntitySensor(Sensor):
    """Watch one entity by id."""

    entity_id: str = ""

    def evaluate(
        self,
        graph: Any,
        previous: SensorFingerprint | None,
        now: datetime,
    ) -> Trigger:
        node_data = graph.graph.nodes.get(self.entity_id)
        captured_at = now.isoformat()
        if node_data is None:
            fp = SensorFingerprint(
                sensor_id=self.sensor_id,
                entity_ids=[],
                digest="missing",
                captured_at=captured_at,
            )
            return Trigger(
                sensor_id=self.sensor_id,
                sensor_kind="entity",
                fired=previous is not None and previous.digest != "missing",
                reason=(
                    f"entity {self.entity_id!r} not in graph"
                    if previous and previous.digest != "missing"
                    else f"entity {self.entity_id!r} not yet present"
                ),
                fingerprint=fp,
                changed_entity_ids=(
                    [self.entity_id]
                    if previous and previous.digest != "missing"
                    else []
                ),
            )
        digest = _digest_entities(graph, [self.entity_id])
        fp = SensorFingerprint(
            sensor_id=self.sensor_id,
            entity_ids=[self.entity_id],
            digest=digest,
            captured_at=captured_at,
        )
        if previous is None:
            return Trigger(
                sensor_id=self.sensor_id,
                sensor_kind="entity",
                fired=False,
                reason="initial fingerprint captured",
                fingerprint=fp,
            )
        if previous.digest == digest:
            return Trigger(
                sensor_id=self.sensor_id,
                sensor_kind="entity",
                fired=False,
                reason="no change",
                fingerprint=fp,
            )
        return Trigger(
            sensor_id=self.sensor_id,
            sensor_kind="entity",
            fired=True,
            reason="entity state changed since last tick",
            fingerprint=fp,
            changed_entity_ids=[self.entity_id],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": "entity",
            "sensor_id": self.sensor_id,
            "entity_id": self.entity_id,
        }


# ──────────────────────────────────────────────────────────────────────
# ScopeSensor
# ──────────────────────────────────────────────────────────────────────


@dataclass
class ScopeSensor(Sensor):
    """Watch every entity matching a filter.

    All filters AND together — set just one for the common
    case. Empty matchers raise on construction to avoid the
    accidental "everything in the graph" sensor that would
    fire on every tick."""

    entity_type: str | None = None
    parent_domain: str | None = None
    value_contains: str | None = None

    def __post_init__(self) -> None:
        if not any((self.entity_type, self.parent_domain, self.value_contains)):
            raise ValueError(
                "ScopeSensor requires at least one of: "
                "entity_type, parent_domain, value_contains"
            )

    def evaluate(
        self,
        graph: Any,
        previous: SensorFingerprint | None,
        now: datetime,
    ) -> Trigger:
        matched = self._match(graph)
        digest = _digest_entities(graph, matched)
        fp = SensorFingerprint(
            sensor_id=self.sensor_id,
            entity_ids=matched,
            digest=digest,
            captured_at=now.isoformat(),
        )
        if previous is None:
            return Trigger(
                sensor_id=self.sensor_id,
                sensor_kind="scope",
                fired=False,
                reason="initial fingerprint captured",
                fingerprint=fp,
            )
        if previous.digest == digest:
            return Trigger(
                sensor_id=self.sensor_id,
                sensor_kind="scope",
                fired=False,
                reason="no change",
                fingerprint=fp,
            )
        # Compute which entities changed for the trigger
        # payload + the runner's downstream severity grading.
        prev_set = set(previous.entity_ids)
        curr_set = set(matched)
        added = sorted(curr_set - prev_set)
        removed = sorted(prev_set - curr_set)
        # Members that survived but whose individual state
        # changed: only detectable via per-entity digest, which
        # we don't store separately in the v1 fingerprint.
        # Conservative behavior: report the set delta;
        # in-place changes get "set hash changed" attribution
        # instead.
        changed = added + removed
        if not changed:
            changed = matched  # in-place change → mark all
        reason_parts: list[str] = []
        if added:
            reason_parts.append(f"+{len(added)} entit{'y' if len(added) == 1 else 'ies'}")
        if removed:
            reason_parts.append(f"-{len(removed)} entit{'y' if len(removed) == 1 else 'ies'}")
        if not reason_parts:
            reason_parts.append("in-place state change on matched set")
        return Trigger(
            sensor_id=self.sensor_id,
            sensor_kind="scope",
            fired=True,
            reason=", ".join(reason_parts),
            fingerprint=fp,
            changed_entity_ids=changed,
        )

    def _match(self, graph: Any) -> list[str]:
        out: list[str] = []
        for eid, data in graph.graph.nodes(data=True):
            if self.entity_type and data.get("entity_type") != self.entity_type:
                continue
            if (
                self.parent_domain
                and data.get("parent_domain") != self.parent_domain
            ):
                continue
            if (
                self.value_contains
                and self.value_contains.lower() not in str(
                    data.get("value", "")
                ).lower()
            ):
                continue
            out.append(eid)
        return sorted(out)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": "scope",
            "sensor_id": self.sensor_id,
            "entity_type": self.entity_type,
            "parent_domain": self.parent_domain,
            "value_contains": self.value_contains,
        }


# ──────────────────────────────────────────────────────────────────────
# TimedSensor
# ──────────────────────────────────────────────────────────────────────


@dataclass
class TimedSensor(Sensor):
    """Fire on a fixed cadence.

    Doesn't look at the graph — purely a clock-driven
    schedule. Used to re-run a passive recon footprint
    periodically. The runner records the fire timestamp in
    the fingerprint's ``captured_at`` so the next tick can
    decide whether the cadence has elapsed."""

    interval_seconds: int = 21600  # 6 hours
    description: str = ""

    def evaluate(
        self,
        graph: Any,
        previous: SensorFingerprint | None,
        now: datetime,
    ) -> Trigger:
        # We use a synthetic fingerprint that just carries the
        # ISO timestamp of the last fire. Subsequent ticks
        # parse it and compare against now.
        if previous is None or not previous.captured_at:
            fp = SensorFingerprint(
                sensor_id=self.sensor_id,
                entity_ids=[],
                digest="timed",
                captured_at=now.isoformat(),
            )
            return Trigger(
                sensor_id=self.sensor_id,
                sensor_kind="timed",
                fired=True,
                reason="initial timed fire",
                fingerprint=fp,
            )
        try:
            prev_ts = datetime.fromisoformat(previous.captured_at)
        except ValueError:
            prev_ts = now - timedelta(seconds=self.interval_seconds + 1)
        elapsed = (now - prev_ts).total_seconds()
        if elapsed < self.interval_seconds:
            return Trigger(
                sensor_id=self.sensor_id,
                sensor_kind="timed",
                fired=False,
                reason=(
                    f"cadence not elapsed "
                    f"({int(elapsed)}s/{self.interval_seconds}s)"
                ),
                fingerprint=previous,
            )
        fp = SensorFingerprint(
            sensor_id=self.sensor_id,
            entity_ids=[],
            digest="timed",
            captured_at=now.isoformat(),
        )
        return Trigger(
            sensor_id=self.sensor_id,
            sensor_kind="timed",
            fired=True,
            reason=(
                f"cadence elapsed ({int(elapsed)}s) — "
                f"{self.description or 'scheduled re-run'}"
            ),
            fingerprint=fp,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": "timed",
            "sensor_id": self.sensor_id,
            "interval_seconds": self.interval_seconds,
            "description": self.description,
        }


# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────


def _digest_entities(graph: Any, entity_ids: list[str]) -> str:
    """Hash the canonical state of the listed entities. The
    digest carries:
      - entity_type, value, confidence, sources, tags
      - in-degree + out-degree (so edge changes register)
    """
    if not entity_ids:
        return hashlib.sha256(b"empty").hexdigest()
    items: list[dict[str, Any]] = []
    for eid in sorted(entity_ids):
        data = graph.graph.nodes.get(eid)
        if data is None:
            items.append({"entity_id": eid, "missing": True})
            continue
        items.append({
            "entity_id": eid,
            "entity_type": data.get("entity_type"),
            "value": data.get("value"),
            "confidence": float(data.get("confidence", 0.0)),
            "sources": sorted(data.get("sources") or []),
            "tags": sorted(data.get("tags") or []),
            "in_degree": graph.graph.in_degree(eid),
            "out_degree": graph.graph.out_degree(eid),
        })
    canonical = json.dumps(items, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
